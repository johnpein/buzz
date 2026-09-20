//! Room catch-up for `stream` deliveries.
//!
//! Managed agents run mention-gated, so an agent is only handed the messages
//! that `@` it and never sees what the rest of the room said in between. When
//! a stream delivery is built, the room's messages since this agent's previous
//! turn are fetched and delivered ahead of the triggering message(s), inside
//! the same signed envelope, so the agent reads the conversation it is joining.
//!
//! Catch-up is context, never a trigger: it is bounded, limited to validly
//! signed kind-9 messages of this channel authored by members of the
//! relay-signed roster, and excludes the agent's own messages (its context
//! engine already holds those). The window is stateless and restart-safe: it
//! opens at the message this agent last replied to and closes strictly before
//! the triggering batch, so a retried delivery selects the same events and
//! keeps the same delivery id.

use std::collections::HashSet;
use std::time::Duration;

use nostr::{Alphabet, Event, EventId, Filter, Kind, PublicKey, SingleLetterTag, Timestamp};
use uuid::Uuid;

use crate::relay::RestClient;

/// Most catch-up messages one delivery carries (the newest are kept). With the
/// triggering batch this stays under the envelope's 64-event ceiling.
pub(crate) const MAX_CATCHUP_EVENTS: usize = 40;
/// Catch-up for an agent that has never replied in the room.
const FIRST_TURN_CATCHUP_EVENTS: usize = 20;
const QUERY_LIMIT: usize = 200;
const FETCH_TIMEOUT: Duration = Duration::from_millis(3_000);

/// Where the catch-up window opens: the message this agent last replied to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cursor {
    pub event_id: EventId,
    pub created_at: Timestamp,
}

/// Why a fetched room message was left out of the catch-up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dropped {
    NotChat,
    Own,
    NotBeforeBatch,
    InBatch,
    BeforeCursor,
    NotOnRoster,
    OtherChannel,
    BadSignature,
    Duplicate,
    OverLimit,
}

/// What a catch-up fetch saw and kept. Logged once per stream delivery so a
/// surprising count (e.g. 0 where the room was busy) names its own cause.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct Tally {
    pub fetched: usize,
    /// Fetched messages that are thread replies (carry an `e` tag). Zero in a
    /// busy threaded room means the relay's channel query omits thread replies.
    pub fetched_thread_replies: usize,
    pub kept: usize,
    pub not_chat: usize,
    pub own: usize,
    pub not_before_batch: usize,
    pub in_batch: usize,
    pub before_cursor: usize,
    pub not_on_roster: usize,
    pub other_channel: usize,
    pub bad_signature: usize,
    pub duplicate: usize,
    pub over_limit: usize,
}

impl Tally {
    fn count(&mut self, reason: Dropped) {
        let slot = match reason {
            Dropped::NotChat => &mut self.not_chat,
            Dropped::Own => &mut self.own,
            Dropped::NotBeforeBatch => &mut self.not_before_batch,
            Dropped::InBatch => &mut self.in_batch,
            Dropped::BeforeCursor => &mut self.before_cursor,
            Dropped::NotOnRoster => &mut self.not_on_roster,
            Dropped::OtherChannel => &mut self.other_channel,
            Dropped::BadSignature => &mut self.bad_signature,
            Dropped::Duplicate => &mut self.duplicate,
            Dropped::OverLimit => &mut self.over_limit,
        };
        *slot += 1;
    }
}

fn is_thread_reply(event: &Event) -> bool {
    event
        .tags
        .iter()
        .any(|tag| tag.as_slice().first().map(String::as_str) == Some("e"))
}

/// Choose the catch-up events for one delivery from the channel's candidates.
pub(crate) fn select(
    candidates: Vec<Event>,
    batch: &[Event],
    roster: &[String],
    own_pubkey: &PublicKey,
    channel_id: Uuid,
    cursor: Option<Cursor>,
) -> (Vec<Event>, Tally) {
    let mut tally = Tally {
        fetched: candidates.len(),
        fetched_thread_replies: candidates
            .iter()
            .filter(|event| is_thread_reply(event))
            .count(),
        ..Tally::default()
    };
    let Some(window_closes) = batch.iter().map(|event| event.created_at).min() else {
        return (Vec::new(), tally);
    };
    let channel = channel_id.to_string();
    let batch_ids: HashSet<EventId> = batch.iter().map(|event| event.id).collect();
    let mut seen = HashSet::new();
    let mut selected: Vec<Event> = Vec::new();
    for event in candidates {
        let dropped = if event.kind != Kind::Custom(9) {
            Some(Dropped::NotChat)
        } else if event.pubkey == *own_pubkey {
            Some(Dropped::Own)
        } else if batch_ids.contains(&event.id) {
            Some(Dropped::InBatch)
        } else if event.created_at >= window_closes {
            Some(Dropped::NotBeforeBatch)
        } else if cursor.is_some_and(|cursor| {
            event.created_at < cursor.created_at || event.id == cursor.event_id
        }) {
            Some(Dropped::BeforeCursor)
        } else if !roster
            .iter()
            .any(|member| member.eq_ignore_ascii_case(&event.pubkey.to_hex()))
        {
            Some(Dropped::NotOnRoster)
        } else if !event.tags.iter().any(|tag| {
            let values = tag.as_slice();
            values.first().map(String::as_str) == Some("h")
                && values.get(1).map(String::as_str) == Some(channel.as_str())
        }) {
            Some(Dropped::OtherChannel)
        } else if event.verify().is_err() {
            Some(Dropped::BadSignature)
        } else if !seen.insert(event.id) {
            Some(Dropped::Duplicate)
        } else {
            None
        };
        match dropped {
            Some(reason) => tally.count(reason),
            None => selected.push(event),
        }
    }
    selected.sort_by(|left, right| {
        left.created_at
            .cmp(&right.created_at)
            .then_with(|| left.id.to_hex().cmp(&right.id.to_hex()))
    });
    let limit = if cursor.is_some() {
        MAX_CATCHUP_EVENTS
    } else {
        FIRST_TURN_CATCHUP_EVENTS
    };
    let excess = selected.len().saturating_sub(limit);
    for _ in 0..excess {
        tally.count(Dropped::OverLimit);
    }
    let kept = selected.split_off(excess);
    tally.kept = kept.len();
    (kept, tally)
}

/// The message a reply answers: its `e` tag marked `reply`.
fn replied_to(reply: &Event) -> Option<EventId> {
    reply.tags.iter().find_map(|tag| {
        let values = tag.as_slice();
        (values.first().map(String::as_str) == Some("e")
            && values.get(3).map(String::as_str) == Some("reply"))
        .then(|| values.get(1))
        .flatten()
        .and_then(|id| EventId::from_hex(id).ok())
    })
}

/// Fetch the room catch-up for a stream delivery.
///
/// `Err` names why the room could not be read. The caller delivers the batch
/// without catch-up in that case: a turn with less context beats a lost turn.
pub(crate) async fn fetch(
    rest: &RestClient,
    channel_id: Uuid,
    own_pubkey: &PublicKey,
    roster: &[String],
    batch: &[Event],
) -> Result<Vec<Event>, String> {
    let Some(window_closes) = batch.iter().map(|event| event.created_at).min() else {
        return Ok(Vec::new());
    };
    let h_tag = SingleLetterTag::lowercase(Alphabet::H);
    let channel = channel_id.to_string();

    let own_last_reply = Filter::new()
        .kind(Kind::Custom(9))
        .author(*own_pubkey)
        .custom_tags(h_tag, [channel.clone()])
        .until(window_closes)
        .limit(1);
    let own_last_reply = query(rest, own_last_reply).await?;
    let own_last_reply_found = !own_last_reply.is_empty();
    let cursor = match own_last_reply.first().and_then(replied_to) {
        Some(parent_id) => query(rest, Filter::new().id(parent_id).limit(1))
            .await?
            .into_iter()
            .find(|event| event.id == parent_id)
            .map(|parent| Cursor {
                event_id: parent.id,
                created_at: parent.created_at,
            }),
        None => None,
    };

    let mut room = Filter::new()
        .kind(Kind::Custom(9))
        .custom_tags(h_tag, [channel])
        .until(window_closes)
        .limit(QUERY_LIMIT);
    if let Some(cursor) = cursor {
        room = room.since(cursor.created_at);
    }
    let candidates = query(rest, room).await?;
    let (catchup, tally) = select(candidates, batch, roster, own_pubkey, channel_id, cursor);
    tracing::info!(
        channel_id = %channel_id,
        own_last_reply_found,
        cursor_at = cursor.map(|cursor| cursor.created_at.as_secs()),
        window_closes = window_closes.as_secs(),
        ?tally,
        "room catch-up selection"
    );
    Ok(catchup)
}

async fn query(rest: &RestClient, filter: Filter) -> Result<Vec<Event>, String> {
    let response = tokio::time::timeout(FETCH_TIMEOUT, rest.query(&[filter]))
        .await
        .map_err(|_| "room query timed out".to_string())?
        .map_err(|error| format!("room query failed: {error}"))?;
    Ok(response
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|value| serde_json::from_value::<Event>(value.clone()).ok())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr::{EventBuilder, Keys, Tag};

    const CHANNEL: &str = "f3bcd88a-c339-497b-96dd-f8aea2638242";

    fn message(keys: &Keys, at: u64, text: &str, channel: &str, reply_to: Option<&Event>) -> Event {
        let mut tags = vec![Tag::parse(["h", channel]).expect("channel tag")];
        if let Some(parent) = reply_to {
            tags.push(Tag::parse(["e", &parent.id.to_hex(), "", "reply"]).expect("reply tag"));
        }
        EventBuilder::new(Kind::Custom(9), text)
            .tags(tags)
            .custom_created_at(Timestamp::from(at))
            .sign_with_keys(keys)
            .expect("signed message")
    }

    struct Room {
        owner: Keys,
        me: Keys,
        sibling: Keys,
        roster: Vec<String>,
        channel: Uuid,
    }

    fn room() -> Room {
        let (owner, me, sibling) = (Keys::generate(), Keys::generate(), Keys::generate());
        let roster = [&owner, &me, &sibling]
            .iter()
            .map(|keys| keys.public_key().to_hex())
            .collect();
        Room {
            owner,
            me,
            sibling,
            roster,
            channel: Uuid::parse_str(CHANNEL).expect("channel"),
        }
    }

    fn texts(events: &[Event]) -> Vec<&str> {
        events.iter().map(|event| event.content.as_str()).collect()
    }

    #[test]
    fn delivers_what_the_room_said_since_this_agents_previous_turn() {
        let room = room();
        let previous = message(&room.owner, 100, "team, thoughts?", CHANNEL, None);
        let cursor = Cursor {
            event_id: previous.id,
            created_at: previous.created_at,
        };
        let trigger = message(&room.owner, 200, "@me and you?", CHANNEL, None);
        let candidates = vec![
            message(&room.sibling, 50, "before my previous turn", CHANNEL, None),
            previous.clone(),
            message(
                &room.me,
                110,
                "my own earlier reply",
                CHANNEL,
                Some(&previous),
            ),
            message(
                &room.sibling,
                120,
                "sibling's answer to the owner",
                CHANNEL,
                None,
            ),
            message(&room.owner, 130, "owner follow-up", CHANNEL, None),
            trigger.clone(),
            message(&room.sibling, 250, "after the trigger", CHANNEL, None),
        ];
        let (selected, _tally) = select(
            candidates,
            std::slice::from_ref(&trigger),
            &room.roster,
            &room.me.public_key(),
            room.channel,
            Some(cursor),
        );
        assert_eq!(
            texts(&selected),
            vec!["sibling's answer to the owner", "owner follow-up"]
        );
    }

    #[test]
    fn admits_only_verified_roster_messages_of_this_channel() {
        let room = room();
        let outsider = Keys::generate();
        let trigger = message(&room.owner, 200, "@me", CHANNEL, None);
        let mut forged = serde_json::to_value(message(&room.owner, 150, "real", CHANNEL, None))
            .expect("event JSON");
        forged["content"] = serde_json::json!("tampered owner words");
        let candidates = vec![
            message(&outsider, 140, "not on the roster", CHANNEL, None),
            message(
                &room.sibling,
                141,
                "another room",
                "11111111-2222-4333-8444-555555555555",
                None,
            ),
            serde_json::from_value(forged).expect("forged event"),
            message(&room.sibling, 160, "legitimate", CHANNEL, None),
        ];
        let (selected, _tally) = select(
            candidates,
            std::slice::from_ref(&trigger),
            &room.roster,
            &room.me.public_key(),
            room.channel,
            None,
        );
        assert_eq!(texts(&selected), vec!["legitimate"]);
    }

    #[test]
    fn keeps_only_the_newest_messages_within_the_bound() {
        let room = room();
        let trigger = message(&room.owner, 10_000, "@me", CHANNEL, None);
        let candidates: Vec<Event> = (0..100)
            .map(|index| {
                message(
                    &room.sibling,
                    100 + index,
                    &format!("m{index}"),
                    CHANNEL,
                    None,
                )
            })
            .collect();
        let previous = message(&room.owner, 1, "start", CHANNEL, None);
        let (bounded, bounded_tally) = select(
            candidates.clone(),
            std::slice::from_ref(&trigger),
            &room.roster,
            &room.me.public_key(),
            room.channel,
            Some(Cursor {
                event_id: previous.id,
                created_at: previous.created_at,
            }),
        );
        assert_eq!(bounded.len(), MAX_CATCHUP_EVENTS);
        assert_eq!(bounded_tally.over_limit, 100 - MAX_CATCHUP_EVENTS);
        assert_eq!(
            bounded.first().map(|event| event.content.as_str()),
            Some("m60")
        );
        assert_eq!(
            bounded.last().map(|event| event.content.as_str()),
            Some("m99")
        );

        let (first_turn, _tally) = select(
            candidates,
            std::slice::from_ref(&trigger),
            &room.roster,
            &room.me.public_key(),
            room.channel,
            None,
        );
        assert_eq!(first_turn.len(), FIRST_TURN_CATCHUP_EVENTS);
    }

    #[test]
    fn a_retried_delivery_selects_the_same_events() {
        let room = room();
        let trigger = message(&room.owner, 200, "@me", CHANNEL, None);
        let first = message(&room.sibling, 120, "a", CHANNEL, None);
        let second = message(&room.sibling, 120, "b", CHANNEL, None);
        let late = message(
            &room.sibling,
            300,
            "arrived after the trigger",
            CHANNEL,
            None,
        );
        let run = |candidates: Vec<Event>| {
            select(
                candidates,
                std::slice::from_ref(&trigger),
                &room.roster,
                &room.me.public_key(),
                room.channel,
                None,
            )
            .0
            .iter()
            .map(|event| event.id)
            .collect::<Vec<_>>()
        };
        assert_eq!(
            run(vec![first.clone(), second.clone()]),
            run(vec![late, second, first.clone(), first])
        );
    }

    #[test]
    fn finds_the_message_a_reply_answers() {
        let room = room();
        let parent = message(&room.owner, 100, "question", CHANNEL, None);
        let reply = message(&room.me, 110, "answer", CHANNEL, Some(&parent));
        assert_eq!(replied_to(&reply), Some(parent.id));
        assert_eq!(replied_to(&parent), None);
    }

    #[test]
    fn the_tally_names_why_each_fetched_message_was_left_out() {
        let room = room();
        let outsider = Keys::generate();
        let previous = message(&room.owner, 100, "earlier question", CHANNEL, None);
        let trigger = message(&room.owner, 200, "@me", CHANNEL, None);
        let thread_reply = message(
            &room.sibling,
            150,
            "threaded answer",
            CHANNEL,
            Some(&previous),
        );
        let candidates = vec![
            message(&room.sibling, 50, "before the cursor", CHANNEL, None),
            previous.clone(),
            message(&room.me, 110, "my own", CHANNEL, Some(&previous)),
            message(&outsider, 120, "not on the roster", CHANNEL, None),
            thread_reply.clone(),
            thread_reply,
            trigger.clone(),
            message(&room.sibling, 250, "after the batch", CHANNEL, None),
        ];
        let (kept, tally) = select(
            candidates,
            std::slice::from_ref(&trigger),
            &room.roster,
            &room.me.public_key(),
            room.channel,
            Some(Cursor {
                event_id: previous.id,
                created_at: previous.created_at,
            }),
        );
        assert_eq!(texts(&kept), vec!["threaded answer"]);
        assert_eq!(
            tally,
            Tally {
                fetched: 8,
                fetched_thread_replies: 3,
                kept: 1,
                own: 1,
                not_before_batch: 1,
                in_batch: 1,
                before_cursor: 2,
                not_on_roster: 1,
                duplicate: 1,
                ..Tally::default()
            }
        );
    }
}
