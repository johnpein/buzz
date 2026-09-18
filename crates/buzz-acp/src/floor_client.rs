//! Floor-protocol client for multi-agent group-chat channels (Task 6 of the
//! multi-agent floor-lease work).
//!
//! When two or more agents share a `stream` channel, the relay (Task 3/4,
//! see `crates/buzz-relay/src/floor.rs` and `crates/buzz-relay/src/floor_wire.rs`
//! in the buzz-relay crate — not a dependency of this crate, so the wire
//! shapes below are reimplemented locally rather than shared) serializes who
//! may reply via a `kind:20003` request / `kind:39007` grant handshake and
//! rejects any `kind:9` publish from an agent that does not currently hold
//! the floor. This module is the client half of that handshake: it builds
//! and posts the request, waits for a decisive grant (bounded by a timeout),
//! and reports a pure, non-I/O outcome the caller uses to decide whether to
//! run a Context Engine turn at all.
//!
//! ## Design notes
//!
//! - **No signature verification of the grant.** Unlike the membership
//!   snapshot (`pool::fetch_verified_channel_members`, which verifies the
//!   relay's signature because a forged membership event could smuggle an
//!   unauthorized author into kind:9 admission), a forged or spoofed
//!   `kind:39007` cannot cause a safety violation here: the relay remains
//!   the sole floor authority and rejects any kind:9 publish from an agent
//!   that does not actually hold the floor server-side (Task 3). The worst
//!   case of trusting an unverified grant is a wasted CE turn followed by a
//!   rejected publish (a visible failure), or a missed turn the agent could
//!   have taken — never two agents talking over each other. Signature
//!   verification is therefore a defense-in-depth nice-to-have, not a
//!   correctness requirement, and is left out of this pass.
//! - **`BudgetExhausted` is a conflated name.** The wire only ever gives a
//!   client two distinguishable shapes: an explicit `kind:39007` (naming a
//!   holder, or `status=open` with no holder) or silence. Silence is what
//!   the relay's real per-owner-turn budget exhaustion looks like on the
//!   wire (`handlers::floor_glue::handle_floor_request` emits *no* grant on
//!   `FloorDecision::DeniedBudgetExhausted` — see that module's doc comment)
//!   — so genuine budget exhaustion and a slow/dead relay are indistinguishable
//!   from here and both surface as [`FloorAcquire::TimedOut`]. An *explicit*
//!   grant that simply doesn't name this agent (a legitimate round-robin
//!   turn for a sibling, or the TTL-reclaim `status=open` clear) is the one
//!   case this client CAN tell apart from silence, and is reported as
//!   [`FloorAcquire::BudgetExhausted`] even though it is not always literally
//!   budget exhaustion. Both variants resolve identically at the call site
//!   (skip the turn, stay quiet), so the distinction is diagnostic only.

use std::future::Future;
use std::time::Duration;

use nostr::{Event, EventBuilder, Keys, Kind, PublicKey, Tag};
use tokio::sync::broadcast;
use uuid::Uuid;

use buzz_core::kind::{KIND_FLOOR_GRANT, KIND_FLOOR_REQUEST};

use crate::relay::RelayError;

/// Outcome of an [`acquire_floor`] attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FloorAcquire {
    /// A `kind:39007` grant naming this agent as holder arrived — proceed
    /// with the Context Engine turn and publish.
    Granted,
    /// An explicit, decisive `kind:39007` arrived before the timeout that
    /// does NOT grant this agent the floor: either `status=open` (no
    /// holder — e.g. a TTL reclaim with no round-robin next agent) or a
    /// grant naming a different agent (a sibling's legitimate turn). See
    /// the module doc for why this is named `BudgetExhausted` even though
    /// it is not always literally the relay's budget-exhaustion path.
    BudgetExhausted,
    /// No decisive `kind:39007` event was observed within the timeout —
    /// including the relay's real budget-exhaustion path, which emits no
    /// grant at all. See the module doc for this conflation.
    TimedOut,
}

/// Build the signed `kind:20003` floor-request event for `channel_id`.
///
/// Mirrors `buzz_relay::floor_wire::floor_request_event`'s wire shape
/// (`h` tag = channel, no content) — reimplemented here rather than shared
/// because `buzz-acp` does not depend on `buzz-relay` (client vs. server
/// crate boundary).
fn build_floor_request_event(
    agent_keys: &Keys,
    channel_id: Uuid,
) -> Result<Event, nostr::event::builder::Error> {
    let channel_hex = channel_id.to_string();
    EventBuilder::new(Kind::Custom(KIND_FLOOR_REQUEST as u16), "")
        .tags([Tag::parse(["h", &channel_hex]).expect("channel uuid is a valid tag value")])
        .sign_with_keys(agent_keys)
}

/// First value of a tag named `name`, if present.
fn tag_value(event: &Event, name: &str) -> Option<String> {
    event.tags.iter().find_map(|tag| {
        let values = tag.as_slice();
        if values.first().map(String::as_str) == Some(name) {
            values.get(1).cloned()
        } else {
            None
        }
    })
}

/// Pure grant-matching predicate: classifies one already-received event
/// against `channel_id` and `agent_pubkey`.
///
/// Returns `None` for anything irrelevant to this wait — a non-`kind:39007`
/// event, or a `kind:39007` scoped to a different channel (`h`/`d` tag
/// mismatch) — so the caller keeps waiting rather than resolving on noise.
/// Returns `Some(Granted)` when the grant's `p` tag names `agent_pubkey`
/// (case-insensitive hex compare) and `Some(BudgetExhausted)` for every
/// other decisive shape (`status=open` with no `p` tag, or a `p` tag naming
/// someone else).
fn floor_grant_outcome(
    event: &Event,
    channel_id: Uuid,
    agent_pubkey: &PublicKey,
) -> Option<FloorAcquire> {
    if event.kind.as_u16() as u32 != KIND_FLOOR_GRANT {
        return None;
    }
    let channel_hex = channel_id.to_string();
    let matches_channel = tag_value(event, "h").as_deref() == Some(channel_hex.as_str());
    if !matches_channel {
        return None;
    }
    let agent_hex = agent_pubkey.to_hex();
    match tag_value(event, "p") {
        Some(holder) if holder.eq_ignore_ascii_case(&agent_hex) => Some(FloorAcquire::Granted),
        _ => Some(FloorAcquire::BudgetExhausted),
    }
}

/// Whether floor enforcement should gate a reply in this channel, mirroring
/// the relay's `crate::floor::is_floor_enforced` gate at the decision level
/// (Task 3/4): a `stream` channel with at least one OTHER agent present.
///
/// This is the pure decision — `resolve_floor_enforcement` below does the
/// I/O (roster + sibling classification) that produces `other_agent_present`.
/// Kept separate so the gating rule itself is unit-testable without a relay.
fn floor_enforced_decision(channel_type: &str, other_agent_present: bool) -> bool {
    channel_type == "stream" && other_agent_present
}

/// Whether a channel is even a *candidate* for floor-enforcement resolution
/// at all — the cheap pre-check `run_prompt_task` applies before spending an
/// HTTP round trip on `resolve_floor_enforcement`. A DM channel is always
/// exactly the owner and this one agent (see `buzz_envelope`'s DM roster
/// rule), so there is never a sibling to coordinate with — DM channels
/// bypass the floor protocol entirely, unconditionally, regardless of
/// whether an owner identity is resolved. An agent with no resolved owner
/// cannot classify any other roster member as a sibling either (see
/// `crate::is_owner_or_sibling`'s "no owner configured — fail closed"
/// branch), so that case is also never a candidate.
pub(crate) fn floor_enforcement_applicable(is_dm: bool, has_owner: bool) -> bool {
    has_owner && !is_dm
}

/// Resolve whether floor enforcement applies to `channel_id`, from an
/// already-fetched member roster.
///
/// Scoped to same-owner sibling agents (via `crate::check_sibling_via_profile`,
/// the same NIP-OA classification the inbound author gate already uses) —
/// the realistic deployment shape this feature targets (e.g. Gabe/Stacy
/// sharing a channel). A cross-owner agent in the same stream channel is NOT
/// detected by this heuristic; see the Task 6 report for that known scope
/// limitation. `members` pairs are `(pubkey_hex, role)`, as returned by
/// `pool::fetch_verified_channel_members`; `role` is unused here (NIP-29
/// owner/admin/member, not an agent classification).
pub(crate) async fn resolve_floor_enforcement(
    channel_type: &str,
    members: &[(String, String)],
    my_pubkey: &str,
    owner: &str,
    rest_client: &crate::relay::RestClient,
) -> bool {
    if channel_type != "stream" {
        return false;
    }
    for (pubkey, _role) in members {
        if pubkey.eq_ignore_ascii_case(my_pubkey) || pubkey.eq_ignore_ascii_case(owner) {
            continue;
        }
        if crate::check_sibling_via_profile(pubkey, owner, rest_client).await {
            return floor_enforced_decision(channel_type, true);
        }
    }
    floor_enforced_decision(channel_type, false)
}

/// Request the floor for `channel_id` and wait for a decisive grant.
///
/// Posts a signed `kind:20003` request via `submit_request` (production
/// callers pass a closure over the existing `RestClient::submit_event` HTTP
/// bridge — no new transport is introduced), then consumes `grant_rx`
/// (a `crate::relay::HarnessRelay`-fed broadcast receiver of `kind:39007`
/// events) until a decisive [`floor_grant_outcome`] arrives or `timeout`
/// elapses.
///
/// Returns `Err` only if `submit_request` itself fails (network/HTTP error)
/// — callers should treat that identically to [`FloorAcquire::TimedOut`]
/// (stay quiet; we cannot confirm we hold the floor).
pub(crate) async fn acquire_floor<Fut>(
    channel_id: Uuid,
    agent_keys: &Keys,
    grant_rx: &mut broadcast::Receiver<Event>,
    timeout: Duration,
    submit_request: impl FnOnce(Event) -> Fut,
) -> Result<FloorAcquire, RelayError>
where
    Fut: Future<Output = Result<(), RelayError>>,
{
    let request = build_floor_request_event(agent_keys, channel_id).map_err(RelayError::from)?;
    submit_request(request).await?;

    let agent_pubkey = agent_keys.public_key();
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Ok(FloorAcquire::TimedOut);
        }
        match tokio::time::timeout(remaining, grant_rx.recv()).await {
            Ok(Ok(event)) => {
                if let Some(outcome) = floor_grant_outcome(&event, channel_id, &agent_pubkey) {
                    return Ok(outcome);
                }
                // Irrelevant event (different channel, or not a grant at
                // all) — keep waiting within the remaining budget.
            }
            Ok(Err(broadcast::error::RecvError::Lagged(skipped))) => {
                tracing::debug!(
                    skipped,
                    channel_id = %channel_id,
                    "floor-grant broadcast receiver lagged — continuing to wait"
                );
            }
            Ok(Err(broadcast::error::RecvError::Closed)) => {
                // The forwarder task is gone (relay background task shut
                // down) — no grant will ever arrive on this receiver. Fail
                // safe: treat as TimedOut so the caller stays quiet rather
                // than assuming a grant it never saw.
                return Ok(FloorAcquire::TimedOut);
            }
            Err(_) => return Ok(FloorAcquire::TimedOut), // outer deadline elapsed
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> Uuid {
        Uuid::from_u128(42)
    }

    fn grant_event(relay: &Keys, channel_id: Uuid, holder: Option<&PublicKey>) -> Event {
        let channel_hex = channel_id.to_string();
        let mut tags = vec![
            Tag::parse(["d", &channel_hex]).unwrap(),
            Tag::parse(["h", &channel_hex]).unwrap(),
            Tag::parse(["rev", "1"]).unwrap(),
        ];
        match holder {
            Some(pk) => {
                tags.push(Tag::parse(["p", &pk.to_hex()]).unwrap());
                tags.push(Tag::parse(["status", "granted"]).unwrap());
            }
            None => tags.push(Tag::parse(["status", "open"]).unwrap()),
        }
        EventBuilder::new(Kind::Custom(KIND_FLOOR_GRANT as u16), "")
            .tags(tags)
            .sign_with_keys(relay)
            .expect("signs")
    }

    // --- build_floor_request_event ---

    #[test]
    fn floor_request_event_is_kind_20003_scoped_by_h_tag() {
        let agent = Keys::generate();
        let event = build_floor_request_event(&agent, channel()).expect("signs");
        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_REQUEST);
        assert_eq!(event.pubkey, agent.public_key());
        assert_eq!(tag_value(&event, "h"), Some(channel().to_string()));
    }

    // --- floor_grant_outcome (pure decision layer) ---

    #[test]
    fn grant_naming_this_agent_is_granted() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let event = grant_event(&relay, channel(), Some(&agent.public_key()));
        assert_eq!(
            floor_grant_outcome(&event, channel(), &agent.public_key()),
            Some(FloorAcquire::Granted)
        );
    }

    #[test]
    fn grant_naming_a_different_agent_is_budget_exhausted() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let sibling = Keys::generate();
        let event = grant_event(&relay, channel(), Some(&sibling.public_key()));
        assert_eq!(
            floor_grant_outcome(&event, channel(), &agent.public_key()),
            Some(FloorAcquire::BudgetExhausted)
        );
    }

    #[test]
    fn status_open_with_no_holder_is_budget_exhausted() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let event = grant_event(&relay, channel(), None);
        assert_eq!(
            floor_grant_outcome(&event, channel(), &agent.public_key()),
            Some(FloorAcquire::BudgetExhausted)
        );
    }

    #[test]
    fn grant_for_a_different_channel_is_ignored() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let event = grant_event(&relay, channel(), Some(&agent.public_key()));
        let other_channel = Uuid::from_u128(43);
        assert_eq!(
            floor_grant_outcome(&event, other_channel, &agent.public_key()),
            None
        );
    }

    #[test]
    fn non_grant_kind_is_ignored() {
        let agent = Keys::generate();
        let event = EventBuilder::new(Kind::Custom(9), "hi")
            .sign_with_keys(&agent)
            .expect("signs");
        assert_eq!(
            floor_grant_outcome(&event, channel(), &agent.public_key()),
            None
        );
    }

    // --- floor_enforced_decision (pure gating rule) ---

    #[test]
    fn stream_channel_with_another_agent_is_enforced() {
        assert!(floor_enforced_decision("stream", true));
    }

    #[test]
    fn stream_channel_alone_is_not_enforced() {
        assert!(!floor_enforced_decision("stream", false));
    }

    #[test]
    fn dm_channel_is_never_enforced_even_with_another_agent() {
        assert!(!floor_enforced_decision("dm", true));
    }

    // --- floor_enforcement_applicable (dm/no-owner bypass pre-check) ---

    #[test]
    fn dm_channel_is_never_applicable_even_with_a_resolved_owner() {
        assert!(!floor_enforcement_applicable(true, true));
    }

    #[test]
    fn stream_channel_with_a_resolved_owner_is_applicable() {
        assert!(floor_enforcement_applicable(false, true));
    }

    #[test]
    fn stream_channel_with_no_resolved_owner_is_not_applicable() {
        assert!(!floor_enforcement_applicable(false, false));
    }

    // --- acquire_floor (async control flow, no live relay) ---

    async fn noop_submit(_event: Event) -> Result<(), RelayError> {
        Ok(())
    }

    #[tokio::test]
    async fn acquire_floor_resolves_granted_when_grant_names_this_agent() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let (tx, mut rx) = broadcast::channel(8);
        let grant = grant_event(&relay, channel(), Some(&agent.public_key()));
        tx.send(grant).unwrap();

        let outcome = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_secs(5),
            noop_submit,
        )
        .await
        .expect("submit ok");
        assert_eq!(outcome, FloorAcquire::Granted);
    }

    #[tokio::test]
    async fn acquire_floor_resolves_budget_exhausted_on_status_open() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let (tx, mut rx) = broadcast::channel(8);
        let grant = grant_event(&relay, channel(), None);
        tx.send(grant).unwrap();

        let outcome = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_secs(5),
            noop_submit,
        )
        .await
        .expect("submit ok");
        assert_eq!(outcome, FloorAcquire::BudgetExhausted);
    }

    #[tokio::test]
    async fn acquire_floor_ignores_grant_for_a_different_channel_then_resolves_on_the_real_one() {
        let relay = Keys::generate();
        let agent = Keys::generate();
        let (tx, mut rx) = broadcast::channel(8);
        let other_channel = Uuid::from_u128(99);
        tx.send(grant_event(
            &relay,
            other_channel,
            Some(&agent.public_key()),
        ))
        .unwrap();
        tx.send(grant_event(&relay, channel(), Some(&agent.public_key())))
            .unwrap();

        let outcome = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_secs(5),
            noop_submit,
        )
        .await
        .expect("submit ok");
        assert_eq!(outcome, FloorAcquire::Granted);
    }

    #[tokio::test(start_paused = true)]
    async fn acquire_floor_times_out_when_no_grant_arrives() {
        let agent = Keys::generate();
        let (_tx, mut rx) = broadcast::channel::<Event>(8);

        let outcome = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_millis(200),
            noop_submit,
        )
        .await
        .expect("submit ok");
        assert_eq!(outcome, FloorAcquire::TimedOut);
    }

    #[tokio::test]
    async fn acquire_floor_times_out_when_sender_side_is_dropped() {
        let agent = Keys::generate();
        let (tx, mut rx) = broadcast::channel::<Event>(8);
        drop(tx);

        let outcome = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_secs(5),
            noop_submit,
        )
        .await
        .expect("submit ok");
        assert_eq!(outcome, FloorAcquire::TimedOut);
    }

    #[tokio::test]
    async fn acquire_floor_propagates_a_submit_failure() {
        let agent = Keys::generate();
        let (_tx, mut rx) = broadcast::channel::<Event>(8);

        let result = acquire_floor(
            channel(),
            &agent,
            &mut rx,
            Duration::from_secs(5),
            |_event| async { Err(RelayError::ConnectionClosed) },
        )
        .await;
        assert!(matches!(result, Err(RelayError::ConnectionClosed)));
    }

    // --- resolve_floor_enforcement (async I/O wrapper) ---
    //
    // No live relay in this crate's test harness — the roster/sibling I/O
    // path is exercised indirectly through `check_sibling_via_profile`'s own
    // tests in `lib.rs`. Documented deferral per the Task 6 brief: covering
    // this wrapper directly would require standing up a mock HTTP relay
    // bridge, which is out of scope for this pass. The non-"stream" and
    // empty-roster short-circuits below need no HTTP at all, so they are
    // covered directly.

    #[tokio::test]
    async fn resolve_floor_enforcement_short_circuits_on_non_stream_channel_type() {
        let rest_client = crate::relay::RestClient {
            http: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".to_string(),
            keys: Keys::generate(),
            auth_tag_json: None,
            relay_self_pubkey_cache: Default::default(),
        };
        let members = vec![("aa".to_string(), "member".to_string())];
        let enforced = resolve_floor_enforcement("dm", &members, "aa", "bb", &rest_client).await;
        assert!(!enforced, "dm channels must never be floor-enforced");
    }

    #[tokio::test]
    async fn resolve_floor_enforcement_is_false_for_an_empty_roster() {
        let rest_client = crate::relay::RestClient {
            http: reqwest::Client::new(),
            base_url: "http://127.0.0.1:1".to_string(),
            keys: Keys::generate(),
            auth_tag_json: None,
            relay_self_pubkey_cache: Default::default(),
        };
        let enforced = resolve_floor_enforcement("stream", &[], "aa", "bb", &rest_client).await;
        assert!(!enforced, "no roster to check means no other agent found");
    }
}
