//! Who a stream-channel reply `p`-tags.
//!
//! Agents run mention-gated (`BUZZ_ACP_SUBSCRIBE=mentions`), so a sibling agent
//! only takes a turn on a reply that mentions it. A managed agent addresses a
//! room member the way a person does in Buzz Desktop — `@DisplayName` in the
//! text — and this module turns those into mention pubkeys. Only members of the
//! relay-signed roster the prompt was verified against are ever candidates, so
//! reply text can never page anyone outside the room. A reply that addresses
//! nobody mentions nobody, which is what ends an agent-to-agent exchange.

use std::collections::HashMap;
use std::time::Duration;

use crate::relay::RestClient;

const PROFILE_LOOKUP_TIMEOUT: Duration = Duration::from_millis(2000);

/// A roster member and the profile names it can be addressed by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Addressable {
    pub pubkey: String,
    pub names: Vec<String>,
}

/// Roster members the reply addresses as `@Name`, in roster order.
///
/// Mirrors Buzz Desktop's `extractMentionPubkeys`: names match
/// case-insensitively, and at each `@` only the longest matching name wins so
/// a member whose name prefixes another's is not spuriously tagged.
pub(crate) fn addressed_pubkeys(text: &str, roster: &[Addressable]) -> Vec<String> {
    let mut addressed: Vec<&str> = Vec::new();
    let mut previous: Option<char> = None;
    for (offset, current) in text.char_indices() {
        // `name@host` is an address, not a mention.
        let starts_mention = current == '@' && !previous.is_some_and(is_name_char);
        previous = Some(current);
        if !starts_mention {
            continue;
        }
        let after = &text[offset + current.len_utf8()..];
        let mut longest = 0;
        let mut winners: Vec<&str> = Vec::new();
        for member in roster {
            for name in &member.names {
                let length = name.chars().count();
                if length < longest || !names_at_start(after, name) {
                    continue;
                }
                if length > longest {
                    longest = length;
                    winners.clear();
                }
                winners.push(&member.pubkey);
            }
        }
        addressed.extend(winners);
    }
    roster
        .iter()
        .map(|member| member.pubkey.as_str())
        .filter(|pubkey| addressed.contains(pubkey))
        .map(str::to_string)
        .collect()
}

fn is_name_char(value: char) -> bool {
    value.is_alphanumeric() || value == '_'
}

/// Whether `text` begins with `name` (case-insensitive) ending on a word boundary.
fn names_at_start(text: &str, name: &str) -> bool {
    let mut rest = text.chars();
    for expected in name.chars() {
        match rest.next() {
            Some(actual) if actual.to_lowercase().eq(expected.to_lowercase()) => {}
            _ => return false,
        }
    }
    !rest.next().is_some_and(is_name_char)
}

/// Resolve the mentions for a stream reply.
///
/// `Err` means the roster's names could not be read right now. The caller must
/// retry rather than publish unmentioned: the mention set is part of the
/// durable reply's fingerprint, so it has to come out the same on every attempt.
pub(crate) async fn resolve(
    rest_client: &RestClient,
    roster: &[String],
    own_pubkey: &str,
    text: &str,
) -> Result<Vec<String>, String> {
    let others: Vec<&String> = roster
        .iter()
        .filter(|pubkey| !pubkey.eq_ignore_ascii_case(own_pubkey))
        .collect();
    if others.is_empty() || !text.contains('@') {
        return Ok(Vec::new());
    }
    let authors = others
        .iter()
        .map(|pubkey| nostr::PublicKey::from_hex(pubkey.as_str()))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("roster pubkey is invalid: {error}"))?;
    let filter = nostr::Filter::new()
        .kind(nostr::Kind::Metadata)
        .authors(authors);
    let response = tokio::time::timeout(PROFILE_LOOKUP_TIMEOUT, rest_client.query(&[filter]))
        .await
        .map_err(|_| "roster profile lookup timed out".to_string())?
        .map_err(|error| format!("roster profile lookup failed: {error}"))?;
    let names = profile_names(&response);
    let addressable = others
        .into_iter()
        .map(|pubkey| Addressable {
            pubkey: pubkey.to_ascii_lowercase(),
            names: names
                .get(&pubkey.to_ascii_lowercase())
                .cloned()
                .unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    Ok(addressed_pubkeys(text, &addressable))
}

/// Names from each author's newest validly signed kind-0 profile.
fn profile_names(response: &serde_json::Value) -> HashMap<String, Vec<String>> {
    let mut newest: HashMap<String, nostr::Event> = HashMap::new();
    for value in response.as_array().into_iter().flatten() {
        let Ok(event) = serde_json::from_value::<nostr::Event>(value.clone()) else {
            continue;
        };
        if event.kind != nostr::Kind::Metadata || event.verify().is_err() {
            continue;
        }
        let author = event.pubkey.to_hex().to_ascii_lowercase();
        if newest
            .get(&author)
            .is_none_or(|known| known.created_at < event.created_at)
        {
            newest.insert(author, event);
        }
    }
    newest
        .into_iter()
        .map(|(author, event)| {
            let profile: serde_json::Value =
                serde_json::from_str(&event.content).unwrap_or_default();
            let names = ["display_name", "displayName", "name"]
                .iter()
                .filter_map(|field| profile.get(field).and_then(serde_json::Value::as_str))
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect();
            (author, names)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(pubkey: &str, names: &[&str]) -> Addressable {
        Addressable {
            pubkey: pubkey.to_string(),
            names: names.iter().map(|name| name.to_string()).collect(),
        }
    }

    #[test]
    fn addressing_a_member_by_name_mentions_only_that_member() {
        let roster = [member("aa", &["Stacy"]), member("bb", &["John"])];
        assert_eq!(
            addressed_pubkeys("@stacy, can you check the ledger?", &roster),
            vec!["aa"]
        );
        assert_eq!(
            addressed_pubkeys("Done — @John and @Stacy, see above.", &roster),
            vec!["aa", "bb"]
        );
    }

    #[test]
    fn a_reply_that_addresses_nobody_mentions_nobody() {
        let roster = [member("aa", &["Stacy"])];
        for text in [
            "Stacy already answered that.",
            "mail stacy@example.com about it",
            "@Stacyx is someone else",
            "@Stranger is not in this room",
        ] {
            assert!(addressed_pubkeys(text, &roster).is_empty(), "{text}");
        }
    }

    #[test]
    fn the_longest_name_wins_at_one_offset() {
        let roster = [member("aa", &["Sam"]), member("bb", &["Sam Lee"])];
        assert_eq!(addressed_pubkeys("over to @Sam Lee", &roster), vec!["bb"]);
        assert_eq!(addressed_pubkeys("over to @Sam.", &roster), vec!["aa"]);
    }

    #[test]
    fn profile_names_use_the_newest_verified_profile_only() {
        let keys = nostr::Keys::generate();
        let profile = |content: &str, at: u64| {
            let event = nostr::EventBuilder::new(nostr::Kind::Metadata, content)
                .custom_created_at(nostr::Timestamp::from(at))
                .sign_with_keys(&keys)
                .expect("signed profile");
            serde_json::to_value(event).expect("profile JSON")
        };
        let mut forged = profile(r#"{"name":"Forged"}"#, 300);
        forged["content"] = serde_json::json!(r#"{"name":"Tampered"}"#);
        let response = serde_json::json!([
            profile(r#"{"name":"old"}"#, 100),
            profile(r#"{"display_name":"Stacy","name":"stacy-agent"}"#, 200),
            forged,
        ]);
        let names = profile_names(&response);
        assert_eq!(
            names.get(&keys.public_key().to_hex()),
            Some(&vec!["Stacy".to_string(), "stacy-agent".to_string()])
        );
    }
}
