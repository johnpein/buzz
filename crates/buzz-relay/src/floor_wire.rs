//! Wire-shape construction for the group-chat floor request/grant protocol
//! (Task 4 of the multi-agent floor-lease work).
//!
//! [`crate::floor`] owns the decision state machine (`FloorLease`, its
//! `request`/`on_publish`/`reclaim_if_expired` transitions, and the
//! monotonically increasing `revision` counter) and performs no I/O. This
//! module owns turning a decision into the two signed Nostr events the wire
//! protocol defines (see `NOSTR.md`):
//!
//! - `kind:20003` ([`buzz_core::kind::KIND_FLOOR_REQUEST`]) — an ephemeral
//!   event an agent posts to ask for the floor, scoped to the channel via an
//!   `h` tag.
//! - `kind:39007` ([`buzz_core::kind::KIND_FLOOR_GRANT`]) — a relay-signed,
//!   addressable, fan-out-only event naming the channel's current holder,
//!   expiry, and revision.
//!
//! Building these events needs no database and no running relay state — only
//! a keypair and the already-decided values — so this module stays plain
//! pure functions, unit-testable without Postgres. The relay handler
//! (`crate::handlers::ingest::{resolve_floor_lease, enforce_floor_lease,
//! handle_floor_request}` and `crate::handlers::side_effects::emit_floor_grant`)
//! is the thin I/O glue that calls `FloorLease`, then calls this module, then
//! signs/fans out the result via the existing subscription/pubsub plumbing.

use std::time::Duration;

use buzz_sdk::broker::PubkeyHex;
use nostr::{Event, EventBuilder, Kind, Tag};
use uuid::Uuid;

use buzz_core::kind::{KIND_FLOOR_GRANT, KIND_FLOOR_REQUEST};

/// Build the relay-signed `kind:39007` floor-grant event naming `holder` as
/// `channel_id`'s current [`crate::floor::FloorLease`] holder.
///
/// - `d` and `h` both carry `channel_id` — addressable-by-channel, and
///   `h`-scoped like every other channel-scoped kind.
/// - `p` carries `holder`'s hex pubkey.
/// - `rev` carries `revision` (see [`crate::floor::FloorLease::revision`]):
///   callers pass the lease's post-grant value, so `rev` strictly increases
///   across every grant a given lease has ever issued.
/// - `expiration` carries `now + ttl` in unix seconds (NIP-40 convention),
///   so a client can tell a grant is stale without waiting for the relay to
///   reclaim and re-announce.
///
/// # Errors
///
/// Returns the underlying [`nostr::event::builder::Error`] if signing fails
/// (e.g. an invalid keypair) — expected to be infallible in practice for a
/// well-formed `relay_keys`, but propagated rather than unwrapped so a
/// caller can log the channel/holder context.
pub fn floor_grant_event(
    relay_keys: &nostr::Keys,
    channel_id: Uuid,
    holder: &PubkeyHex,
    revision: u64,
    ttl: Duration,
) -> Result<Event, nostr::event::builder::Error> {
    let channel_hex = channel_id.to_string();
    let expiry = nostr::Timestamp::now() + ttl.as_secs();
    let tags = [
        Tag::parse(["d", &channel_hex]).expect("channel uuid is a valid tag value"),
        Tag::parse(["h", &channel_hex]).expect("channel uuid is a valid tag value"),
        Tag::parse(["p", holder.as_str()]).expect("hex pubkey is a valid tag value"),
        Tag::parse(["rev", &revision.to_string()]).expect("revision is a valid tag value"),
        Tag::parse(["expiration", &expiry.as_secs().to_string()])
            .expect("timestamp is a valid tag value"),
    ];
    EventBuilder::new(Kind::Custom(KIND_FLOOR_GRANT as u16), "")
        .tags(tags)
        .sign_with_keys(relay_keys)
}

/// Build a signed `kind:20003` floor-request event for `channel_id`, scoped
/// via an `h` tag.
///
/// Production requests are authored client-side by the requesting agent's
/// own key, not by the relay — this helper exists so reference clients and
/// tests can construct a wire-conformant request without hand-rolling the
/// tag shape.
///
/// # Errors
///
/// Returns the underlying [`nostr::event::builder::Error`] if signing fails.
pub fn floor_request_event(
    agent_keys: &nostr::Keys,
    channel_id: Uuid,
) -> Result<Event, nostr::event::builder::Error> {
    let channel_hex = channel_id.to_string();
    EventBuilder::new(Kind::Custom(KIND_FLOOR_REQUEST as u16), "")
        .tags([Tag::parse(["h", &channel_hex]).expect("channel uuid is a valid tag value")])
        .sign_with_keys(agent_keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn channel() -> Uuid {
        Uuid::from_u128(1)
    }

    #[test]
    fn floor_request_event_is_kind_20003_scoped_by_h_tag() {
        let agent = nostr::Keys::generate();
        let event = floor_request_event(&agent, channel()).expect("signs");
        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_REQUEST);
        assert_eq!(event.pubkey, agent.public_key());
        let h = event
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("h"))
            .expect("h tag present");
        assert_eq!(h.as_slice().get(1).map(String::as_str), Some(channel().to_string()).as_deref());
    }

    #[test]
    fn floor_grant_event_is_kind_39007_addressable_and_carries_holder_and_revision() {
        let relay = nostr::Keys::generate();
        let holder = PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex()).unwrap();
        let event =
            floor_grant_event(&relay, channel(), &holder, 3, Duration::from_secs(30)).expect("signs");

        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_GRANT);
        assert_eq!(event.pubkey, relay.public_key());

        let tag_value = |name: &str| {
            event
                .tags
                .iter()
                .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
                .and_then(|t| t.as_slice().get(1).cloned())
        };
        assert_eq!(tag_value("d"), Some(channel().to_string()));
        assert_eq!(tag_value("h"), Some(channel().to_string()));
        assert_eq!(tag_value("p"), Some(holder.as_str().to_string()));
        assert_eq!(tag_value("rev"), Some("3".to_string()));
        assert!(tag_value("expiration").is_some());
    }

    #[test]
    fn floor_grant_event_revision_strictly_increases_across_calls() {
        // Mirrors the relay handler's real usage: it calls this once per
        // fresh FloorLease::request() grant, passing the lease's running
        // revision counter — never resetting or reusing a value.
        let relay = nostr::Keys::generate();
        let holder = PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex()).unwrap();
        let first = floor_grant_event(&relay, channel(), &holder, 1, Duration::from_secs(30))
            .expect("signs");
        let second = floor_grant_event(&relay, channel(), &holder, 2, Duration::from_secs(30))
            .expect("signs");

        let rev = |e: &Event| -> u64 {
            e.tags
                .iter()
                .find(|t| t.as_slice().first().map(String::as_str) == Some("rev"))
                .and_then(|t| t.as_slice().get(1).and_then(|v| v.parse().ok()))
                .expect("rev tag present and numeric")
        };
        assert!(rev(&second) > rev(&first));
    }
}
