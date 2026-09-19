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
//!   expiry, and revision — or, since Task 4's review, an explicit
//!   "cleared/open" variant with no holder (see [`floor_grant_event`]).
//!
//! Building these events needs no database and no running relay state — only
//! a keypair and the already-decided values — so this module stays plain
//! pure functions, unit-testable without Postgres. The relay handler
//! (`crate::handlers::floor_glue::{resolve_floor_lease, handle_floor_request,
//! emit_floor_grant}` plus `crate::handlers::ingest::enforce_floor_lease`,
//! which stays inline at the ingest CAS seam) is the thin I/O glue that
//! calls `FloorLease`, then calls this module, then signs/fans out the
//! result via the existing subscription/pubsub plumbing.

use std::time::Duration;

use buzz_sdk::broker::PubkeyHex;
use nostr::{Event, EventBuilder, Kind, Tag};
use uuid::Uuid;

use buzz_core::kind::{KIND_FLOOR_GRANT, KIND_FLOOR_REQUEST};

/// Build the relay-signed `kind:39007` floor-grant event for `channel_id`.
///
/// `holder` is `Some(pubkey)` for a normal grant naming the current
/// [`crate::floor::FloorLease`] holder, or `None` for the "floor cleared /
/// open" variant (Task 4 review Fix 1: a TTL reclaim frees a stalled holder
/// with no round-robin next agent to hand off to — see
/// `crate::floor::GrantBroadcast::Clear`). Both variants are the same event
/// kind, addressable by the same `d`/`h` tag, so a cleared grant replaces a
/// prior holder-naming grant for any subscriber that only keeps the latest
/// per-channel `kind:39007`.
///
/// - `d` and `h` both carry `channel_id` — addressable-by-channel, and
///   `h`-scoped like every other channel-scoped kind.
/// - `p` carries `holder`'s hex pubkey when `Some`; omitted entirely for the
///   cleared/open variant, which is the wire signal a subscriber uses to
///   tell "someone holds it" apart from "no one currently does".
/// - `status` is `"granted"` when `holder` is `Some`, `"open"` when `None`
///   — an explicit, redundant-with-`p`-absence marker so a consumer never
///   has to infer the cleared state from a tag's mere absence.
/// - `rev` carries `revision` (see [`crate::floor::FloorLease::revision`]):
///   callers pass the lease's post-transition value, so `rev` strictly
///   increases across every grant *and* every clear a given lease has ever
///   issued — [`crate::floor::FloorLease::reclaim_if_expired`] bumps the
///   revision on a real clear for exactly this reason, so a clear is always
///   provably newer than the grant it supersedes.
/// - `expiration` carries `now + ttl` in unix seconds (NIP-40 convention),
///   so a client can tell a grant is stale without waiting for the relay to
///   reclaim and re-announce. Carried on the cleared variant too, even
///   though it is moot there, so every `kind:39007` has a uniform tag set.
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
    holder: Option<&PubkeyHex>,
    revision: u64,
    ttl: Duration,
) -> Result<Event, nostr::event::builder::Error> {
    // `granted` names a holder (`p` tag); `open` clears the floor for
    // requests. The "closed" state is a sibling variant, see
    // [`floor_closed_event`].
    let status = if holder.is_some() { "granted" } else { "open" };
    build_floor_event(relay_keys, channel_id, holder, status, revision, ttl)
}

/// Shared builder for every relay-signed `kind:39007` overlay: the uniform
/// `d`/`h`/`rev`/`expiration` tag set, an optional `p` holder tag, and an
/// explicit `status` marker. The three public variants — `granted`, `open`
/// ([`floor_grant_event`]) and `closed` ([`floor_closed_event`]) — differ
/// only in `holder`/`status`, so the tag construction lives here once.
fn build_floor_event(
    relay_keys: &nostr::Keys,
    channel_id: Uuid,
    holder: Option<&PubkeyHex>,
    status: &str,
    revision: u64,
    ttl: Duration,
) -> Result<Event, nostr::event::builder::Error> {
    let channel_hex = channel_id.to_string();
    let expiry = nostr::Timestamp::now() + ttl.as_secs();
    let mut tags = vec![
        Tag::parse(["d", &channel_hex]).expect("channel uuid is a valid tag value"),
        Tag::parse(["h", &channel_hex]).expect("channel uuid is a valid tag value"),
        Tag::parse(["rev", &revision.to_string()]).expect("revision is a valid tag value"),
        Tag::parse(["expiration", &expiry.as_secs().to_string()])
            .expect("timestamp is a valid tag value"),
    ];
    if let Some(holder) = holder {
        tags.push(Tag::parse(["p", holder.as_str()]).expect("hex pubkey is a valid tag value"));
    }
    tags.push(Tag::parse(["status", status]).expect("status is a valid tag value"));
    EventBuilder::new(Kind::Custom(KIND_FLOOR_GRANT as u16), "")
        .tags(tags)
        .sign_with_keys(relay_keys)
}

/// Build the relay-signed `kind:39007` "floor closed" event for `channel_id`.
///
/// Emitted when the channel's per-owner-turn agent budget is exhausted (see
/// [`crate::floor::FloorDecision::DeniedBudgetExhausted`] and
/// [`crate::floor::GrantBroadcast::Closed`]): no agent may take the floor
/// again until the owner speaks. It is the explicit wire counterpart to what
/// used to be silence — a waiting [`buzz-acp` floor client] resolves any
/// `kind:39007` for its channel that does not name it as holder to "not my
/// turn, stay quiet" *immediately*, instead of waiting out its acquire
/// timeout (Follow-up (a), 2026-09-18).
///
/// Shape mirrors the `open` variant of [`floor_grant_event`] — no `p` tag,
/// uniform `d`/`h`/`rev`/`expiration` — but carries `status="closed"` rather
/// than `"open"`. The distinction matters for correctness of any future
/// consumer: `"open"` means the floor is *free to request*, whereas
/// `"closed"` means requesting is futile until the owner reopens it, so the
/// two must never be conflated on the wire.
///
/// `revision` is the lease's current [`crate::floor::FloorLease::revision`],
/// carried unchanged: budget exhaustion is not a fresh holder transition and
/// deliberately does not bump the revision (see
/// `crate::floor::FloorLease`'s `revision_does_not_bump_while_queued_or_budget_denied`
/// contract), and the sole live consumer resolves on holder identity, not
/// `rev`.
///
/// # Errors
///
/// Returns the underlying [`nostr::event::builder::Error`] if signing fails.
pub fn floor_closed_event(
    relay_keys: &nostr::Keys,
    channel_id: Uuid,
    revision: u64,
    ttl: Duration,
) -> Result<Event, nostr::event::builder::Error> {
    build_floor_event(relay_keys, channel_id, None, "closed", revision, ttl)
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

    fn tag_value(event: &Event, name: &str) -> Option<String> {
        event
            .tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some(name))
            .and_then(|t| t.as_slice().get(1).cloned())
    }

    #[test]
    fn floor_grant_event_is_kind_39007_addressable_and_carries_holder_and_revision() {
        let relay = nostr::Keys::generate();
        let holder = PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex()).unwrap();
        let event = floor_grant_event(&relay, channel(), Some(&holder), 3, Duration::from_secs(30))
            .expect("signs");

        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_GRANT);
        assert_eq!(event.pubkey, relay.public_key());

        assert_eq!(tag_value(&event, "d"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "h"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "p"), Some(holder.as_str().to_string()));
        assert_eq!(tag_value(&event, "status"), Some("granted".to_string()));
        assert_eq!(tag_value(&event, "rev"), Some("3".to_string()));
        assert!(tag_value(&event, "expiration").is_some());
    }

    // --- Task 4 review Fix 1: the "floor cleared / open" grant variant ---

    #[test]
    fn floor_grant_event_open_variant_has_no_p_tag_and_status_open() {
        let relay = nostr::Keys::generate();
        let event = floor_grant_event(&relay, channel(), None, 4, Duration::from_secs(30))
            .expect("signs");

        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_GRANT);
        assert_eq!(tag_value(&event, "d"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "h"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "p"), None, "cleared grant must carry no holder");
        assert_eq!(tag_value(&event, "status"), Some("open".to_string()));
        assert_eq!(tag_value(&event, "rev"), Some("4".to_string()));
        assert!(tag_value(&event, "expiration").is_some());
    }

    // --- Follow-up (a): the "floor closed / budget exhausted" variant ---

    #[test]
    fn floor_closed_event_has_no_p_tag_and_status_closed() {
        let relay = nostr::Keys::generate();
        let event = floor_closed_event(&relay, channel(), 5, Duration::from_secs(30))
            .expect("signs");

        assert_eq!(event.kind.as_u16() as u32, KIND_FLOOR_GRANT);
        assert_eq!(event.pubkey, relay.public_key());
        assert_eq!(tag_value(&event, "d"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "h"), Some(channel().to_string()));
        assert_eq!(tag_value(&event, "p"), None, "a closed floor names no holder");
        assert_eq!(
            tag_value(&event, "status"),
            Some("closed".to_string()),
            "budget-exhausted close must be status=closed, never conflated with open"
        );
        assert_eq!(tag_value(&event, "rev"), Some("5".to_string()));
        assert!(tag_value(&event, "expiration").is_some());
    }

    #[test]
    fn floor_grant_event_revision_strictly_increases_across_calls() {
        // Mirrors the relay handler's real usage: it calls this once per
        // fresh FloorLease::request() grant, passing the lease's running
        // revision counter — never resetting or reusing a value.
        let relay = nostr::Keys::generate();
        let holder = PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex()).unwrap();
        let first = floor_grant_event(&relay, channel(), Some(&holder), 1, Duration::from_secs(30))
            .expect("signs");
        let second = floor_grant_event(&relay, channel(), Some(&holder), 2, Duration::from_secs(30))
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

    #[test]
    fn floor_grant_event_revision_strictly_increases_across_a_grant_then_a_clear() {
        // Mirrors `FloorLease::reclaim_if_expired`'s revision bump on a real
        // Some->None clear (see its doc comment): the cleared event's
        // revision must exceed the grant it supersedes, exactly like two
        // successive holder grants do above.
        let relay = nostr::Keys::generate();
        let holder = PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex()).unwrap();
        let granted = floor_grant_event(&relay, channel(), Some(&holder), 1, Duration::from_secs(30))
            .expect("signs");
        let cleared = floor_grant_event(&relay, channel(), None, 2, Duration::from_secs(30))
            .expect("signs");

        let rev = |e: &Event| -> u64 {
            tag_value(e, "rev").and_then(|v| v.parse().ok()).expect("rev tag present and numeric")
        };
        assert!(
            rev(&cleared) > rev(&granted),
            "a cleared grant's revision must strictly exceed the grant it supersedes"
        );
    }
}
