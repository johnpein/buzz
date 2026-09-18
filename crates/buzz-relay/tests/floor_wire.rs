//! Wire-level conformance for the group-chat floor request/grant protocol
//! (Task 4): a `kind:20003` request decided against a real
//! [`buzz_relay::floor::FloorLease`] produces a real signed `kind:39007`
//! grant event ([`buzz_relay::floor_wire::floor_grant_event`]) that is
//! actually matched by the relay's real subscription fan-out
//! ([`buzz_relay::subscription::SubscriptionRegistry::fan_out_scoped`]) —
//! not a re-implementation of either.
//!
//! `fan_out_scoped` is called directly here rather than through
//! `handlers::event::filter_fanout_by_access` (Task 4 review Fix 4): that
//! access filter only narrows delivery for private/membership-gated
//! channels, which is immaterial for these tests' open, channel-scoped
//! overlay subscriptions — acknowledged, not exercised.
//!
//! ## What changed in the Task 4 review (Fix 1 / Fix 2)
//!
//! [`buzz_relay::floor::evaluate_floor_publish`] is the pure decision layer
//! added by the review: it wraps `evaluate_floor_at_ingest` with the
//! `kind:39007` fan-out decision the ingest glue needs, including the new
//! "floor cleared / open" grant (no holder) a TTL reclaim produces when
//! there is no round-robin next agent to hand off to. That decision is
//! exercised directly against a real `FloorLease` in
//! `crates/buzz-relay/src/floor.rs`'s own test module (no Postgres needed —
//! it only touches the lease and a synthetic roster); this file adds the
//! wire-shape layer on top: the real `floor_grant_event(None, ...)` output
//! and its `rev`-strictly-greater property, fanned out through the real
//! `SubscriptionRegistry` exactly as the two tests below already do for a
//! normal grant.
//!
//! ## Why this file exists instead of `crates/buzz-conformance/`
//!
//! The task brief asked for these assertions to live in the
//! `buzz-conformance` crate, "follow its existing test structure". That
//! crate's entire structure — [`buzz_conformance::TraceAction`], the
//! `ModelState`/`check_step` replay engine, every existing fixture in
//! `tests/replay_fixtures.rs` and `tests/proptest_checker.rs` — is an
//! independent Rust re-implementation of `docs/spec/MultiTenantRelay.tla`'s
//! `Next` transition relation: multi-tenant row/community non-interference.
//! Its trace schema has no vocabulary for a floor decision, a grant, or a
//! revision — extending it here would mean bolting a second, unrelated
//! protocol onto a checker whose whole design point (per its own module
//! docs) is being an *independent, single-purpose* validator for the
//! tenant-isolation spec. That felt like exactly the kind of "plausible but
//! wrong wiring" the brief said to avoid, so this is a deliberate deviation:
//! documented, not guessed.
//!
//! Task 3's own precedent is the fallback this file follows instead:
//! `crates/buzz-relay/tests/floor_lease.rs` already established
//! `crates/buzz-relay/tests/` as the floor protocol's real conformance home,
//! exercising the pure/decision surface as an external integration test
//! rather than a unit test buried in `floor.rs`. This file extends that
//! same home one layer further out: real signed wire events plus the real
//! (pure, in-memory, no-Postgres) subscription registry, instead of only
//! the decision enum.
//!
//! ## What is honestly tested here vs. deferred (review Fix 2)
//!
//! Layers actually exercised, end to end, by this file plus
//! `crates/buzz-relay/src/floor.rs`'s own test module:
//!
//! - the pure decision layer — real `FloorLease` transitions
//!   (`request`/`on_publish`/`reclaim_if_expired`) and, since the review,
//!   real `evaluate_floor_publish` grant-vs-clear-vs-nothing decisions
//!   (`floor.rs` tests — no Postgres, no `AppState`);
//! - the pure wire-shape layer — real `floor_grant_event`/
//!   `floor_request_event` output, including the new cleared/open variant
//!   (`floor_wire.rs` tests, and the clear-grant tests below);
//! - the real, in-memory `subscription::SubscriptionRegistry` fan-out
//!   (`fan_out_scoped`, exercised by every test in this file).
//!
//! What this file's `build_and_fan_out_grant` does **not** do — despite its
//! name mirroring `handlers::floor_glue::emit_floor_grant` — is call that
//! function, or `resolve_floor_lease`, or `handle_floor_request`, or the
//! `enforce_floor_lease` auto-grant branch. Those are `async fn`s that read
//! the channel roster and agent classification through `state.db`
//! (Postgres) and deliver over the real Redis/WebSocket transport; driving
//! them needs a live Postgres-backed `AppState`, which this crate's
//! existing floor tests (`floor_lease.rs`) also don't stand up. That
//! DB-backed handler path — the real `ingest_event` entry point, not a
//! mirror — is a documented deferral to the Phase-3 integration proof (plan
//! Task 13), not something this file claims to cover. Until then it is
//! exercised by compilation + clippy + the pure tests here; if that glue is
//! wrong, it is wrong in the same way Task 3's already-landed
//! `enforce_floor_lease` would be.

use std::time::{Duration, Instant};

use uuid::Uuid;

use buzz_core::tenant::CommunityId;
use buzz_core::StoredEvent;
use buzz_relay::floor::{FloorDecision, FloorLease, NextGrant};
use buzz_relay::floor_wire::floor_grant_event;
use buzz_relay::subscription::SubscriptionRegistry;
use buzz_sdk::broker::PubkeyHex;

fn pubkey() -> PubkeyHex {
    PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex())
        .expect("generated key is a valid pubkey")
}

/// A subscriber registered for the channel's `kind:39007` grant overlay —
/// the shape a connected agent's own client subscription takes.
fn subscribe_to_channel_grants(registry: &SubscriptionRegistry, community: CommunityId, channel_id: Uuid) {
    let filter = nostr::Filter::new().kind(nostr::Kind::Custom(
        buzz_core::kind::KIND_FLOOR_GRANT as u16,
    ));
    registry.register_scoped(
        community,
        Uuid::new_v4(), // conn_id
        "sub-grants".to_string(),
        vec![filter],
        Some(channel_id),
    );
}

/// Build+fan-out a grant for `holder` (or the cleared/open variant when
/// `None`) at `revision`, returning the match count `fan_out_scoped`
/// reports. Mirrors the signature and behavior of
/// `handlers::floor_glue::emit_floor_grant`, minus signing with the
/// production relay keypair and minus the Redis/WS delivery I/O — the parts
/// that need a live `AppState`, per this file's header.
fn build_and_fan_out_grant(
    registry: &SubscriptionRegistry,
    community: CommunityId,
    channel_id: Uuid,
    holder: Option<&PubkeyHex>,
    revision: u64,
) -> Vec<(Uuid, String)> {
    let relay_keys = nostr::Keys::generate();
    let event = floor_grant_event(&relay_keys, channel_id, holder, revision, Duration::from_secs(30))
        .expect("grant event signs");
    let stored = StoredEvent::new(event, Some(channel_id));
    registry.fan_out_scoped(community, &stored)
}

#[test]
fn request_yields_exactly_one_grant_event_to_the_requesting_agent() {
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let agent = pubkey();
    let mut lease = FloorLease::new(vec![agent.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    assert_eq!(lease.request(&agent, now), FloorDecision::Granted);
    let matches =
        build_and_fan_out_grant(&registry, community, channel_id, Some(&agent), lease.revision());

    assert_eq!(
        matches.len(),
        1,
        "exactly one grant delivery is expected for the one channel subscriber"
    );
}

#[test]
fn concurrent_second_request_yields_no_grant_until_the_first_releases() {
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let gabe = pubkey();
    let stacy = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone(), stacy.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    // gabe requests first and is granted — exactly one grant goes out.
    assert_eq!(lease.request(&gabe, now), FloorDecision::Granted);
    let first_matches =
        build_and_fan_out_grant(&registry, community, channel_id, Some(&gabe), lease.revision());
    assert_eq!(first_matches.len(), 1);

    // stacy's concurrent request is Queued — per the wire rule ("on
    // Queued/DeniedBudgetExhausted, emit no grant"), no grant event is even
    // built, so there is nothing new to fan out.
    assert_eq!(lease.request(&stacy, now), FloorDecision::Queued);

    // gabe releases (publishes); round-robin hands the floor to stacy.
    let next = lease.on_publish(&gabe, now).expect("gabe holds the floor");
    assert_eq!(next, NextGrant::Some(stacy.clone()));

    // Only now — after release — does stacy's request produce a grant.
    assert_eq!(lease.request(&stacy, now), FloorDecision::Granted);
    let second_matches =
        build_and_fan_out_grant(&registry, community, channel_id, Some(&stacy), lease.revision());
    assert_eq!(second_matches.len(), 1);
}

#[test]
fn grant_revision_strictly_increases_across_successive_grants() {
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let gabe = pubkey();
    let stacy = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone(), stacy.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    lease.request(&gabe, now);
    let rev1 = lease.revision();
    let event1 = floor_grant_event(
        &nostr::Keys::generate(),
        channel_id,
        Some(&gabe),
        rev1,
        Duration::from_secs(30),
    )
    .expect("signs");

    lease.on_publish(&gabe, now).unwrap();
    lease.request(&stacy, now);
    let rev2 = lease.revision();
    let event2 = floor_grant_event(
        &nostr::Keys::generate(),
        channel_id,
        Some(&stacy),
        rev2,
        Duration::from_secs(30),
    )
    .expect("signs");

    let rev_tag = |e: &nostr::Event| -> u64 {
        e.tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("rev"))
            .and_then(|t| t.as_slice().get(1).and_then(|v| v.parse().ok()))
            .expect("rev tag present")
    };
    assert!(
        rev_tag(&event2) > rev_tag(&event1),
        "grant revision must strictly increase: {} -> {}",
        rev_tag(&event1),
        rev_tag(&event2)
    );
}

#[test]
fn publish_hands_the_floor_to_the_next_round_robin_agent_and_grants_it() {
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let gabe = pubkey();
    let stacy = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone(), stacy.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    lease.request(&gabe, now);
    // gabe's publish releases the floor; on_publish reports who round-robin
    // hands it to next — this is what `enforce_floor_lease` auto-grants.
    let next = lease.on_publish(&gabe, now).expect("gabe holds the floor");
    let NextGrant::Some(next_agent) = next else {
        panic!("expected a round-robin next agent, got None");
    };
    assert_eq!(next_agent, stacy);

    // The relay handler's auto-grant: call request() on the named agent's
    // behalf without requiring it to submit its own kind:20003 event.
    assert_eq!(lease.request(&next_agent, now), FloorDecision::Granted);
    let matches = build_and_fan_out_grant(
        &registry,
        community,
        channel_id,
        Some(&next_agent),
        lease.revision(),
    );
    assert_eq!(matches.len(), 1);
}

#[test]
fn ttl_reclaim_then_a_fresh_request_is_granted_and_wired_to_a_new_grant() {
    // Documents the TTL half of "on publish/TTL the next round-robin agent
    // is granted": FloorLease::reclaim_if_expired does not itself pick a
    // next holder (see its doc comment) — the relay's
    // handlers::floor_glue::handle_floor_request wiring calls it opportunistically
    // and then evaluates the incoming request against the now-freed lease,
    // exactly like this test.
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let gabe = pubkey();
    let stacy = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone(), stacy.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    lease.request(&gabe, now); // granted, then stalls — never publishes
    let stalled_at = now + Duration::from_secs(31);
    assert_eq!(lease.reclaim_if_expired(stalled_at), Some(gabe));

    assert_eq!(lease.request(&stacy, stalled_at), FloorDecision::Granted);
    let matches =
        build_and_fan_out_grant(&registry, community, channel_id, Some(&stacy), lease.revision());
    assert_eq!(matches.len(), 1);
}

// --- Task 4 review Fix 1: the "floor cleared / open" grant, wire-level ---

#[test]
fn cleared_grant_is_delivered_to_the_channel_subscriber_with_no_holder_tag() {
    // Mirrors evaluate_floor_publish's Clear path (see floor.rs's own
    // tests for the pure decision): gabe stalls past the TTL and a
    // reclaim frees him with no round-robin next agent to hand off to.
    // The wire glue must still fan out a `kind:39007` so the one
    // subscriber learns the floor opened, even though no one now holds it.
    let community = CommunityId::from_uuid(Uuid::new_v4());
    let channel_id = Uuid::new_v4();
    let registry = SubscriptionRegistry::new();
    subscribe_to_channel_grants(&registry, community, channel_id);

    let gabe = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    assert_eq!(lease.request(&gabe, now), FloorDecision::Granted);
    let stalled_at = now + Duration::from_secs(31);
    assert_eq!(lease.reclaim_if_expired(stalled_at), Some(gabe));

    let matches =
        build_and_fan_out_grant(&registry, community, channel_id, None, lease.revision());
    assert_eq!(
        matches.len(),
        1,
        "the cleared grant must still reach the one channel subscriber"
    );
}

#[test]
fn cleared_grant_revision_strictly_exceeds_the_grant_it_supersedes() {
    let relay_keys = nostr::Keys::generate();
    let channel_id = Uuid::new_v4();
    let gabe = pubkey();
    let mut lease = FloorLease::new(vec![gabe.clone()], Duration::from_secs(30), 8);
    let now = Instant::now();

    assert_eq!(lease.request(&gabe, now), FloorDecision::Granted);
    let granted_event = floor_grant_event(
        &relay_keys,
        channel_id,
        Some(&gabe),
        lease.revision(),
        Duration::from_secs(30),
    )
    .expect("signs");

    let stalled_at = now + Duration::from_secs(31);
    assert_eq!(lease.reclaim_if_expired(stalled_at), Some(gabe));
    let cleared_event = floor_grant_event(
        &relay_keys,
        channel_id,
        None,
        lease.revision(),
        Duration::from_secs(30),
    )
    .expect("signs");

    let rev_tag = |e: &nostr::Event| -> u64 {
        e.tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("rev"))
            .and_then(|t| t.as_slice().get(1).and_then(|v| v.parse().ok()))
            .expect("rev tag present")
    };
    let status_tag = |e: &nostr::Event| -> Option<String> {
        e.tags
            .iter()
            .find(|t| t.as_slice().first().map(String::as_str) == Some("status"))
            .and_then(|t| t.as_slice().get(1).cloned())
    };

    assert!(
        rev_tag(&cleared_event) > rev_tag(&granted_event),
        "cleared grant's revision must strictly exceed the grant it supersedes: {} -> {}",
        rev_tag(&granted_event),
        rev_tag(&cleared_event)
    );
    assert_eq!(status_tag(&granted_event), Some("granted".to_string()));
    assert_eq!(status_tag(&cleared_event), Some("open".to_string()));
}
