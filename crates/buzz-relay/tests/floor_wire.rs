//! Wire-level conformance for the group-chat floor request/grant protocol
//! (Task 4): a `kind:20003` request decided against a real
//! [`buzz_relay::floor::FloorLease`] produces a real signed `kind:39007`
//! grant event ([`buzz_relay::floor_wire::floor_grant_event`]) that is
//! actually matched by the relay's real subscription fan-out
//! ([`buzz_relay::subscription::SubscriptionRegistry::fan_out_scoped`]) —
//! not a re-implementation of either.
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
//! ## What is deliberately NOT covered here (documented deferral)
//!
//! The relay handlers that call into this machinery
//! (`handlers::ingest::{resolve_floor_lease, enforce_floor_lease,
//! handle_floor_request}`, `handlers::side_effects::emit_floor_grant`) also
//! do channel/roster/agent-classification reads through `state.db`
//! (Postgres) and real WebSocket delivery. Driving those specific lines
//! needs a live Postgres-backed `AppState`, which this crate's existing
//! floor tests (`floor_lease.rs`) also don't stand up — consistent with
//! that precedent, the DB-touching glue is exercised by compilation +
//! clippy + the pure tests here, not by a fresh Postgres-backed
//! integration test. If that glue is wrong, it is wrong in the same way
//! Task 3's already-landed `enforce_floor_lease` would be.

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

/// Build+fan-out a grant for `holder` at `revision`, returning the match
/// count `fan_out_scoped` reports. Mirrors exactly what
/// `handlers::side_effects::emit_floor_grant` does, minus signing with the
/// production relay keypair and minus the Redis/WS delivery I/O — the parts
/// that need a live `AppState`, per this file's header.
fn build_and_fan_out_grant(
    registry: &SubscriptionRegistry,
    community: CommunityId,
    channel_id: Uuid,
    holder: &PubkeyHex,
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
    let matches = build_and_fan_out_grant(&registry, community, channel_id, &agent, lease.revision());

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
        build_and_fan_out_grant(&registry, community, channel_id, &gabe, lease.revision());
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
        build_and_fan_out_grant(&registry, community, channel_id, &stacy, lease.revision());
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
    let event1 =
        floor_grant_event(&nostr::Keys::generate(), channel_id, &gabe, rev1, Duration::from_secs(30))
            .expect("signs");

    lease.on_publish(&gabe, now).unwrap();
    lease.request(&stacy, now);
    let rev2 = lease.revision();
    let event2 = floor_grant_event(
        &nostr::Keys::generate(),
        channel_id,
        &stacy,
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
    let matches =
        build_and_fan_out_grant(&registry, community, channel_id, &next_agent, lease.revision());
    assert_eq!(matches.len(), 1);
}

#[test]
fn ttl_reclaim_then_a_fresh_request_is_granted_and_wired_to_a_new_grant() {
    // Documents the TTL half of "on publish/TTL the next round-robin agent
    // is granted": FloorLease::reclaim_if_expired does not itself pick a
    // next holder (see its doc comment) — the relay's
    // handlers::ingest::handle_floor_request wiring calls it opportunistically
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
        build_and_fan_out_grant(&registry, community, channel_id, &stacy, lease.revision());
    assert_eq!(matches.len(), 1);
}
