//! Multi-agent channel detection for the group-chat floor lease (Task 2).
//!
//! [`buzz_relay::floor::is_floor_enforced`] decides whether a channel's
//! roster should have the floor lease ([`buzz_relay::floor::FloorLease`])
//! enforced at all: only channels with two or more agent members, never an
//! ordinary owner+single-agent DM. The agent-identity set is caller-resolved
//! (NIP-OA profile lookups happen in the ingest-wiring task, not here) so
//! this stays a pure roster-shape check.

use chrono::Utc;
use uuid::Uuid;

use buzz_db::channel_members::{MemberRecord, MemberRole};
use buzz_relay::floor::is_floor_enforced;
use buzz_sdk::broker::PubkeyHex;

fn pubkey() -> PubkeyHex {
    PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex())
        .expect("generated key is a valid pubkey")
}

fn owner() -> PubkeyHex {
    static KEY: std::sync::OnceLock<PubkeyHex> = std::sync::OnceLock::new();
    KEY.get_or_init(pubkey).clone()
}

fn gabe() -> PubkeyHex {
    static KEY: std::sync::OnceLock<PubkeyHex> = std::sync::OnceLock::new();
    KEY.get_or_init(pubkey).clone()
}

fn stacy() -> PubkeyHex {
    static KEY: std::sync::OnceLock<PubkeyHex> = std::sync::OnceLock::new();
    KEY.get_or_init(pubkey).clone()
}

fn bob() -> PubkeyHex {
    static KEY: std::sync::OnceLock<PubkeyHex> = std::sync::OnceLock::new();
    KEY.get_or_init(pubkey).clone()
}

fn ann() -> PubkeyHex {
    static KEY: std::sync::OnceLock<PubkeyHex> = std::sync::OnceLock::new();
    KEY.get_or_init(pubkey).clone()
}

/// Build a `Vec<MemberRecord>` from `(pubkey, role)` pairs, faithful to the
/// real `channel_members` row shape (`pubkey` as compressed key bytes,
/// `role` as its canonical lowercase string).
fn roster(members: &[(PubkeyHex, MemberRole)]) -> Vec<MemberRecord> {
    members
        .iter()
        .map(|(pubkey, role)| MemberRecord {
            channel_id: Uuid::nil(),
            pubkey: hex::decode(pubkey.as_str()).expect("test pubkey is valid hex"),
            role: role.as_str().to_string(),
            joined_at: Utc::now(),
            invited_by: None,
            removed_at: None,
        })
        .collect()
}

#[test]
fn floor_enforced_only_with_two_or_more_agents() {
    use MemberRole::{Member, Owner};

    // Owner + 2 agents: floor lease applies.
    assert!(is_floor_enforced(
        &roster(&[(owner(), Owner), (gabe(), Member), (stacy(), Member)]),
        &[gabe(), stacy()],
    ));

    // Owner + 1 agent is a plain 2-party DM: never enforced.
    assert!(!is_floor_enforced(
        &roster(&[(owner(), Owner), (gabe(), Member)]),
        &[gabe()],
    ));

    // Owner + 2 humans, no agents at all: never enforced.
    assert!(!is_floor_enforced(
        &roster(&[(owner(), Owner), (bob(), Member), (ann(), Member)]),
        &[],
    ));
}

#[test]
fn floor_enforced_false_for_two_agent_roster_with_no_owner() {
    use MemberRole::Member;

    // 2 members, both agents, no owner: still a 2-party roster, so it falls
    // out of the same `len() <= 2` short-circuit as an owner+agent DM.
    assert!(!is_floor_enforced(
        &roster(&[(gabe(), Member), (stacy(), Member)]),
        &[gabe(), stacy()],
    ));
}

// --- Task 3: floor enforcement at the ingest seam --------------------------
//
// [`buzz_relay::floor::evaluate_floor_at_ingest`] is the pure decision the
// relay's kind:9 ingest path runs after it has resolved the real channel type,
// the channel roster, and which roster members are agents. Driving it here with
// a realistic owner+gabe+stacy `Stream` roster exercises the exact branch the
// ingest wiring calls (gate on `ChannelType::Stream` + `is_floor_enforced`,
// classify owner-vs-agent author, consult the per-channel `FloorLease`) without
// standing up a Postgres-backed relay. The DB reads the ingest wiring performs
// (`get_channel`, `get_members`, `get_agent_channel_policy`) are plain plumbing
// over that decision, wired in `enforce_floor_lease` in the ingest handler.

use std::time::{Duration, Instant};

use buzz_core::channel::ChannelType;
use buzz_relay::floor::{evaluate_floor_at_ingest, FloorDecision, FloorLease, IngestFloorAction};

#[test]
fn floor_enforced_at_ingest_gates_agent_kind9_publishes() {
    use MemberRole::{Member, Owner};

    let members = roster(&[(owner(), Owner), (gabe(), Member), (stacy(), Member)]);
    let agents = [gabe(), stacy()];
    let mut lease = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
    let now = Instant::now();

    // 1. gabe (an agent) publishes kind:9 without holding the floor → rejected.
    assert!(
        matches!(
            evaluate_floor_at_ingest(
                ChannelType::Stream,
                &members,
                &agents,
                &gabe(),
                &mut lease,
                now
            ),
            IngestFloorAction::Rejected(_)
        ),
        "agent publish with no held floor must be rejected",
    );

    // 2. The owner (a non-agent) publishes → accepted, and the floor opens.
    assert_eq!(
        evaluate_floor_at_ingest(ChannelType::Stream, &members, &agents, &owner(), &mut lease, now),
        IngestFloorAction::Opened,
        "owner message must open the floor and be accepted",
    );

    // 3. gabe requests the floor (the grant path is driven out of band, not at
    //    ingest) and is granted, then publishes → accepted.
    assert_eq!(lease.request(&gabe(), now), FloorDecision::Granted);
    assert!(
        matches!(
            evaluate_floor_at_ingest(
                ChannelType::Stream,
                &members,
                &agents,
                &gabe(),
                &mut lease,
                now
            ),
            IngestFloorAction::Published(_)
        ),
        "the floor holder's publish must be accepted",
    );

    // 4. stacy publishes at the same instant without ever being granted → rejected.
    assert!(
        matches!(
            evaluate_floor_at_ingest(
                ChannelType::Stream,
                &members,
                &agents,
                &stacy(),
                &mut lease,
                now
            ),
            IngestFloorAction::Rejected(_)
        ),
        "a non-holder agent publish must be rejected even right after the holder released",
    );
}

#[test]
fn dm_and_non_enforced_channels_bypass_the_floor_untouched() {
    use MemberRole::{Member, Owner};

    let now = Instant::now();
    let mut lease = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);

    // A real DM (owner + single agent) bypasses regardless of the roster: the
    // authoritative gate is the channel type, not the member-count heuristic.
    let dm = roster(&[(owner(), Owner), (gabe(), Member)]);
    assert_eq!(
        evaluate_floor_at_ingest(ChannelType::Dm, &dm, &[gabe()], &gabe(), &mut lease, now),
        IngestFloorAction::Bypass,
        "a DM ingest path must be byte-unaffected by the floor",
    );

    // Even a multi-agent roster in a Dm-typed channel bypasses outright.
    let multi = roster(&[(owner(), Owner), (gabe(), Member), (stacy(), Member)]);
    assert_eq!(
        evaluate_floor_at_ingest(
            ChannelType::Dm,
            &multi,
            &[gabe(), stacy()],
            &gabe(),
            &mut lease,
            now
        ),
        IngestFloorAction::Bypass,
        "channel type Dm is the authoritative exclusion",
    );

    // A Stream channel that is not floor-enforced (a single agent) also bypasses.
    assert_eq!(
        evaluate_floor_at_ingest(ChannelType::Stream, &dm, &[gabe()], &gabe(), &mut lease, now),
        IngestFloorAction::Bypass,
        "a non-enforced stream bypasses the floor",
    );

    // Proof the bypass never touched the lease: no holder was set and no owner
    // message was recorded, so agents still cannot publish through it.
    assert!(
        lease.current_holder().is_none(),
        "bypass paths must not mutate the channel's floor lease",
    );
}
