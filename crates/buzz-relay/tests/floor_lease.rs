//! Multi-agent channel detection for the group-chat floor lease (Task 2).
//!
//! [`buzz_relay::handlers::ingest::is_floor_enforced`] decides whether a
//! channel's roster should have the floor lease (Task 1's
//! [`buzz_relay::floor::FloorLease`]) enforced at all: only channels with two
//! or more agent members, never an ordinary owner+single-agent DM. The
//! agent-identity set is caller-resolved (NIP-OA profile lookups happen in
//! the ingest-wiring task, not here) so this stays a pure roster-shape check.

use chrono::Utc;
use uuid::Uuid;

use buzz_db::channel_members::{MemberRecord, MemberRole};
use buzz_relay::handlers::ingest::is_floor_enforced;
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
