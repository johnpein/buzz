//! Floor-lease state machine for native multi-agent group chat.
//!
//! Serializes which agent may reply in a channel: a round-robin order over
//! `agent_members`, a per-owner-turn agent budget, and a TTL on the held
//! floor so a stalled agent cannot lock the channel forever. Pure and
//! deterministic — every method that needs the current time takes `now:
//! Instant` explicitly, so there is no internal clock read and no I/O.
//! [`FloorLease`] itself performs no ingest wiring; a later task drives it
//! from the relay's message-ingest path.

use std::time::{Duration, Instant};

use buzz_core::channel::ChannelType;
use buzz_sdk::broker::PubkeyHex;
use thiserror::Error;

/// Default TTL on a held floor when the relay creates a channel's lease. A
/// stalled holder's floor is reclaimable after this window (see
/// [`FloorLease::reclaim_if_expired`]).
pub const DEFAULT_FLOOR_TTL: Duration = Duration::from_secs(30);

/// Default per-owner-turn agent budget when the relay creates a channel's
/// lease: how many agent replies may follow one owner message before the floor
/// closes until the owner speaks again.
pub const DEFAULT_FLOOR_BUDGET: u32 = 8;

/// Whether a channel's roster should have the group-chat floor lease
/// ([`FloorLease`]) enforced at all.
///
/// True iff at least two roster members are agents (their pubkey appears in
/// `agent_pubkeys`) AND the channel is not a plain 2-party DM. A roster with
/// exactly two entries is treated as a DM by construction — whether
/// owner+agent or agent+agent — so the two-party case is excluded outright
/// rather than merely implied by the agent count.
///
/// That two-party-is-a-DM rule is a documented assumption pending
/// verification against the real channel-type model, not a proven invariant
/// of this module. The ingest-wiring task (the next task in this sequence)
/// will gate floor enforcement on the real `ChannelType::Stream` explicitly,
/// rather than relying on this member-count heuristic alone.
///
/// Pure and caller-driven: resolving which members are agents (a NIP-OA
/// profile lookup, mirroring `buzz-acp`'s `check_sibling_via_profile`) is the
/// caller's job in the ingest-wiring task that drives this alongside
/// `FloorLease`. No I/O happens here.
#[must_use]
pub fn is_floor_enforced(
    members: &[buzz_db::channel_members::MemberRecord],
    agent_pubkeys: &[PubkeyHex],
) -> bool {
    if members.len() <= 2 {
        return false;
    }
    let agent_count = members
        .iter()
        .filter(|member| {
            let member_hex = hex::encode(&member.pubkey);
            agent_pubkeys
                .iter()
                .any(|agent| agent.as_str() == member_hex)
        })
        .count();
    agent_count >= 2
}

/// Pure parse-and-match for the floor gate's channel-type check: true only
/// for the [`ChannelType::Stream`] variant. Extracted from
/// `enforce_floor_lease` (`crates/buzz-relay/src/handlers/ingest.rs`) so the
/// DM-bypass parse has direct unit coverage instead of resting on inference
/// from the `FloorLease` state-machine tests. `raw` is a stored
/// `channel_type` value (e.g. `"stream"`, `"dm"`, `"forum"`).
#[must_use]
pub fn is_enforced_channel_type(raw: &str) -> bool {
    raw.parse::<ChannelType>().ok() == Some(ChannelType::Stream)
}

/// A channel roster member as classified for floor-gate authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberKind {
    /// `users.agent_owner_pubkey IS NOT NULL` for this pubkey.
    Agent,
    /// `users.agent_owner_pubkey IS NULL` for this pubkey — a definite,
    /// successfully looked-up human.
    Human,
}

/// The floor-gate agent-membership lookup could not determine whether a
/// roster member is human or an agent — a DB error or an unknown pubkey, per
/// [`classify_member`]'s doc comment. Carries no payload: the caller
/// (`enforce_floor_lease`) always turns this into a generic
/// `IngestError::Internal` and the DB error detail, when there is one, is
/// already logged/traced at the lookup site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("floor-gate agent classification is indeterminate")]
pub struct IndeterminateMember;

/// Fail-closed classification of a floor-gate roster lookup.
///
/// `lookup` is `Ok(is_agent)` when the caller's DB read of this pubkey's
/// `agent_owner_pubkey` succeeded and found a row; it is
/// `Err(IndeterminateMember)` for anything that didn't produce that
/// evidence — a DB error or an unknown pubkey both count, since neither
/// tells us the member is human.
///
/// This is deliberately the opposite of the ingest metrics-label lookup
/// (`author_type_label` in `handlers::ingest`, which is documented
/// "Metric-labeling only — never used for authorization" and collapses
/// `Ok(None) | Err(_)` to `false`/"human"). That collapse is a fail-open
/// path: for floor-gate authorization it would let a misclassified agent
/// get treated as the channel owner and reset the floor. `classify_member`
/// never maps `Err(IndeterminateMember)` to [`MemberKind::Human`] — the
/// caller (`enforce_floor_lease`) instead propagates it as an ingest error,
/// so an indeterminate lookup rejects/retries the publish rather than
/// silently admitting it.
pub fn classify_member(lookup: Result<bool, IndeterminateMember>) -> Result<MemberKind, IndeterminateMember> {
    match lookup {
        Ok(true) => Ok(MemberKind::Agent),
        Ok(false) => Ok(MemberKind::Human),
        Err(e) => Err(e),
    }
}

/// Outcome of an agent's request to speak.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorDecision {
    /// The requesting agent now holds the floor.
    Granted,
    /// Another agent already holds the floor; this request is queued behind it.
    Queued,
    /// The per-owner-turn agent budget is exhausted; only an owner message reopens it.
    DeniedBudgetExhausted,
}

/// Who round-robin hands the floor to next after a publish.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NextGrant {
    /// The next agent in rotation.
    Some(PubkeyHex),
    /// No further agent turn — the budget is now exhausted or membership is empty.
    None,
}

/// Errors raised by [`FloorLease::on_publish`].
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum FloorError {
    /// The publishing agent does not currently hold the floor.
    #[error("agent does not hold the floor")]
    NotHolder,
}

/// Pure round-robin + budget + TTL floor-lease state machine for a single
/// group-chat channel. See the module docs for the model; no method reads
/// the clock or performs I/O.
#[derive(Debug, Clone)]
pub struct FloorLease {
    agent_members: Vec<PubkeyHex>,
    ttl: Duration,
    budget: u32,
    next_index: usize,
    holder: Option<PubkeyHex>,
    granted_at: Option<Instant>,
    agent_turns: u32,
    revision: u64,
}

impl FloorLease {
    /// Build a lease over `agent_members` in round-robin order, with a TTL
    /// on each held floor and a per-owner-turn agent budget.
    #[must_use]
    pub fn new(agent_members: Vec<PubkeyHex>, ttl: Duration, budget: u32) -> Self {
        Self {
            agent_members,
            ttl,
            budget,
            next_index: 0,
            holder: None,
            granted_at: None,
            agent_turns: 0,
            revision: 0,
        }
    }

    /// Record an owner (human) message: clears any held floor and resets
    /// the agent-turn budget, reopening the floor for requests.
    pub fn on_owner_message(&mut self, _now: Instant) {
        self.holder = None;
        self.granted_at = None;
        self.agent_turns = 0;
    }

    /// Request the floor on behalf of `agent`.
    ///
    /// Denies once the agent-turn budget is exhausted (regardless of
    /// holder), grants immediately when the floor is free, re-grants an
    /// idempotent re-request from the current holder, and otherwise queues
    /// behind the current holder.
    ///
    /// Every *fresh* grant (the floor was free and is now held) bumps
    /// [`Self::revision`] — the counter the wire protocol's `kind:39007`
    /// grant event carries so subscribers can tell one grant apart from the
    /// next even if delivery reorders them. An idempotent re-request from
    /// the already-current holder returns `Granted` again without bumping
    /// the revision, since no new grant occurred.
    pub fn request(&mut self, agent: &PubkeyHex, now: Instant) -> FloorDecision {
        if self.agent_turns >= self.budget {
            return FloorDecision::DeniedBudgetExhausted;
        }
        match &self.holder {
            Some(holder) if holder == agent => FloorDecision::Granted,
            Some(_) => FloorDecision::Queued,
            None => {
                self.holder = Some(agent.clone());
                self.granted_at = Some(now);
                self.revision += 1;
                FloorDecision::Granted
            }
        }
    }

    /// The number of fresh grants this lease has ever issued (see
    /// [`Self::request`]). Starts at 0 (no grant yet) and only ever
    /// increases, so it is safe to carry on the wire as a strictly
    /// increasing `rev` tag.
    #[must_use]
    pub fn revision(&self) -> u64 {
        self.revision
    }

    /// Record a publish by the current holder: validates holdership,
    /// increments the agent-turn counter, releases the floor, advances
    /// round-robin past `agent`, and returns the next agent to be granted
    /// the floor (or [`NextGrant::None`] if the budget is now exhausted or
    /// membership is empty).
    ///
    /// # Errors
    ///
    /// Returns [`FloorError::NotHolder`] if `agent` does not currently hold
    /// the floor.
    pub fn on_publish(
        &mut self,
        agent: &PubkeyHex,
        _now: Instant,
    ) -> Result<NextGrant, FloorError> {
        match &self.holder {
            Some(holder) if holder == agent => {}
            _ => return Err(FloorError::NotHolder),
        }

        self.agent_turns += 1;
        self.holder = None;
        self.granted_at = None;

        if let Some(pos) = self.agent_members.iter().position(|member| member == agent) {
            self.next_index = (pos + 1) % self.agent_members.len();
        }

        if self.agent_turns >= self.budget {
            return Ok(NextGrant::None);
        }

        Ok(self
            .agent_members
            .get(self.next_index)
            .cloned()
            .map(NextGrant::Some)
            .unwrap_or(NextGrant::None))
    }

    /// If the held floor has outlived its TTL as of `now`, reclaim it and
    /// return the stalled holder's key. Does not auto-grant the next
    /// agent — callers re-[`request`](Self::request) to do that.
    pub fn reclaim_if_expired(&mut self, now: Instant) -> Option<PubkeyHex> {
        let granted_at = self.granted_at?;
        if now.duration_since(granted_at) < self.ttl {
            return None;
        }
        self.granted_at = None;
        self.holder.take()
    }

    /// The agent currently holding the floor, if any.
    #[must_use]
    pub fn current_holder(&self) -> Option<&PubkeyHex> {
        self.holder.as_ref()
    }
}

/// Outcome of consulting the floor for a kind:9 (stream message) at ingest.
///
/// Returned by [`evaluate_floor_at_ingest`]; the ingest wiring maps
/// [`Rejected`](Self::Rejected) onto the relay's existing publish-rejection
/// path and treats every other variant as "store the event".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestFloorAction {
    /// The channel is not floor-enforced (not a multi-agent stream). Ingest
    /// proceeds exactly as it would without the floor — the lease is untouched.
    Bypass,
    /// A non-agent (owner/human) message: the floor was opened and the agent
    /// budget reset. Accept.
    Opened,
    /// The publishing agent held the floor; its turn was recorded and the floor
    /// released. Accept. Carries the next agent round-robin would grant (unused
    /// at ingest today — the grant path is driven out of band).
    Published(NextGrant),
    /// The publishing agent did not hold the floor. Reject via the relay's
    /// existing publish-rejection surface.
    Rejected(FloorError),
}

/// Decide how a kind:9 publish should be handled against the channel's floor.
///
/// This is the whole floor decision the relay's ingest path runs once it has
/// resolved the real channel type, the channel roster, and which roster members
/// are agents (`agent_pubkeys`, resolved caller-side from
/// `users.agent_owner_pubkey`, the same signal the NIP-OA sibling gate uses).
/// It is pure and deterministic — all clock access is the caller-supplied
/// `now` — so the ingest wiring stays thin glue over this function.
///
/// The authoritative enforcement gate is the channel type: only a
/// [`ChannelType::Stream`] that is also [`is_floor_enforced`] is gated; every
/// other channel (DMs, forums, single-agent streams) returns
/// [`IngestFloorAction::Bypass`] without touching `lease`. Within an enforced
/// stream, a non-agent author's message opens the floor
/// ([`FloorLease::on_owner_message`]) and an agent author must hold the floor
/// ([`FloorLease::on_publish`]) or be rejected. `reclaim_if_expired` is applied
/// opportunistically first so a stalled holder never wedges the channel.
///
/// An agent author that is not part of the lease's rotation surfaces as
/// [`FloorError::NotHolder`] from `on_publish` (it can never be the holder), so
/// no distinct unknown-agent error is needed here.
#[must_use]
pub fn evaluate_floor_at_ingest(
    channel_type: ChannelType,
    members: &[buzz_db::channel_members::MemberRecord],
    agent_pubkeys: &[PubkeyHex],
    author: &PubkeyHex,
    lease: &mut FloorLease,
    now: Instant,
) -> IngestFloorAction {
    // Authoritative gate (design requirement 1): only multi-agent streams are
    // floor-enforced. `is_floor_enforced`'s member-count rule is the secondary
    // guard behind this channel-type check.
    if channel_type != ChannelType::Stream || !is_floor_enforced(members, agent_pubkeys) {
        return IngestFloorAction::Bypass;
    }

    // Opportunistic reclaim: a held-but-expired floor is released before this
    // publish is judged, so a stalled holder cannot lock the channel forever.
    lease.reclaim_if_expired(now);

    let author_is_agent = agent_pubkeys.iter().any(|agent| agent == author);
    if !author_is_agent {
        // A non-agent (the human owner) speaking reopens the floor for agents.
        lease.on_owner_message(now);
        return IngestFloorAction::Opened;
    }

    match lease.on_publish(author, now) {
        Ok(next) => IngestFloorAction::Published(next),
        Err(error) => IngestFloorAction::Rejected(error),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;
    use std::time::{Duration, Instant};

    use super::*;

    // Each helper generates a real secp256k1 key once per test process and
    // caches it, so repeated calls (e.g. once to build `agent_members`, again
    // to `request`) compare equal instead of minting a fresh random pubkey
    // per call.
    fn gabe() -> PubkeyHex {
        static KEY: OnceLock<PubkeyHex> = OnceLock::new();
        KEY.get_or_init(|| {
            PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex())
                .expect("generated key is a valid pubkey")
        })
        .clone()
    }

    fn stacy() -> PubkeyHex {
        static KEY: OnceLock<PubkeyHex> = OnceLock::new();
        KEY.get_or_init(|| {
            PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex())
                .expect("generated key is a valid pubkey")
        })
        .clone()
    }

    // Not exercised by the current fixed set of assertions below (owner
    // messages take no pubkey) — kept because the task's interface calls for
    // it as a symmetric fixture alongside gabe()/stacy().
    #[allow(dead_code)]
    fn owner() -> PubkeyHex {
        static KEY: OnceLock<PubkeyHex> = OnceLock::new();
        KEY.get_or_init(|| {
            PubkeyHex::parse(nostr::Keys::generate().public_key().to_hex())
                .expect("generated key is a valid pubkey")
        })
        .clone()
    }

    fn t0() -> Instant {
        Instant::now()
    }

    fn t1() -> Instant {
        t0() + Duration::from_secs(1)
    }

    #[test]
    fn owner_message_opens_floor_and_resets_budget() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 4);
        f.on_owner_message(t0());

        // Exhaust the budget through real request + on_publish cycles, the
        // same way budget_exhaustion_denies_agents_until_owner_speaks does.
        let agents = [gabe(), stacy(), gabe(), stacy()];
        for agent in &agents {
            assert!(matches!(f.request(agent, t0()), FloorDecision::Granted));
            f.on_publish(agent, t0()).unwrap();
        }
        assert!(matches!(
            f.request(&gabe(), t0()),
            FloorDecision::DeniedBudgetExhausted
        ));

        f.on_owner_message(t1());
        assert!(matches!(f.request(&gabe(), t1()), FloorDecision::Granted));
    }

    #[test]
    fn only_one_holder_at_a_time_round_robin() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        f.on_owner_message(t0());
        assert!(matches!(f.request(&gabe(), t0()), FloorDecision::Granted));
        assert!(matches!(f.request(&stacy(), t0()), FloorDecision::Queued));
        let next = f.on_publish(&gabe(), t0()).unwrap();
        assert_eq!(next, NextGrant::Some(stacy())); // round-robin hands off
    }

    #[test]
    fn budget_exhaustion_denies_agents_until_owner_speaks() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 2);
        f.on_owner_message(t0());
        f.request(&gabe(), t0());
        f.on_publish(&gabe(), t0()).unwrap(); // agent turn 1
        f.request(&stacy(), t0());
        f.on_publish(&stacy(), t0()).unwrap(); // agent turn 2
        assert!(matches!(
            f.request(&gabe(), t0()),
            FloorDecision::DeniedBudgetExhausted
        ));
        f.on_owner_message(t1());
        assert!(matches!(f.request(&gabe(), t1()), FloorDecision::Granted));
    }

    #[test]
    fn ttl_reclaim_hands_floor_to_next_when_holder_stalls() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        f.on_owner_message(t0());
        f.request(&gabe(), t0()); // granted, never publishes
        assert_eq!(
            f.reclaim_if_expired(t0() + Duration::from_secs(31)),
            Some(gabe())
        );
        assert!(matches!(
            f.request(&stacy(), t0() + Duration::from_secs(31)),
            FloorDecision::Granted
        ));
    }

    #[test]
    fn publish_from_non_holder_is_rejected() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        f.on_owner_message(t0());
        f.request(&gabe(), t0());
        assert!(matches!(
            f.on_publish(&stacy(), t0()),
            Err(FloorError::NotHolder)
        ));
    }

    // --- is_enforced_channel_type: proves the DM-bypass parse directly,
    // rather than by inference from the FloorLease tests above. ---

    #[test]
    fn stream_channel_type_is_enforced() {
        assert!(is_enforced_channel_type("stream"));
    }

    #[test]
    fn dm_channel_type_is_not_enforced() {
        assert!(!is_enforced_channel_type("dm"));
    }

    #[test]
    fn forum_channel_type_is_not_enforced() {
        assert!(!is_enforced_channel_type("forum"));
    }

    #[test]
    fn unknown_and_garbage_channel_types_are_not_enforced() {
        assert!(!is_enforced_channel_type("not-a-real-channel-type"));
        assert!(!is_enforced_channel_type(""));
    }

    // --- revision: Task 4 wire-protocol precondition ---------------------
    //
    // The relay's kind:39007 grant event carries `FloorLease::revision()` as
    // its `rev` tag so a subscriber can order grants even under redelivery.
    // These are the pure decision-level tests for that counter; the actual
    // signed-event shape is covered in `crates/buzz-relay/src/floor_wire.rs`
    // and the wire-level fan-out assertions live in
    // `crates/buzz-relay/tests/floor_wire.rs` (see that file's header for why
    // they replace the `buzz-conformance` crate named in the task brief).

    #[test]
    fn revision_starts_at_zero_and_bumps_on_first_grant() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        assert_eq!(f.revision(), 0);
        assert!(matches!(f.request(&gabe(), t0()), FloorDecision::Granted));
        assert_eq!(f.revision(), 1);
    }

    #[test]
    fn revision_does_not_bump_on_idempotent_re_request() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        f.request(&gabe(), t0());
        assert_eq!(f.revision(), 1);
        // Same holder asking again is idempotent — still Granted, no new revision.
        assert!(matches!(f.request(&gabe(), t0()), FloorDecision::Granted));
        assert_eq!(f.revision(), 1);
    }

    #[test]
    fn revision_does_not_bump_while_queued_or_budget_denied() {
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 1);
        f.request(&gabe(), t0());
        assert_eq!(f.revision(), 1);
        // stacy is queued behind gabe — no grant, no revision bump.
        assert!(matches!(f.request(&stacy(), t0()), FloorDecision::Queued));
        assert_eq!(f.revision(), 1);
        f.on_publish(&gabe(), t0()).unwrap(); // exhausts the budget of 1
        assert!(matches!(
            f.request(&stacy(), t0()),
            FloorDecision::DeniedBudgetExhausted
        ));
        assert_eq!(f.revision(), 1);
    }

    #[test]
    fn revision_strictly_increases_across_round_robin_grants() {
        // Models the wire flow: gabe is granted (rev 1), publishes, the
        // relay auto-requests the round-robin next agent (stacy) on his
        // behalf (rev 2) — see `handlers::ingest::enforce_floor_lease`.
        let mut f = FloorLease::new(vec![gabe(), stacy()], Duration::from_secs(30), 8);
        assert_eq!(f.request(&gabe(), t0()), FloorDecision::Granted);
        let rev1 = f.revision();
        let next = f.on_publish(&gabe(), t0()).unwrap();
        assert_eq!(next, NextGrant::Some(stacy()));
        assert_eq!(f.request(&stacy(), t0()), FloorDecision::Granted);
        let rev2 = f.revision();
        assert!(rev2 > rev1, "revision must strictly increase: {rev1} -> {rev2}");
    }

    // --- classify_member: proves the fail-closed mapping directly. ---

    #[test]
    fn classify_member_maps_known_agent() {
        assert_eq!(classify_member(Ok(true)), Ok(MemberKind::Agent));
    }

    #[test]
    fn classify_member_maps_known_human() {
        assert_eq!(classify_member(Ok(false)), Ok(MemberKind::Human));
    }

    #[test]
    fn classify_member_fails_closed_on_indeterminate_lookup() {
        // Neither a DB error nor an unknown pubkey is evidence of humanness,
        // so both must stay Err — never silently become MemberKind::Human.
        assert_eq!(
            classify_member(Err(IndeterminateMember)),
            Err(IndeterminateMember)
        );
    }
}
