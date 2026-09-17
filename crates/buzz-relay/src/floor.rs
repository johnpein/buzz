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

use buzz_sdk::broker::PubkeyHex;
use thiserror::Error;

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
                FloorDecision::Granted
            }
        }
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
}
