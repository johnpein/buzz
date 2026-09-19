//! Floor-lease handler glue for the group-chat floor request/grant protocol
//! (`kind:20003` / `kind:39007`).
//!
//! Extracted from `handlers::ingest` and `handlers::side_effects` (Task 4
//! review, Fix 3): both of those files already sit ~4x over the project's
//! 1,500-line god-file limit, and Task 4 had added new floor-only glue to
//! both. [`crate::floor`] owns the pure decision state machine (`FloorLease`,
//! `evaluate_floor_at_ingest`, `evaluate_floor_publish`) and
//! [`crate::floor_wire`] owns the signed-event shape; this module is the I/O
//! glue between those and the relay's Postgres/pubsub/subscription state —
//! resolving a channel's floor context, driving `kind:20003` requests, and
//! fanning out `kind:39007` grants (including the "floor cleared" variant,
//! see [`emit_floor_grant`]).
//!
//! The kind:9 publish-time enforcement branch
//! (`handlers::ingest::enforce_floor_lease`) stays inline in `ingest.rs`,
//! at the same seam as the membership-revision CAS check it runs alongside
//! — only the reusable glue below moved here. It calls into
//! [`resolve_floor_lease`] and [`emit_floor_grant`] exactly as it did when
//! they were local functions.

use std::sync::Arc;
use std::time::Duration;

use tracing::warn;
use uuid::Uuid;

use buzz_core::tenant::TenantContext;
use buzz_core::CommunityId;
use buzz_core::StoredEvent;
use buzz_pubsub::EventTopic;
use buzz_sdk::broker::PubkeyHex;

use crate::state::AppState;

use super::ingest::IngestError;

/// Fail-closed agent-membership lookup for the floor gate
/// (`handlers::ingest::enforce_floor_lease`). Unlike `author_type_label`
/// (metric-labeling only, deliberately fail-open: `Ok(None) | Err(_) =>
/// false`/"human"), this feeds a security-relevant authorization decision,
/// so a DB error and an unknown pubkey both collapse to
/// `Err(IndeterminateMember)` ("cannot determine") instead of `Ok(false)`
/// ("human"). Bypasses `author_type_cache`, which is populated under the
/// fail-open policy and would otherwise re-surface a previously-coerced
/// "human" for an errored/unknown lookup. See [`crate::floor::classify_member`]
/// for how the caller turns this into a [`crate::floor::MemberKind`].
async fn floor_gate_agent_lookup(
    state: &Arc<AppState>,
    community: CommunityId,
    pubkey_bytes: &[u8],
) -> Result<bool, crate::floor::IndeterminateMember> {
    match state.db.get_agent_channel_policy(community, pubkey_bytes).await {
        Ok(Some((_, owner))) => Ok(owner.is_some()),
        Ok(None) => Err(crate::floor::IndeterminateMember),
        Err(e) => {
            tracing::warn!(
                error = %e,
                "floor gate agent-membership lookup failed; failing closed"
            );
            Err(crate::floor::IndeterminateMember)
        }
    }
}

/// Shared context resolved once for a floor-enforced channel: its roster,
/// the subset classified as agents, and the channel's cached
/// [`crate::floor::FloorLease`]. Consumed by both the kind:9 publish gate
/// (`handlers::ingest::enforce_floor_lease`) and the kind:20003
/// floor-request handler ([`handle_floor_request`]) so the
/// roster/agent-classification plumbing has exactly one implementation.
pub(crate) struct FloorContext {
    pub(crate) members: Vec<buzz_db::channel_members::MemberRecord>,
    pub(crate) agent_pubkeys: Vec<buzz_sdk::broker::PubkeyHex>,
    pub(crate) lease: Arc<std::sync::Mutex<crate::floor::FloorLease>>,
}

/// Resolve the floor context for `channel_id`, or `None` if the channel is
/// not floor-enforced.
///
/// Bypass (returns `Ok(None)`) covers exactly the two conditions
/// [`crate::floor::evaluate_floor_at_ingest`] itself bypasses on: a
/// non-`Stream` channel type, or a roster with fewer than two agent members
/// ([`crate::floor::is_floor_enforced`]) — so DMs and single-agent streams
/// never even reach the lease cache. Agent classification is fail-closed:
/// an indeterminate lookup (DB error or unknown pubkey) for any member
/// aborts with [`IngestError::Internal`] rather than silently treating that
/// member as human (see [`floor_gate_agent_lookup`] and
/// [`crate::floor::classify_member`]).
pub(crate) async fn resolve_floor_lease(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    channel_id: Uuid,
    channel_row: Option<&buzz_db::channel::ChannelRecord>,
) -> Result<Option<FloorContext>, IngestError> {
    use buzz_sdk::broker::PubkeyHex;

    // Authoritative enforcement gate (design requirement 1): only stream
    // channels are floor-enforced. DMs/forums bypass before any roster load.
    let is_stream = channel_row
        .map(|row| crate::floor::is_enforced_channel_type(&row.channel_type))
        .unwrap_or(false);
    if !is_stream {
        return Ok(None);
    }

    let members = state
        .db
        .get_members(tenant.community(), channel_id)
        .await
        .map_err(|e| IngestError::Internal(format!("error: floor roster load: {e}")))?;

    // Resolve which roster members are agents. Fail-closed: an indeterminate
    // classification for any member aborts via IngestError rather than
    // silently treating that member as human (see floor_gate_agent_lookup
    // and crate::floor::classify_member).
    let mut agent_pubkeys = Vec::new();
    for member in &members {
        let lookup = floor_gate_agent_lookup(state, tenant.community(), &member.pubkey).await;
        match crate::floor::classify_member(lookup) {
            Ok(crate::floor::MemberKind::Agent) => {
                if let Ok(hex) = PubkeyHex::parse(hex::encode(&member.pubkey)) {
                    agent_pubkeys.push(hex);
                }
            }
            Ok(crate::floor::MemberKind::Human) => {}
            Err(crate::floor::IndeterminateMember) => {
                return Err(IngestError::Internal(format!(
                    "error: floor agent classification indeterminate for a member of channel {channel_id}"
                )));
            }
        }
    }

    if !crate::floor::is_floor_enforced(&members, &agent_pubkeys) {
        return Ok(None);
    }

    // Get-or-create this channel's lease over the current agent set. On an
    // existing entry the init closure is not run, so a lease created earlier is
    // reused (its rotation may lag a since-changed roster — see report concern).
    let lease = state
        .floor_leases
        .get_with((tenant.community(), channel_id), || {
            Arc::new(std::sync::Mutex::new(crate::floor::FloorLease::new(
                agent_pubkeys.clone(),
                crate::floor::DEFAULT_FLOOR_TTL,
                crate::floor::DEFAULT_FLOOR_BUDGET,
            )))
        });

    Ok(Some(FloorContext {
        members,
        agent_pubkeys,
        lease,
    }))
}

/// Handle a `kind:20003` floor-request event (see `crate::floor_wire`).
///
/// Thin I/O wiring over [`resolve_floor_lease`] and
/// [`crate::floor::FloorLease::request`]: resolve the channel's floor
/// context, opportunistically reclaim an expired holder
/// (`FloorLease::reclaim_if_expired`, same "reclaim before deciding"
/// discipline as `evaluate_floor_at_ingest`), then request the floor on the
/// requester's behalf. A `Granted` decision fans out a `kind:39007` grant
/// ([`emit_floor_grant`]); `DeniedBudgetExhausted` fans out an explicit
/// `kind:39007` "closed" signal ([`emit_floor_closed`], Follow-up (a)) so the
/// requester's floor client stops waiting at once rather than burning its
/// acquire timeout; only `Queued` still emits nothing (the requester waits
/// for the current holder's turn to end).
///
/// Returns `Ok(())` in every case except a resolution failure: a
/// non-floor-enforced channel, a non-agent requester, or an unparseable
/// requester pubkey are all no-ops rather than rejections, since the
/// request is an ephemeral, best-effort event with no durable state to
/// protect. Mirrors `handle_ephemeral_event`'s `Result<(), String>`
/// convention so the WS command loop can send one uniform `OK`.
pub(crate) async fn handle_floor_request(
    state: &Arc<AppState>,
    tenant: &TenantContext,
    channel_id: Uuid,
    requester: &nostr::PublicKey,
) -> Result<(), String> {
    use buzz_sdk::broker::PubkeyHex;

    let channel_row = state.db.get_channel(tenant.community(), channel_id).await.ok();
    let ctx = match resolve_floor_lease(state, tenant, channel_id, channel_row.as_ref()).await {
        Ok(Some(ctx)) => ctx,
        Ok(None) => return Ok(()),
        Err(IngestError::Rejected(m) | IngestError::AuthFailed(m) | IngestError::Internal(m)) => {
            return Err(m);
        }
    };

    let Ok(requester_hex) = PubkeyHex::parse(requester.to_hex()) else {
        tracing::warn!(
            channel_id = %channel_id,
            "floor request ignored: requester pubkey failed hex parse"
        );
        return Ok(());
    };

    if !crate::floor::is_floor_participant(&ctx.agent_pubkeys, &requester_hex) {
        // Only agents participate in the floor protocol; a non-agent
        // requester is ignored rather than rejected (ephemeral, best-effort).
        return Ok(());
    }

    let now = std::time::Instant::now();
    let (decision, revision) = {
        let mut guard = ctx.lease.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Opportunistic reclaim: a held-but-expired floor is released before
        // this request is judged, same discipline as evaluate_floor_at_ingest.
        guard.reclaim_if_expired(now);
        let decision = guard.request(&requester_hex, now);
        (decision, guard.revision())
    };

    match decision {
        crate::floor::FloorDecision::Granted => {
            emit_floor_grant(
                tenant,
                state,
                channel_id,
                Some(&requester_hex),
                revision,
                crate::floor::DEFAULT_FLOOR_TTL,
            );
        }
        crate::floor::FloorDecision::DeniedBudgetExhausted => {
            // Explicit "closed" so the requester's floor client stops waiting
            // immediately instead of burning its acquire timeout (Follow-up (a)).
            emit_floor_closed(
                tenant,
                state,
                channel_id,
                revision,
                crate::floor::DEFAULT_FLOOR_TTL,
            );
        }
        // Queued: the requester waits for the current holder's turn to end;
        // it will be granted (or closed) by the holder's publish, so no
        // separate signal is emitted here.
        crate::floor::FloorDecision::Queued => {}
    }

    Ok(())
}

/// Sign and fan out a fresh relay-signed `kind:39007` floor-grant overlay
/// for `channel_id`, after a `kind:20003` request is granted, a holder's
/// publish hands the floor to the next agent in round-robin, or a TTL
/// reclaim frees a stalled holder with no round-robin next agent to hand
/// off to (see `handlers::ingest::enforce_floor_lease` and
/// [`handle_floor_request`]).
///
/// `holder` is `Some(pubkey)` for a normal grant, or `None` for the "floor
/// cleared / open" variant (Task 4 review Fix 1) — see
/// [`crate::floor_wire::floor_grant_event`] for the resulting tag shape.
///
/// Fan-out only — never stored, the same "39xxx but never persisted"
/// convention as `emit_live_thread_summary` (`KIND_THREAD_SUMMARY`). A
/// client that was not subscribed at delivery time learns the current
/// holder from its own next `FloorDecision` response rather than a durable
/// replay of this event — a deliberate scope deferral, see the Task 4
/// report.
///
/// Spawned so this never adds latency to the triggering request/publish's
/// own accept path, matching `dispatch_persistent_event`/
/// `emit_live_thread_summary`.
pub fn emit_floor_grant(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    channel_id: Uuid,
    holder: Option<&PubkeyHex>,
    revision: u64,
    ttl: Duration,
) {
    let holder = holder.cloned();
    spawn_emit_floor_event(tenant, state, channel_id, "grant", move |keys| {
        crate::floor_wire::floor_grant_event(keys, channel_id, holder.as_ref(), revision, ttl)
    });
}

/// Sign and fan out a relay-signed `kind:39007` "floor closed" overlay for
/// `channel_id` — the explicit budget-exhausted signal (see
/// [`crate::floor_wire::floor_closed_event`] and
/// [`crate::floor::GrantBroadcast::Closed`]) emitted when a `kind:20003`
/// request is denied for budget ([`handle_floor_request`]) or a publish
/// consumes the last budgeted turn (`handlers::ingest::enforce_floor_lease`).
/// A waiting agent's floor client resolves it immediately instead of burning
/// its acquire timeout (Follow-up (a)). Same fan-out-only, never-stored
/// discipline as [`emit_floor_grant`].
pub fn emit_floor_closed(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    channel_id: Uuid,
    revision: u64,
    ttl: Duration,
) {
    spawn_emit_floor_event(tenant, state, channel_id, "closed", move |keys| {
        crate::floor_wire::floor_closed_event(keys, channel_id, revision, ttl)
    });
}

/// Shared spawn+sign+fan-out body for every `kind:39007` overlay
/// ([`emit_floor_grant`], [`emit_floor_closed`]): sign with the relay keypair
/// off the triggering request/publish's own accept path, publish to Redis
/// before the local fan-out so subscribers on other relay pods receive it
/// too, and never store the event. `kind_label` names the variant in log
/// lines; `build` turns the relay keypair into the signed event.
fn spawn_emit_floor_event<F>(
    tenant: &TenantContext,
    state: &Arc<AppState>,
    channel_id: Uuid,
    kind_label: &'static str,
    build: F,
) where
    F: FnOnce(&nostr::Keys) -> Result<nostr::Event, nostr::event::builder::Error> + Send + 'static,
{
    let tenant = tenant.clone();
    let state = Arc::clone(state);
    tokio::spawn(async move {
        let event = match build(&state.relay_keypair) {
            Ok(event) => event,
            Err(e) => {
                warn!(channel_id = %channel_id, "floor {kind_label} sign failed: {e}");
                return;
            }
        };

        // Redis before local fan-out so subscribers on other relay pods
        // receive it too, matching emit_live_thread_summary.
        state.mark_local_event(tenant.community(), &event.id);
        if let Err(e) = state
            .pubsub
            .publish_event(&tenant, EventTopic::Channel(channel_id), &event)
            .await
        {
            state
                .local_event_ids
                .invalidate(&(tenant.community(), event.id.to_bytes()));
            warn!(channel_id = %channel_id, "floor {kind_label} Redis publish failed: {e}");
        }
        let stored = StoredEvent::new(event, Some(channel_id));
        crate::handlers::event::fan_out_event_to_local_subscribers(
            &state,
            tenant.community(),
            &stored,
        )
        .await;
    });
}
