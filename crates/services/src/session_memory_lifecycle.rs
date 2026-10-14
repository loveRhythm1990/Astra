//! Durable session-memory work owned by the canonical session lifecycle.
//! Request publication precedes turn completion. Short checkpoints and bounded
//! destructive cleanup take the existing session write fence, shared by all pods
//! and turn admission; a lease selects a worker, never grants user authority.

use crate::CancellationSafePoolConnection;
use astra_core::SharedPool;
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Connection, MySql, Row, Transaction};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionMemoryWork {
    /// Transient projection from the locked canonical Session row.
    #[serde(skip)]
    pub session_closed: bool,
    #[serde(skip)]
    pub canonical_turn: u32,
    pub latest_request: Option<Value>,
    pub latest_fingerprint: Option<String>,
    pub completed_fingerprint: Option<String>,
    pub completed_turn: Option<u32>,
    pub active_request: Option<Value>,
    pub active_fingerprint: Option<String>,
    /// Frozen before HTTP dispatch so crash recovery never synthesizes a
    /// different payload for an uncertain write.
    pub prepared_working: Option<Value>,
    /// Receipt of the working snapshot actually read/written by the settled attempt.
    pub working_memory_id: Option<String>,
    pub extraction_requested: bool,
    pub finalize_requested: bool,
    /// CLI exit targets its idle generation; explicit close settles all already-admitted work.
    pub finalize_turn: Option<u32>,
    /// Frozen snapshot and facts used by every retry of this generation.
    pub plan: Option<Value>,
    pub receipts: BTreeMap<String, String>,
    pub purged_ids: BTreeSet<String>,
    pub reflection: Option<Value>,
    pub consolidation_complete: bool,
    pub optional_complete: bool,
    pub last_report: Option<Value>,
}

impl SessionMemoryWork {
    pub fn extraction_pending(&self) -> bool {
        self.active_request.is_some()
            || ((self.extraction_requested || self.finalize_requested)
                && self.latest_fingerprint != self.completed_fingerprint)
    }
    pub fn pending(&self) -> bool {
        self.extraction_pending() || (self.finalize_requested && !self.optional_complete)
    }
    pub fn reset_plan(&mut self) {
        self.plan = None;
        self.receipts.clear();
        self.purged_ids.clear();
        self.reflection = None;
        self.consolidation_complete = false;
        self.optional_complete = false;
        self.last_report = None;
    }
}

#[derive(Clone)]
pub struct SessionMemoryLifecycleStore {
    pool: SharedPool,
}

#[derive(Debug, Clone)]
pub struct SessionMemoryWorkClaim {
    pub user_id: String,
    pub session_id: String,
    pub token: String,
    pub work: SessionMemoryWork,
}

impl SessionMemoryLifecycleStore {
    pub fn new(pool: SharedPool) -> Self {
        Self { pool }
    }

    pub async fn publish(
        &self,
        user: &str,
        session: &str,
        request: Value,
        fingerprint: String,
    ) -> Result<(), String> {
        self.with_fenced_state(user, session, None, false, move |work| {
            Box::pin(async move {
                if work.session_closed && work.consolidation_complete && work.finalize_requested {
                    return Err("closed generation is already consolidated".into());
                }
                let turn = request["inference_scope"]["turn"]
                    .as_u64()
                    .or_else(|| request["session_facts"]["turn"].as_u64())
                    .ok_or("missing extraction turn")?;
                let previous = work.latest_request.as_ref().and_then(|request| {
                    request["inference_scope"]["turn"]
                        .as_u64()
                        .or_else(|| request["session_facts"]["turn"].as_u64())
                });
                if previous.is_some_and(|previous| turn < previous) {
                    return Ok(());
                }
                if work.latest_fingerprint.as_ref() != Some(&fingerprint) {
                    work.latest_request = Some(request);
                    work.latest_fingerprint = Some(fingerprint);
                    // A follow-up turn cancels stale exit maintenance. Explicit
                    // close rejects new requests at the session fence below.
                    if !work.session_closed
                        && work
                            .finalize_turn
                            .is_none_or(|target| turn > u64::from(target))
                    {
                        work.finalize_requested = false;
                        work.finalize_turn = None;
                    }
                    work.reset_plan();
                }
                Ok(())
            })
        })
        .await
    }

    /// Repeated exit/close requests preserve stage receipts and retry progress.
    pub async fn request_finalization(&self, user: &str, session: &str) -> Result<(), String> {
        self.with_fenced_state(user, session, None, true, |work| {
            Box::pin(async move {
                if work.canonical_turn > work.completed_turn.unwrap_or(0) {
                    work.reset_plan();
                }
                work.finalize_requested = true;
                let latest_turn = work
                    .latest_request
                    .as_ref()
                    .and_then(|request| {
                        request["inference_scope"]["turn"]
                            .as_u64()
                            .or_else(|| request["session_facts"]["turn"].as_u64())
                    })
                    .unwrap_or(0);
                let latest_turn = u32::try_from(latest_turn)
                    .map_err(|_| "extraction turn exceeds supported memory coordinate")?;
                work.finalize_turn = Some(work.canonical_turn.max(latest_turn));
                Ok(())
            })
        })
        .await
    }

    pub async fn request_extraction(&self, user: &str, session: &str) -> Result<(), String> {
        self.with_fenced_state(user, session, None, false, |work| {
            Box::pin(async move {
                work.extraction_requested = true;
                Ok(())
            })
        })
        .await
    }

    /// Read immutable canonical context only when a handoff was missed. It is
    /// materialized by the existing coordinator, never from transcript/audit projections.
    pub async fn missing_input_head(
        &self,
        user: &str,
        session: &str,
    ) -> Result<Option<astra_turn_types::SessionContextHeadV1>, String> {
        let row = sqlx::query("SELECT CAST(w.state_json AS CHAR) AS state_json, h.head_json FROM agent_session_memory_work w JOIN session_context_heads h ON h.owner_user_id = w.user_id AND h.session_id = w.session_id WHERE w.user_id = ? AND w.session_id = ? AND h.head_json IS NOT NULL ORDER BY h.completed_turn DESC, h.updated_at DESC LIMIT 1")
            .bind(user).bind(session).fetch_optional(self.pool.get()).await.map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(None);
        };
        let work: SessionMemoryWork = serde_json::from_str(
            &row.try_get::<String, _>("state_json")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let head: astra_turn_types::SessionContextHeadV1 = serde_json::from_str(
            &row.try_get::<String, _>("head_json")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if head.key.owner_user_id != user || head.key.session_id != session {
            return Err("canonical recovery head ownership mismatch".into());
        }
        let latest = work
            .latest_request
            .as_ref()
            .and_then(|request| {
                request["inference_scope"]["turn"]
                    .as_u64()
                    .or_else(|| request["session_facts"]["turn"].as_u64())
            })
            .unwrap_or(0);
        Ok((u64::from(head.cursor.completed_turn) > latest).then_some(head))
    }

    pub async fn publish_recovery(
        &self,
        claim: &SessionMemoryWorkClaim,
        request: Value,
        fingerprint: String,
        turn: u32,
    ) -> Result<(), String> {
        self.with_fenced_state(
            &claim.user_id,
            &claim.session_id,
            Some(&claim.token),
            true,
            move |work| {
                Box::pin(async move {
                    if work.canonical_turn != turn {
                        return Err("canonical recovery generation changed".into());
                    }
                    work.latest_request = Some(request);
                    work.latest_fingerprint = Some(fingerprint);
                    work.extraction_requested = true;
                    if !work.session_closed
                        && work.finalize_turn.is_some_and(|target| turn > target)
                    {
                        work.finalize_requested = false;
                        work.finalize_turn = None;
                    }
                    work.reset_plan();
                    if work.active_request.is_none() {
                        work.active_request = work.latest_request.clone();
                        work.active_fingerprint = work.latest_fingerprint.clone();
                    }
                    Ok(())
                })
            },
        )
        .await
    }

    pub async fn load_claim_work(
        &self,
        claim: &SessionMemoryWorkClaim,
    ) -> Result<SessionMemoryWork, String> {
        self.with_fenced_state(
            &claim.user_id,
            &claim.session_id,
            Some(&claim.token),
            false,
            |work| Box::pin(async move { Ok(work.clone()) }),
        )
        .await
    }

    pub async fn status(&self, user: &str, session: &str) -> Result<Value, String> {
        let row = sqlx::query("SELECT CAST(state_json AS CHAR) AS state_json, attempts, CAST(next_attempt_at AS CHAR) AS next_attempt_at FROM agent_session_memory_work WHERE user_id = ? AND session_id = ?")
            .bind(user).bind(session).fetch_optional(self.pool.get()).await.map_err(|error| error.to_string())?;
        let Some(row) = row else {
            return Ok(serde_json::json!({"requested": false, "session_id":session}));
        };
        let work: SessionMemoryWork = serde_json::from_str(
            &row.try_get::<String, _>("state_json")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        Ok(
            serde_json::json!({"session_id":session, "requested":work.finalize_requested,
            "pending":work.pending(), "extraction_pending":work.extraction_pending(),
            "completed_turn":work.completed_turn, "consolidation_complete":work.consolidation_complete,
            "optional_complete":work.optional_complete, "last_report":work.last_report,
            "attempts":row.try_get::<i64,_>("attempts").map_err(|error| error.to_string())?,
            "next_attempt_at":row.try_get::<String,_>("next_attempt_at").map_err(|error| error.to_string())?}),
        )
    }

    pub async fn list_due(&self, limit: u16) -> Result<Vec<(String, String)>, String> {
        let rows = sqlx::query("SELECT w.user_id, w.session_id FROM agent_session_memory_work w JOIN agent_sessions s ON s.user_id = w.user_id AND s.session_id = w.session_id WHERE s.delete_requested_at IS NULL AND w.complete = 0 AND w.next_attempt_at <= NOW(6) AND (w.lease_token IS NULL OR w.lease_expires_at <= NOW(6)) ORDER BY w.next_attempt_at, w.user_id, w.session_id LIMIT ?")
            .bind(limit).fetch_all(self.pool.get()).await.map_err(|error| error.to_string())?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("user_id").map_err(|error| error.to_string())?,
                    row.try_get("session_id")
                        .map_err(|error| error.to_string())?,
                ))
            })
            .collect()
    }

    pub async fn claim(
        &self,
        user: &str,
        session: &str,
    ) -> Result<Option<SessionMemoryWorkClaim>, String> {
        let mut connection = CancellationSafePoolConnection::acquire(self.pool.get())
            .await
            .map_err(|error| error.to_string())?;
        let mut tx = connection
            .connection_mut()
            .begin()
            .await
            .map_err(|error| error.to_string())?;
        lock_session(&mut tx, user, session).await?;
        let Some(row) = sqlx::query("SELECT CAST(state_json AS CHAR) AS state_json, (lease_token IS NULL OR lease_expires_at <= NOW(6)) AS available FROM agent_session_memory_work WHERE user_id = ? AND session_id = ? AND complete = 0 AND next_attempt_at <= NOW(6) FOR UPDATE")
            .bind(user).bind(session).fetch_optional(&mut *tx).await.map_err(|error| error.to_string())? else { return Ok(None); };
        if row
            .try_get::<i64, _>("available")
            .map_err(|error| error.to_string())?
            == 0
        {
            return Ok(None);
        }
        let mut work: SessionMemoryWork = serde_json::from_str(
            &row.try_get::<String, _>("state_json")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        if work.extraction_pending() && work.active_request.is_none() {
            work.active_request = work.latest_request.clone();
            work.active_fingerprint = work.latest_fingerprint.clone();
        }
        let token = uuid::Uuid::new_v4().to_string();
        sqlx::query("UPDATE agent_session_memory_work SET state_json = ?, lease_token = ?, lease_expires_at = DATE_ADD(NOW(6), INTERVAL 90 SECOND), attempts = attempts + 1 WHERE user_id = ? AND session_id = ?")
            .bind(serde_json::to_string(&work).map_err(|error| error.to_string())?).bind(&token).bind(user).bind(session).execute(&mut *tx).await.map_err(|error| error.to_string())?;
        tx.commit().await.map_err(|error| error.to_string())?;
        connection.release();
        Ok(Some(SessionMemoryWorkClaim {
            user_id: user.into(),
            session_id: session.into(),
            token,
            work,
        }))
    }

    /// The callback may perform one bounded HTTP operation while the canonical
    /// session fence is held. This prevents turn admission, close, delete and
    /// another worker from crossing a destructive checkpoint mid-request.
    pub async fn with_fenced_state<R: Send, F>(
        &self,
        user: &str,
        session: &str,
        token: Option<&str>,
        require_idle: bool,
        f: F,
    ) -> Result<R, String>
    where
        F: for<'a> FnOnce(&'a mut SessionMemoryWork) -> BoxFuture<'a, Result<R, String>> + Send,
    {
        let mut connection = CancellationSafePoolConnection::acquire(self.pool.get())
            .await
            .map_err(|error| error.to_string())?;
        let mut tx = connection
            .connection_mut()
            .begin()
            .await
            .map_err(|error| error.to_string())?;
        let status = lock_session(&mut tx, user, session).await?;

        if require_idle {
            ensure_idle(&mut tx, user, session).await?;
        }
        ensure_work_row(&mut tx, user, session).await?;
        let row = sqlx::query("SELECT CAST(state_json AS CHAR) AS state_json, lease_token, (lease_expires_at > NOW(6)) AS lease_live FROM agent_session_memory_work WHERE user_id = ? AND session_id = ? FOR UPDATE")
            .bind(user).bind(session).fetch_one(&mut *tx).await.map_err(|error| error.to_string())?;
        if let Some(token) = token
            && (row
                .try_get::<Option<String>, _>("lease_token")
                .map_err(|error| error.to_string())?
                .as_deref()
                != Some(token)
                || row
                    .try_get::<Option<i64>, _>("lease_live")
                    .map_err(|error| error.to_string())?
                    != Some(1))
        {
            return Err("session memory worker lease was superseded".into());
        }
        let mut work: SessionMemoryWork = serde_json::from_str(
            &row.try_get::<String, _>("state_json")
                .map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        work.session_closed = status == "closed";
        if require_idle {
            work.canonical_turn = canonical_turn_tx(&mut tx, user, session).await?;
        }
        let result = f(&mut work).await?;
        sqlx::query("UPDATE agent_session_memory_work SET state_json = ?, complete = ?, next_attempt_at = NOW(6), updated_at = NOW(6) WHERE user_id = ? AND session_id = ?")
            .bind(serde_json::to_string(&work).map_err(|error| error.to_string())?).bind(!work.pending()).bind(user).bind(session).execute(&mut *tx).await.map_err(|error| error.to_string())?;
        tx.commit().await.map_err(|error| error.to_string())?;
        connection.release();
        Ok(result)
    }

    pub async fn finish_extraction(
        &self,
        claim: &SessionMemoryWorkClaim,
        success: bool,
        turn: u32,
    ) -> Result<(), String> {
        self.with_fenced_state(
            &claim.user_id,
            &claim.session_id,
            Some(&claim.token),
            false,
            move |work| {
                Box::pin(async move {
                    if success {
                        work.completed_fingerprint = work.active_fingerprint.take();
                        work.completed_turn = Some(turn);
                        work.active_request = None;
                        work.prepared_working = None;
                        work.extraction_requested =
                            work.latest_fingerprint != work.completed_fingerprint;
                    }
                    Ok(())
                })
            },
        )
        .await?;
        self.release(claim, success).await
    }

    pub async fn release(
        &self,
        claim: &SessionMemoryWorkClaim,
        success: bool,
    ) -> Result<(), String> {
        // A failure backs off but remains durable; successful progress is due
        // immediately for the next stage. Claim expiry recovers process death.
        let due = if success {
            "NOW(6)"
        } else {
            "DATE_ADD(NOW(6), INTERVAL LEAST(960, 5 * POW(2, LEAST(GREATEST(attempts - 1, 0), 8))) SECOND)"
        };
        let attempts = if success { "0" } else { "attempts" };
        let query = format!(
            "UPDATE agent_session_memory_work SET lease_token = NULL, lease_expires_at = NULL, next_attempt_at = {due}, attempts = {attempts}, updated_at = NOW(6) WHERE user_id = ? AND session_id = ? AND lease_token = ?"
        );
        sqlx::query(&query)
            .bind(&claim.user_id)
            .bind(&claim.session_id)
            .bind(&claim.token)
            .execute(self.pool.get())
            .await
            .map_err(|error| error.to_string())?;
        Ok(())
    }
}

async fn lock_session(
    tx: &mut Transaction<'_, MySql>,
    user: &str,
    session: &str,
) -> Result<String, String> {
    crate::storage::lock_agent_session_write_fence(tx, session, user)
        .await
        .map_err(|error| error.to_string())?;
    sqlx::query_scalar("SELECT status FROM agent_sessions WHERE user_id = ? AND session_id = ? AND delete_requested_at IS NULL FOR UPDATE")
        .bind(user).bind(session).fetch_optional(&mut **tx).await.map_err(|error| error.to_string())?.ok_or_else(|| "session memory work requires an owned, retained session".into())
}

async fn ensure_idle(
    tx: &mut Transaction<'_, MySql>,
    user: &str,
    session: &str,
) -> Result<(), String> {
    let slots: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_session_execution_slots WHERE user_id = ? AND session_id = ?",
    )
    .bind(user)
    .bind(session)
    .fetch_one(&mut **tx)
    .await
    .map_err(|error| error.to_string())?;
    if slots != 0 {
        return Err("session memory finalization waits for execution settlement".into());
    }
    Ok(())
}

async fn ensure_work_row(
    tx: &mut Transaction<'_, MySql>,
    user: &str,
    session: &str,
) -> Result<(), String> {
    sqlx::query("INSERT IGNORE INTO agent_session_memory_work (user_id, session_id, state_json, complete) VALUES (?, ?, '{}', 1)")
        .bind(user).bind(session).execute(&mut **tx).await.map_err(|error| error.to_string())?;
    Ok(())
}

/// Called inside the session service's close transaction, after its row lock.
pub(crate) async fn request_finalization_tx(
    tx: &mut Transaction<'_, MySql>,
    user: &str,
    session: &str,
) -> Result<(), String> {
    // Closing may occur while an extraction is pending; the recovery worker
    // settles that exact durable generation before constructing a purge plan.
    let raw: Option<String> = sqlx::query_scalar("SELECT CAST(state_json AS CHAR) FROM agent_session_memory_work WHERE user_id = ? AND session_id = ? FOR UPDATE")
        .bind(user).bind(session).fetch_optional(&mut **tx).await.map_err(|error| error.to_string())?;
    let Some(raw) = raw else {
        return Ok(());
    };
    let mut work: SessionMemoryWork =
        serde_json::from_str(&raw).map_err(|error| error.to_string())?;
    work.canonical_turn = canonical_turn_tx(tx, user, session).await?;
    if work.canonical_turn > work.completed_turn.unwrap_or(0) {
        work.reset_plan();
    }
    work.finalize_requested = true;
    work.finalize_turn = None;
    sqlx::query("UPDATE agent_session_memory_work SET state_json = ?, complete = ?, next_attempt_at = NOW(6) WHERE user_id = ? AND session_id = ?")
        .bind(serde_json::to_string(&work).map_err(|error| error.to_string())?).bind(!work.pending()).bind(user).bind(session).execute(&mut **tx).await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn canonical_turn_tx(
    tx: &mut Transaction<'_, MySql>,
    user: &str,
    session: &str,
) -> Result<u32, String> {
    let turn:i64=sqlx::query_scalar("SELECT COALESCE(MAX(completed_turn), 0) FROM session_context_heads WHERE owner_user_id = ? AND session_id = ?")
        .bind(user).bind(session).fetch_one(&mut **tx).await.map_err(|error|error.to_string())?;
    u32::try_from(turn).map_err(|_| "canonical turn exceeds supported memory coordinate".into())
}
