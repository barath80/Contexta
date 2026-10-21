"""
Contexta Backend - Ledger event types.

The hash chain itself lives in app.services.ledger_service (database backed,
signed). This module only defines the shared event-type vocabulary.
"""


class LedgerEventTypes:
    """Standard event types for the ledger."""

    GENESIS = "genesis"

    # Auth / users
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    LOGIN_FAILED = "login_failed"

    # Assets
    ASSET_CREATED = "asset_created"
    ASSET_UPDATED = "asset_updated"
    ASSET_DELETED = "asset_deleted"
    ASSET_ISOLATED = "asset_isolated"
    ASSET_RESTORED = "asset_restored"

    # Risk
    RISK_CALCULATED = "risk_calculated"
    RISK_CREATED = "risk_created"
    RISK_STATUS_CHANGED = "risk_status_changed"

    # Incidents
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_CLOSED = "incident_closed"

    # Agents
    ANALYSIS_STARTED = "analysis_started"
    ANALYSIS_COMPLETE = "analysis_complete"
    CONSENSUS_GENERATED = "consensus_generated"

    # Response
    PLAYBOOK_TRIGGERED = "playbook_triggered"
    PLAYBOOK_STEP_COMPLETED = "playbook_step_completed"
    PLAYBOOK_COMPLETED = "playbook_completed"
    IOC_BLOCKED = "ioc_blocked"
    EVIDENCE_COLLECTED = "evidence_collected"
    ACTION_TAKEN = "action_taken"

    # System
    FEED_SYNC = "feed_sync"
    SYSTEM_CONFIG_CHANGED = "system_config_changed"
    DATA_EXPORTED = "data_exported"
    REPORT_GENERATED = "report_generated"
    INTEGRITY_CHECK = "integrity_check"
