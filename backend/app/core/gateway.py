from typing import Tuple, List, Dict, Any
from backend.app.schemas.gateway import ToolCallRequest, ContextSource
from backend.app.core.trust_labeler import label_trust
from backend.app.core.taint_tracker import track_session_taint
from backend.app.detection.rules import run_all_detectors, Finding
from backend.app.core.risk_scorer import compute_risk_score
from backend.app.core.policy_engine import PolicyEngine
from backend.app.privacy.detectors import CompositePiiDetector, PiiFinding
from backend.app.privacy.masker import PrivacyEngine
from backend.app.baseline.anomaly_detector import AnomalyDetector
from backend.app.judge.intent_judge import IntentJudge
from backend.app.db.database import list_session_events

class GatewayCore:
    """
    SentinelMesh Gateway Core Evaluation Pipeline (Milestones 2, 4, and 5):
    1. Server-side Trust Labeling (provenance-based)
    2. Session-Level Taint Tracking (propagation across steps)
    3. Rule-Based Threat Detectors (unapproved recipient, SSRF, SQLi, traversal, credentials, injection)
    4. Privacy & PII Detection (Composite detector: emails, phones, IDs, cards, IBANs, keys, salaries, names)
    5. Integrated 0-100 Threat & Privacy Risk Scoring
    6. Milestone 5: Learned Behavioral Baseline Anomaly Detection (MAD, bursts, off-hours, rare sequences)
    7. Milestone 5: Intent-vs-Action LLM Judge (masked payloads only, prompt-injection defense)
    8. Policy Engine Evaluation (allow, block, would_block, redact, require_approval)
    """
    _pii_detector = CompositePiiDetector()

    @classmethod
    def evaluate(cls, request: ToolCallRequest) -> Tuple[str, str, int, dict, List[ContextSource], List[Finding]]:
        risk_breakdown: dict = {}

        # 0. Milestone 6: Verification of Signed Approval Token (if presented)
        if getattr(request, "approval_token", None):
            from backend.app.approvals.tokens import verify_and_consume_approval_token, ApprovalTokenError
            try:
                verified_payload = verify_and_consume_approval_token(
                    token_str=request.approval_token,
                    tool_name=request.tool_name,
                    arguments=request.arguments,
                    trace_id=request.trace_id
                )
                risk_breakdown["approval_token_verified"] = True
                risk_breakdown["token_nonce"] = verified_payload.get("nonce")
                return (
                    "allow",
                    "Action permitted via verified one-time HMAC approval token.",
                    0,
                    risk_breakdown,
                    request.context_sources,
                    []
                )
            except ApprovalTokenError as exc:
                risk_breakdown["approval_token_error"] = str(exc)
                return (
                    "block",
                    f"Security Policy Block: Approval token verification failed ({exc}).",
                    100,
                    risk_breakdown,
                    request.context_sources,
                    []
                )

        # 1. Authoritative Server-side Trust Labeling (Provenance-based)
        normalized_sources, trust_warnings = label_trust(
            context_sources=request.context_sources,
            tool_name=request.tool_name,
            arguments=request.arguments
        )

        # 2. Session Taint Tracking
        is_tainted, tainted_by, newly_tainted = track_session_taint(
            session_id=request.session_id,
            context_sources=normalized_sources
        )

        # 3. Rule Detection
        findings = run_all_detectors(
            tool_name=request.tool_name,
            arguments=request.arguments,
            context_sources=normalized_sources
        )

        # 4. Privacy & PII Detection across arguments and context
        pii_findings: List[PiiFinding] = []
        for val in request.arguments.values():
            if isinstance(val, str):
                pii_findings.extend(cls._pii_detector.detect(val))
        for src in normalized_sources:
            if src.snippet:
                pii_findings.extend(cls._pii_detector.detect(src.snippet))

        # 5. Risk Scoring (0-100 Threat Signals)
        risk_score, risk_breakdown = compute_risk_score(
            is_tainted=is_tainted,
            findings=findings,
            tool_name=request.tool_name,
            arguments=request.arguments
        )

        # 6. Privacy Risk Scoring (0-100 Privacy Signals)
        is_external = False
        if request.tool_name == "send_email":
            from backend.app.detection.rules import is_approved_email_domain
            rec = request.arguments.get("to") or request.arguments.get("recipient") or ""
            is_external = not is_approved_email_domain(str(rec))
        elif request.tool_name == "external_api":
            from backend.app.detection.rules import is_approved_api_host
            url = str(request.arguments.get("url") or request.arguments.get("endpoint") or "")
            is_external = not is_approved_api_host(url)

        priv_score, priv_breakdown = PrivacyEngine.calculate_privacy_risk(
            pii_findings,
            is_external=is_external,
            is_tainted=is_tainted
        )
        if priv_score > 0:
            risk_breakdown["privacy_score"] = priv_score
            risk_breakdown["privacy_breakdown"] = priv_breakdown
            risk_score = max(risk_score, priv_score)

        # 7. Milestone 5: Learned Behavioral Baseline Anomaly Detection
        session_events = list_session_events(request.session_id)
        anomaly_score, anomaly_reasons, anomaly_breakdown = AnomalyDetector.evaluate(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            arguments=request.arguments,
            session_events=session_events,
            sim_datetime=request.timestamp
        )
        if anomaly_score > 0:
            risk_breakdown["baseline_anomaly"] = anomaly_score
            risk_breakdown["anomaly_reasons"] = anomaly_reasons
            risk_breakdown["anomaly_breakdown"] = anomaly_breakdown
            risk_score = max(risk_score, anomaly_score)

        # 8. Intent-vs-Action LLM Judge (MASKED PAYLOADS ONLY with non-PII security context)
        masked_args_for_judge, _ = PrivacyEngine.mask_payload(request.session_id, request.arguments)
        
        # Extract destination domain for context
        dest_domain = None
        if request.tool_name == "send_email":
            email_val = str(request.arguments.get("to") or request.arguments.get("recipient") or "")
            if "@" in email_val:
                dest_domain = email_val.split("@")[-1].strip().lower()
        elif request.tool_name == "external_api":
            import urllib.parse
            url_val = str(request.arguments.get("url") or request.arguments.get("endpoint") or "")
            dest_domain = urllib.parse.urlparse(url_val).hostname

        data_class_counts: Dict[str, int] = {}
        for f in pii_findings:
            data_class_counts[f.pii_type] = data_class_counts.get(f.pii_type, 0) + 1

        judge_verdict = IntentJudge.evaluate(
            task_description=request.task_description or "Autonomous session task",
            session_id=request.session_id,
            tool_name=request.tool_name,
            masked_arguments=masked_args_for_judge,
            destination_domain=dest_domain,
            is_tainted=is_tainted,
            tainted_sources=tainted_by,
            data_class_counts=data_class_counts
        )
        if judge_verdict:
            risk_breakdown["judge_mismatch"] = judge_verdict.mismatch_score
            risk_breakdown["judge_reasoning"] = judge_verdict.reasoning
            risk_breakdown["judge_risk_level"] = judge_verdict.risk_level
            risk_breakdown["judge_latency_ms"] = judge_verdict.latency_ms
            risk_breakdown["judge_mode"] = judge_verdict.mode
            if judge_verdict.mismatch_score > 50:
                risk_score = max(risk_score, judge_verdict.mismatch_score)

        # 9. Policy Engine Evaluation (Enforce vs Monitor mode, with Redact & Judge hooks)
        decision, reason = PolicyEngine.evaluate_policy(
            tool_name=request.tool_name,
            arguments=request.arguments,
            is_tainted=is_tainted,
            tainted_by=tainted_by,
            findings=findings,
            risk_score=risk_score,
            pii_findings=pii_findings,
            judge_verdict=judge_verdict,
            anomaly_score=anomaly_score,
            anomaly_reasons=anomaly_reasons
        )

        # 10. Milestone 6: Approval Workflow & Simulated Reviewer
        if decision == "require_approval":
            from backend.app.approvals.service import ApprovalService
            from backend.app.approvals.reviewer import SimulatedReviewer

            appr = ApprovalService.create_approval_request(
                session_id=request.session_id,
                trace_id=request.trace_id,
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                arguments=request.arguments,
                reason=reason,
                risk_score=risk_score
            )
            risk_breakdown["approval_id"] = appr["id"]

            if SimulatedReviewer.is_active():
                sim_res = SimulatedReviewer.evaluate_and_resolve(
                    approval_id=appr["id"],
                    tool_name=request.tool_name,
                    arguments=request.arguments
                )
                if sim_res and sim_res["status"] == "denied":
                    decision = "block"
                    reason = f"Simulated reviewer denied human approval request [{appr['id']}]: {sim_res.get('resolution_reason')}"
                elif sim_res and sim_res["status"] == "approved":
                    decision = "allow"
                    reason = f"Simulated reviewer approved human approval request [{appr['id']}]."
            else:
                reason = f"{reason} (Approval Request ID: {appr['id']})"

        # Append trust disagreement warnings to reason text if present
        if trust_warnings:
            reason += f" [{trust_warnings[0]}]"

        return decision, reason, risk_score, risk_breakdown, normalized_sources, findings
