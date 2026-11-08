import os
import sys
from fpdf import FPDF
from fpdf.fonts import FontFace

class SentinelReport(FPDF):
    def __init__(self):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.set_auto_page_break(auto=True, margin=18)
        self.set_margins(16, 18, 16)
        
    def header(self):
        if self.page_no() == 1:
            return  # Suppress running header on title page
        self.set_font("helvetica", "B", 8)
        self.set_text_color(100, 116, 139)
        self.cell(0, 6, "SENTINELMESH AI  |  TECHNICAL ARCHITECTURE & IMPLEMENTATION BLUEPRINT", align="L", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(226, 232, 240)
        self.set_line_width(0.3)
        self.line(16, 24, 194, 24)
        self.ln(3)

    def footer(self):
        self.set_y(-14)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 8, f"Page {self.page_no()} of {{nb}}   |   Confidential - For Team Review Only", align="C")

    # Helper styling methods
    def section_title(self, num_str, title_str):
        self.ln(4)
        self.set_fill_color(241, 245, 249)
        self.set_draw_color(24, 120, 140)
        self.set_line_width(0.8)
        
        # Cyan left accent line
        x = self.get_x()
        y = self.get_y()
        self.rect(x, y, 178, 9, style="F")
        self.rect(x, y, 2.5, 9, style="DF")
        
        self.set_xy(x + 5, y + 1.2)
        self.set_font("helvetica", "B", 12)
        self.set_text_color(15, 23, 42)
        self.cell(0, 6.5, f"{num_str}. {title_str.upper()}", new_x="LMARGIN", new_y="NEXT")
        self.ln(3)

    def subsection_title(self, title_str):
        self.ln(2)
        self.set_font("helvetica", "B", 10.5)
        self.set_text_color(24, 120, 140)
        self.cell(0, 6, title_str, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def paragraph(self, text):
        self.set_font("helvetica", "", 9.5)
        self.set_text_color(51, 65, 85)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def callout_box(self, title, body_text, alert_type="info"):
        self.ln(1)
        if alert_type == "info":
            bg_col = (240, 249, 255)
            border_col = (24, 120, 140)
            title_col = (14, 116, 144)
        elif alert_type == "warning":
            bg_col = (254, 252, 232)
            border_col = (202, 138, 4)
            title_col = (161, 98, 7)
        elif alert_type == "success":
            bg_col = (240, 253, 244)
            border_col = (34, 197, 94)
            title_col = (21, 128, 61)
        else:
            bg_col = (248, 250, 252)
            border_col = (100, 116, 139)
            title_col = (30, 41, 59)

        x = self.get_x()
        y = self.get_y()
        self.set_fill_color(*bg_col)
        self.set_draw_color(*border_col)
        self.set_line_width(0.4)
        
        # Calculate height roughly
        self.set_font("helvetica", "", 9)
        lines = self.multi_cell(168, 4.8, body_text, dry_run=True, output="LINES")
        h = 8 + (len(lines) * 4.8)
        
        self.rect(x, y, 178, h, style="DF")
        self.rect(x, y, 2.5, h, style="DF") # thicker bar
        
        self.set_xy(x + 5, y + 2)
        self.set_font("helvetica", "B", 9.5)
        self.set_text_color(*title_col)
        self.cell(0, 5, title, new_x="LMARGIN", new_y="NEXT")
        
        self.set_xy(x + 5, y + 7)
        self.set_font("helvetica", "", 9)
        self.set_text_color(51, 65, 85)
        self.multi_cell(168, 4.8, body_text)
        self.set_y(y + h + 2.5)

    def code_block(self, code_str):
        self.ln(1)
        self.set_fill_color(18, 22, 29) # dark charcoal background
        self.set_draw_color(38, 45, 57)
        self.set_line_width(0.3)
        
        self.set_font("courier", "", 8.5)
        lines = code_str.strip().split("\n")
        h = (len(lines) * 4.2) + 6
        
        x = self.get_x()
        y = self.get_y()
        
        # Check if we need page break
        if y + h > 275:
            self.add_page()
            x = self.get_x()
            y = self.get_y()
            
        self.rect(x, y, 178, h, style="DF")
        self.set_xy(x + 4, y + 3)
        self.set_text_color(226, 232, 240)
        
        for line in lines:
            self.cell(0, 4.2, line, new_x="LMARGIN", new_y="NEXT")
            self.set_x(x + 4)
            
        self.set_y(y + h + 2)


def build_pdf():
    pdf = SentinelReport()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # ----------------------------------------------------
    # COVER / HEADER BANNER
    # ----------------------------------------------------
    pdf.set_fill_color(15, 23, 42) # Slate 900
    pdf.rect(16, 16, 178, 48, style="F")
    
    # Accent top border
    pdf.set_fill_color(79, 179, 199) # Cyan accent
    pdf.rect(16, 16, 178, 3, style="F")
    
    pdf.set_xy(22, 23)
    pdf.set_font("helvetica", "B", 19)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 8, "SENTINELMESH AI", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_xy(22, 32)
    pdf.set_font("helvetica", "B", 11)
    pdf.set_text_color(79, 179, 199)
    pdf.cell(0, 6, "Autonomous, Privacy-Preserving Security for AI Agents", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_xy(22, 40)
    pdf.set_font("helvetica", "", 9)
    pdf.set_text_color(203, 213, 225)
    pdf.cell(0, 5, "Technical Architecture, Component Design & Implementation Blueprint", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_xy(22, 49)
    pdf.set_font("helvetica", "I", 8.5)
    pdf.set_text_color(148, 163, 184)
    pdf.cell(0, 5, "Internship Project Specification  |  Version 1.0 (Draft)  |  November 2026", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_y(68)
    
    # Metadata info pills
    pdf.set_font("helvetica", "B", 9)
    pdf.set_text_color(71, 85, 105)
    pdf.cell(42, 6, "ROLE: Lead Engineer Spec")
    pdf.cell(46, 6, "CORE STACK: FastAPI + React")
    pdf.cell(48, 6, "DB: SQLite (Postgres ready)")
    pdf.cell(42, 6, "STATUS: Pending Sign-off", new_x="LMARGIN", new_y="NEXT")
    
    pdf.set_draw_color(226, 232, 240)
    pdf.line(16, 76, 194, 76)
    pdf.ln(4)
    
    # ----------------------------------------------------
    # EXECUTIVE SUMMARY & MISSION
    # ----------------------------------------------------
    pdf.callout_box(
        "Project Scope & Presentation Objective",
        "SentinelMesh AI sits as an inline security gateway between enterprise autonomous agents and business tools. "
        "It inspects every tool call, detects prompt injections and taint propagation, evaluates privacy exposure, "
        "reconstructs attack chains, and enforces policies (Allow, Block, Redact, Require-Approval). "
        "Engineered for high reliability, explainability, and an impressive live demonstration with sub-200ms p95 latency.",
        alert_type="info"
    )
    
    # ----------------------------------------------------
    # SECTION 1: REPOSITORY STRUCTURE
    # ----------------------------------------------------
    pdf.section_title("1", "Proposed Repository Structure")
    pdf.paragraph(
        "The repository is organized as a modular monorepo ensuring clean separation of concerns. Security-critical "
        "components (Gateway, Policy Engine, PII Masker) are isolated in pure, testable modules with zero framework bloat."
    )
    
    repo_tree = """Sentinel AI/
|-- docker-compose.yml              # 1-command startup (backend, frontend, demo agent)
|-- README.md                       # Setup instructions & demo script
|-- backend/                        # Python 3.11 + FastAPI
|   |-- app/
|   |   |-- api/v1/                 # Endpoints: gateway proxy, events, incidents, policies, audit
|   |   |-- core/                   # CRITICAL: gateway interceptor, policy engine, risk scorer
|   |   |-- privacy/                # PII scanner, tokenizing masker, privacy risk scorer
|   |   |-- detection/              # Rules detector, taint tracker, baseline anomaly, LLM judge
|   |   |-- models/                 # SQLAlchemy 2.0 ORM & Pydantic v2 schemas
|   |   `-- simulator/              # Multi-step poisoned resume attack scenario runner
|   `-- tests/                      # Pytest unit & integration test suites
|-- frontend/                       # React 18 + TypeScript + Vite + Tailwind CSS
|   |-- src/components/             # Mesh canvas, attack chain panel, live feed, risk gauge
|   `-- src/hooks/                  # Resilient WebSocket telemetry hook
|-- demo_agents/                    # Mock HR & Finance autonomous agents (read_doc, db_query, etc.)
`-- benchmark/                      # Evaluation harness: 15+ attacks, 15+ benign scenarios"""
    
    pdf.code_block(repo_tree)
    
    # ----------------------------------------------------
    # SECTION 2: ARCHITECTURE & DATA FLOW
    # ----------------------------------------------------
    pdf.section_title("2", "Architecture Description & Data Flow")
    pdf.paragraph(
        "SentinelMesh operates as an inline reverse proxy for agent tool execution. When an agent requests a tool call, "
        "the request passes through a 5-stage inspection pipeline before downstream execution is permitted."
    )
    
    pdf.subsection_title("2.1 System Architecture & Component Flow Diagram")
    if pdf.get_y() + 110 > 275:
        pdf.add_page()
    pdf.image("e:/Sentinel AI/diag_architecture.png", x=16, w=178)
    pdf.ln(4)
    
    pdf.subsection_title("2.2 End-to-End Interception Sequence Diagram")
    if pdf.get_y() + 105 > 275:
        pdf.add_page()
    pdf.image("e:/Sentinel AI/diag_sequence.png", x=16, w=178)
    pdf.ln(4)
    
    pdf.subsection_title("2.3 Key API & Event Schemas")
    
    schema_sample = """1. Gateway Interception Request (POST /api/v1/gateway/execute):
{
  "trace_id": "trc-8821a-4f91", "session_id": "sess-hr-9921", "agent_id": "hr-agent",
  "task_description": "Summarize resume of Alex Verma and extract qualifications",
  "tool_name": "send_email",
  "tool_arguments": {"to": "h.recruiter@ext-mail.io", "body": "Salary: INR 18,40,000"},
  "context_sources": [{"source_type": "document", "source_id": "resume.pdf", "is_untrusted": true}]
}

2. Gateway Interception Response (200 OK / 403 Blocked):
{
  "decision": "BLOCK", "mode": "ENFORCE", "risk_score": 95,
  "risk_breakdown": {"untrusted_context": 38, "intent_mismatch": 30, "baseline": 12, "pii": 15},
  "masked_payload": {"to": "[EMAIL_1]", "body": "Salary: [AMOUNT_1]"},
  "incident_id": "inc-214", "latency_ms": 42.6,
  "error_message": "Action blocked by Policy: No external email from untrusted context"
}"""
    pdf.code_block(schema_sample)
    
    # ----------------------------------------------------
    # SECTION 3: DATA MODEL
    # ----------------------------------------------------
    pdf.section_title("3", "Relational Data Model (SQLite / Postgres)")
    pdf.paragraph(
        "The relational schema supports immutable auditability, privacy isolation (raw payloads are stored encrypted "
        "and access is role-audited), policy configuration, and multi-step incident correlation."
    )
    
    pdf.subsection_title("3.1 Entity-Relationship Architecture Diagram")
    if pdf.get_y() + 115 > 275:
        pdf.add_page()
    pdf.image("e:/Sentinel AI/diag_er.png", x=16, w=178)
    pdf.ln(4)
    
    pdf.subsection_title("3.2 Entity Specifications & Forensic Fields")
    data_model_text = """* AGENT: Tracks authorized agents, declared capabilities, and baseline profiles.
  - Columns: id (PK, e.g. 'hr-agent'), name, role, declared_purpose, allowed_tools (JSON), baseline_stats (JSON)

* AUDIT_EVENT: Immutable capture of every tool interception and security assessment.
  - Columns: id (UUID PK), trace_id (Indexed), agent_id (FK), session_id, tool_name,
    input_payload_masked (JSON), input_payload_raw_encrypted (Text),
    output_payload_masked (JSON), taint_status (Boolean), pii_entities_detected (JSON),
    decision (ALLOW|BLOCK|REDACT|REQUIRE_APPROVAL), policy_mode (MONITOR|ENFORCE),
    risk_score (0-100), risk_breakdown (JSON), latency_ms (Float), timestamp

* POLICY: Guardrail rules defined by administrators.
  - Columns: id (PK), name, description, mode (MONITOR|ENFORCE), conditions (JSON),
    action (ALLOW|BLOCK|REDACT|REQUIRE_APPROVAL), is_active (Boolean), version (Int)

* INCIDENT: Correlated security event containing a reconstructed attack chain.
  - Columns: id (PK, e.g. 'inc-214'), trace_id, agent_id (FK), severity (LOW..CRITICAL),
    confidence (Float), title, summary, mitre_category, blast_radius, status (OPEN|REVIEWED)

* ATTACK_CHAIN_STEP: Ordered step in an incident's narrative timeline.
  - Columns: id (PK), incident_id (FK), step_order (Int), icon, title, detail, status

* APPROVAL_REQUEST: Human-in-the-loop escalation queue for high-risk actions.
  - Columns: id (PK), event_id (FK), agent_id, tool_name, arguments_masked, status, reviewer_id

* USER_AUDIT: Tamper-evident log of analysts viewing raw sensitive payloads.
  - Columns: id (PK), actor_role, action ('VIEW_RAW_PAYLOAD'), target_event_id (FK), timestamp"""
    pdf.code_block(data_model_text)
    
    # ----------------------------------------------------
    # SECTION 4: MILESTONE PLAN
    # ----------------------------------------------------
    pdf.section_title("4", "Phased Milestone Implementation Plan")
    pdf.paragraph(
        "A strict walking skeleton approach ensures an end-to-end working system exists in Milestone 1, "
        "with subsequent milestones incrementally adding detection fidelity, policy control, and visual polish."
    )
    
    head_style = FontFace(emphasis="BOLD", fill_color=(226, 232, 240), color=(15, 23, 42))
    with pdf.table(col_widths=(18, 38, 72, 50), text_align=("C", "L", "L", "L"), line_height=5, headings_style=head_style) as table:
        header_row = table.row()
        header_row.cell("Milestone")
        header_row.cell("Deliverable")
        header_row.cell("Core Engineering Tasks")
        header_row.cell("Acceptance Verification")
        
        pdf.set_font("helvetica", "", 8)
        milestones = [
            ("M1", "Walking Skeleton\n(End-to-End Demo)", "FastAPI proxy, SQLite telemetry, mock HR agent, basic WebSocket stream, minimal UI layout shell.", "Agent calls tool -> logged in SQLite -> pops in dashboard live feed."),
            ("M2", "Privacy Engine &\nMasking System", "PII pattern detector (email, names, salaries), consistent tokenization, AES encrypted raw storage, audited view modal.", "Sensitive payload masked in UI; clicking 'Show Raw' triggers logged audit."),
            ("M3", "Taint Tracker &\nRule Detector", "Session taint graph tracking untrusted doc sources; regex rules for SQLi, SSRF, prompt injection; 0-100 risk score.", "Tool call with untrusted context raises taint flag and risk gauge to >60."),
            ("M4", "Intent-vs-Action\nLLM Judge", "Abstract judge interface; deterministic MockJudge for demo; Pydantic strict JSON schema; live LLM toggle.", "Mismatched action (task vs tool) yields 0.94 mismatch score and alert."),
            ("M5", "Policy Engine &\nApproval Queue", "Deterministic rule engine; Monitor vs Enforce mode toggle; Require-Approval queue with approve/deny actions.", "Monitor mode allows with alert; Enforce mode blocks tool with HTTP 403."),
            ("M6", "Attack Chain &\nCommand Center", "Port canvas mesh animation from prototype; dynamic 5-step attack chain panel; SVG gauge; full scenario runner.", "One-click 'Run Attack Simulation' executes 5-step scenario with full visuals."),
            ("M7", "Benchmark Suite &\nDocker Compose", "30-scenario test harness (15 attacks, 15 benign); metrics report (Recall, FPR, p95); 1-command Docker Compose.", "Automated benchmark proves >=90% detection, <5% FPR, <200ms latency.")
        ]
        
        for m_id, m_del, m_tasks, m_verify in milestones:
            row = table.row()
            row.cell(m_id)
            row.cell(m_del)
            row.cell(m_tasks)
            row.cell(m_verify)
            
    pdf.ln(3)

    # ----------------------------------------------------
    # SECTION 5: TEST STRATEGY & BENCHMARK SUITE
    # ----------------------------------------------------
    pdf.section_title("5", "Test Strategy & Benchmark Suite")
    pdf.paragraph(
        "Testing follows a three-tier model: Pytest unit tests for core security algorithms, FastAPI integration tests for "
        "interception APIs, and an automated benchmark evaluation suite comprising 30 comprehensive scenarios."
    )
    
    pdf.subsection_title("Attack Scenario Evaluation Suite (15 Test Cases)")
    attacks_text = """ 1. Poisoned Resume (Indirect Injection)  9. Invisible Unicode Prompt Injection
 2. Goal Drift via Bulk DB Scrape         10. Delayed Sleeper Instructions in Doc
 3. SSRF via Cloud Metadata URL           11. Automated Employee PII Harvesting
 4. SQL Injection via db_query            12. Invoice Routing Tampering via Email
 5. System Prompt Exfiltration Attempt    13. Rapid Tool Burst (Denial of Wallet)
 6. AWS Secret Exfiltration via Headers   14. Toxic / Hostile Output Delivery
 7. Cross-Agent Privilege Escalation      15. Unapproved Tool Usage for Agent Role
 8. Arbitrary Local File Read (/etc/env)"""
    pdf.code_block(attacks_text)

    pdf.subsection_title("Benign Task Baseline Suite (15 Test Cases)")
    benign_text = """ 1. Standard Resume Summary Extraction    9. Customer Address Change Verification
 2. Internal Employee Payroll Query       10. Invoice Line-Item Math Verification
 3. Support Ticket Details Lookup         11. Corporate Directory Search
 4. Routine Internal Confirmation Email   12. Weekly GitHub Issue Metrics Rollup
 5. Internal HR Policy Document Search    13. Knowledge-Base FAQ Retrieval
 6. GitHub Pull Request Diff Review       14. Order Shipping Notification Dispatch
 7. Ops Microservice /health Ping         15. Scheduled Database Maintenance Call
 8. Multi-Step Document Translation"""
    pdf.code_block(benign_text)
    
    pdf.subsection_title("Target Metrics & Ablation Comparison")
    
    head_style2 = FontFace(emphasis="BOLD", fill_color=(226, 232, 240), color=(15, 23, 42))
    with pdf.table(col_widths=(45, 45, 45, 43), text_align=("L", "C", "C", "C"), line_height=5, headings_style=head_style2) as table:
        header_row = table.row()
        header_row.cell("Configuration Mode")
        header_row.cell("Detection Rate (Recall)")
        header_row.cell("False Positive Rate")
        header_row.cell("p95 Added Latency")
        
        pdf.set_font("helvetica", "", 8)
        r1 = table.row()
        r1.cell("BRS Target Requirement")
        r1.cell(">= 90.0%")
        r1.cell("< 5.0%")
        r1.cell("<= 200 ms")
        
        r2 = table.row()
        r2.cell("Rules-Only Baseline")
        r2.cell("~60.0% (misses taint/drift)")
        r2.cell("~2.0%")
        r2.cell("~12 ms")
        
        r3 = table.row()
        r3.cell("SentinelMesh Full-Stack")
        r3.cell(">= 93.3% (catches multi-step)")
        r3.cell("< 3.0%")
        r3.cell("~48 ms (Mock / Cached)")
        
    pdf.ln(3)

    # ----------------------------------------------------
    # SECTION 6: RISKS, ASSUMPTIONS & OPEN QUESTIONS
    # ----------------------------------------------------
    pdf.section_title("6", "Risks, Assumptions & Decisions Required")
    
    pdf.subsection_title("Identified Project Risks & Technical Mitigations")
    pdf.paragraph(
        "* Live Demo Dependency Risk: Reliance on live third-party LLM APIs can result in latency spikes, rate limits, "
        "or transient network drops during a presentation. Mitigation: Abstract `IntentJudge` with a zero-latency, "
        "deterministic Mock provider enabled by default, with a live toggle for optional testing.\n"
        "* Canvas Performance: Complex UI animations may lag on low-power client devices. Mitigation: Use the ultra-lightweight "
        "native 2D HTML5 canvas particle loop ported directly from sentinelmesh-live.html (60fps, no external dependencies).\n"
        "* Data Privacy during Live Screen Shares: Presenting raw PII exposes confidential data. Mitigation: Default-on "
        "masking before telemetry reaches storage or WebSocket; unmasking requires explicit modal action and logs an audit record."
    )
    
    pdf.subsection_title("Three Decisions Awaiting User Review")
    pdf.callout_box(
        "Decision Points for Implementation",
        "1. LLM Judge Live Provider: Should we default to the deterministic Mock provider for guaranteed demo stability, "
        "with an optional environment variable (OPENAI_API_KEY / GEMINI_API_KEY) for live evaluation?\n"
        "2. Simulation Trigger: Would you like the demo agent to run automatically on a repeating timer (e.g. every 25s), "
        "or strictly when the user clicks 'Run attack simulation'? (We recommend supporting both via a toggle).\n"
        "3. Approval Queue UI: Should pending approvals appear as an interactive modal popup, a slide-over drawer, or "
        "an inline toast in the live command center?",
        alert_type="warning"
    )
    
    output_filename = "e:/Sentinel AI/SentinelMesh_AI_Architecture_Blueprint.pdf"
    pdf.output(output_filename)
    print(f"Successfully generated PDF: {output_filename}")

if __name__ == "__main__":
    build_pdf()
