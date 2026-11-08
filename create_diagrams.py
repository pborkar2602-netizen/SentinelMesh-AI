import os
import matplotlib.pyplot as plt
import matplotlib.patches as patches

# Color palette aligned with sentinelmesh-live.html
BG_DARK = '#0c0f14'
PANEL_BG = '#151a22'
PANEL_BORDER = '#262d39'
CYAN = '#4fb3c7'
VIOLET = '#7f8fd6'
RED = '#e5484d'
AMBER = '#d9a441'
GREEN = '#3fb68b'
TEXT_WHITE = '#e6eaf0'
TEXT_MUTED = '#8a94a3'

def draw_card(ax, x, y, w, h, title, subtitle=None, border_color=CYAN, bg_color=PANEL_BG, title_color=TEXT_WHITE, title_size=10, subtitle_size=8):
    rect = patches.FancyBboxPatch(
        (x, y), w, h,
        boxstyle="round,pad=0.015",
        edgecolor=border_color,
        facecolor=bg_color,
        linewidth=1.2,
        zorder=2
    )
    ax.add_patch(rect)
    if subtitle:
        ax.text(x + w/2, y + h*0.62, title, color=title_color, fontsize=title_size, fontweight='bold', ha='center', va='center', zorder=3)
        ax.text(x + w/2, y + h*0.32, subtitle, color=TEXT_MUTED, fontsize=subtitle_size, ha='center', va='center', zorder=3)
    else:
        ax.text(x + w/2, y + h*0.5, title, color=title_color, fontsize=title_size, fontweight='bold', ha='center', va='center', zorder=3)

def draw_arrow(ax, x1, y1, x2, y2, label=None, color=CYAN, label_pos=(0.5, 0.5), font_size=8, label_color=TEXT_WHITE, connectionstyle="arc3,rad=0"):
    arrow = patches.FancyArrowPatch(
        (x1, y1), (x2, y2),
        arrowstyle='-|>,head_width=3.5,head_length=5.5',
        edgecolor=color,
        facecolor=color,
        linewidth=1.4,
        connectionstyle=connectionstyle,
        zorder=4
    )
    ax.add_patch(arrow)
    if label:
        lx = x1 + (x2 - x1) * label_pos[0]
        ly = y1 + (y2 - y1) * label_pos[1]
        bbox_props = dict(boxstyle="round,pad=0.2", fc=BG_DARK, ec=PANEL_BORDER, lw=0.8, alpha=0.9)
        ax.text(lx, ly, label, color=label_color, fontsize=font_size, fontweight='bold', ha='center', va='center', bbox=bbox_props, zorder=5)

# ==============================================================================
# 1. ARCHITECTURE & COMPONENT DATA FLOW DIAGRAM
# ==============================================================================
def generate_architecture_diagram(output_path="e:/Sentinel AI/diag_architecture.png"):
    fig, ax = plt.subplots(figsize=(13, 8.5), dpi=300)
    fig.patch.set_facecolor(BG_DARK)
    ax.set_facecolor(BG_DARK)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    # Title header
    ax.text(50, 97, "SENTINELMESH AI - ARCHITECTURE & DATA FLOW", color=TEXT_WHITE, fontsize=14, fontweight='bold', ha='center', va='center')
    ax.text(50, 94.2, "End-to-End Inline Tool Interception, Layered Detection & Policy Enforcement", color=CYAN, fontsize=9.5, ha='center', va='center')

    # Subsystem Boundaries (Backing Rectangles)
    # Agent Runtime (Left)
    r_agent = patches.FancyBboxPatch((3, 48), 24, 43, boxstyle="round,pad=0.5", edgecolor=PANEL_BORDER, facecolor='#10141d', linewidth=1, linestyle='--', zorder=1)
    ax.add_patch(r_agent)
    ax.text(15, 88.5, "AI AGENT RUNTIME", color=VIOLET, fontsize=9, fontweight='bold', ha='center')

    draw_card(ax, 5, 75, 20, 10, "Autonomous Agent", "e.g. hr-agent (LLM Loop)", border_color=VIOLET)
    draw_card(ax, 5, 62, 20, 9, "Agent Task Context", "Task prompt + Working Memory", border_color=PANEL_BORDER)
    draw_card(ax, 5, 50, 20, 8.5, "Gateway Client SDK", "Intercepts tool invocations", border_color=CYAN)

    draw_arrow(ax, 15, 75, 15, 71, color=VIOLET)
    draw_arrow(ax, 15, 62, 15, 58.5, color=VIOLET)

    # SentinelMesh Security Gateway (Center Container)
    r_gw = patches.FancyBboxPatch((31, 26), 46, 65, boxstyle="round,pad=0.8", edgecolor=CYAN, facecolor='#121620', linewidth=1.5, zorder=1)
    ax.add_patch(r_gw)
    ax.text(54, 88.5, "SENTINELMESH SECURITY GATEWAY (INLINE PROXY)", color=CYAN, fontsize=10, fontweight='bold', ha='center')

    # Interception Endpoint
    draw_card(ax, 34, 76, 40, 8, "POST /api/v1/gateway/execute", "Interception & Session Context Dispatcher", border_color=CYAN, title_color=CYAN)

    # Privacy Preserving Layer
    draw_card(ax, 34, 63, 40, 10, "Privacy Preserving Engine", "PII Scanner (Regex+NER) | Tokenizer Masker | Privacy Scorer", border_color=AMBER, title_color=AMBER)

    # Layered Threat Detection Pipeline
    draw_card(ax, 34, 46, 40, 14, "Layered Threat Detection Pipeline", "1. Rule Detector (SQLi, SSRF, Injection Regex)\n2. Taint Tracker (Untrusted source propagation)\n3. Behavioral Baseline (Anomaly Z-score)\n4. Intent-vs-Action LLM Judge (Strict JSON)", border_color=RED, title_color=RED, title_size=9.5, subtitle_size=7.5)

    # Risk Scoring & Policy Engine
    draw_card(ax, 34, 35, 19, 8.5, "Risk Scorer", "Composite 0-100 Score", border_color=VIOLET, title_size=8.5)
    draw_card(ax, 55, 35, 19, 8.5, "Policy Engine", "Monitor vs Enforce Mode", border_color=GREEN, title_size=8.5, title_color=GREEN)

    draw_arrow(ax, 25, 54, 34, 80, label="1. Intercept Call", color=CYAN, label_pos=(0.4, 0.55))
    draw_arrow(ax, 54, 76, 54, 73, color=CYAN)
    draw_arrow(ax, 54, 63, 54, 60, label="Masked Payload", color=AMBER, label_pos=(0.5, 0.5), font_size=7)
    draw_arrow(ax, 54, 46, 43.5, 43.5, color=VIOLET)
    draw_arrow(ax, 53, 39, 55, 39, color=VIOLET)

    # Downstream Tools (Top Right)
    r_target = patches.FancyBboxPatch((81, 62), 16, 29, boxstyle="round,pad=0.5", edgecolor=PANEL_BORDER, facecolor='#10141d', linewidth=1, linestyle='--', zorder=1)
    ax.add_patch(r_target)
    ax.text(89, 88.5, "DOWNSTREAM TOOLS", color=GREEN, fontsize=8.5, fontweight='bold', ha='center')

    draw_card(ax, 82.5, 79, 13, 6, "read_doc", border_color=PANEL_BORDER, title_size=8)
    draw_card(ax, 82.5, 71.5, 13, 6, "db_query", border_color=PANEL_BORDER, title_size=8)
    draw_card(ax, 82.5, 64, 13, 6, "send_email", border_color=PANEL_BORDER, title_size=8)

    # Approval Queue (Right Middle)
    draw_card(ax, 80, 42, 17, 12, "Approval Queue", "Human-in-the-Loop\nPending Signoff", border_color=AMBER, title_color=AMBER, title_size=8.5)

    # Flow outputs from Policy Engine
    # ALLOW -> Target Tools
    draw_arrow(ax, 74, 39, 82.5, 74, label="ALLOW", color=GREEN, label_pos=(0.6, 0.5), font_size=8, label_color=GREEN, connectionstyle="arc3,rad=-0.15")
    # REQUIRE_APPROVAL -> Approval Queue
    draw_arrow(ax, 74, 38, 80, 47, label="APPROVAL", color=AMBER, label_pos=(0.5, 0.5), font_size=7.5, label_color=AMBER)
    # BLOCK -> Back to Agent
    draw_arrow(ax, 55, 37, 25, 51, label="BLOCK (HTTP 403)", color=RED, label_pos=(0.5, 0.5), font_size=8, label_color=RED, connectionstyle="arc3,rad=0.25")

    # Observability & Presentation Plane (Bottom)
    r_obs = patches.FancyBboxPatch((3, 3), 94, 19, boxstyle="round,pad=0.5", edgecolor=PANEL_BORDER, facecolor='#10141d', linewidth=1, zorder=1)
    ax.add_patch(r_obs)
    ax.text(50, 19.5, "MANAGEMENT, OBSERVABILITY & INCIDENT PLAYBACK PLANE", color=TEXT_WHITE, fontsize=8.5, fontweight='bold', ha='center')

    draw_card(ax, 5, 5, 26, 12, "SQLite Audit Database", "Encrypted Raw / Masked Events\nPolicies, Incidents & User Audit", border_color=PANEL_BORDER, title_size=8, subtitle_size=7)
    draw_card(ax, 37, 5, 26, 12, "WebSocket Broadcaster", "Live event distribution\nSub-50ms push updates", border_color=CYAN, title_size=8, subtitle_size=7)
    draw_card(ax, 69, 5, 26, 12, "React Live Command Center", "Animated Mesh Canvas | Attack Chain\nRisk Gauge | Raw/Masked Viewer", border_color=CYAN, title_size=8, subtitle_size=7)

    # Observability arrows
    draw_arrow(ax, 43.5, 35, 18, 17, color=TEXT_MUTED)
    draw_arrow(ax, 64.5, 35, 50, 17, color=CYAN)
    draw_arrow(ax, 63, 11, 69, 11, color=CYAN)

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print("Generated Architecture Diagram:", output_path)

# ==============================================================================
# 2. SEQUENCE DIAGRAM
# ==============================================================================
def generate_sequence_diagram(output_path="e:/Sentinel AI/diag_sequence.png"):
    fig, ax = plt.subplots(figsize=(13, 8), dpi=300)
    fig.patch.set_facecolor(BG_DARK)
    ax.set_facecolor(BG_DARK)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 97, "SENTINELMESH AI - TOOL INTERCEPTION SEQUENCE", color=TEXT_WHITE, fontsize=13, fontweight='bold', ha='center')
    ax.text(50, 94.2, "Step-by-Step Message Flow through Interception, Masking, Detection & Decisions", color=CYAN, fontsize=9, ha='center')

    lifelines = [
        ("Agent (hr-agent)", 10, VIOLET),
        ("Sentinel Gateway", 26, CYAN),
        ("Privacy Module", 42, AMBER),
        ("Detection Pipeline", 58, RED),
        ("Policy Engine", 74, GREEN),
        ("WebSocket / UI", 88, CYAN)
    ]

    for name, x, col in lifelines:
        draw_card(ax, x - 7, 86, 14, 6, name, border_color=col, title_size=7.5, title_color=col)
        ax.plot([x, x], [12, 86], color=PANEL_BORDER, linestyle='--', linewidth=1, zorder=1)

    steps = [
        (80, 10, 26, "1. POST /api/v1/gateway/execute (send_email)", CYAN, "right"),
        (73, 26, 42, "2. Scan & tokenize PII payload", AMBER, "right"),
        (66, 42, 26, "3. Return masked payload + privacy score", AMBER, "left"),
        (59, 26, 58, "4. Evaluate (Rules, Taint, Baseline, LLM Judge)", RED, "right"),
        (52, 58, 26, "5. Signals: Taint (38) + Intent Mismatch (30) -> Score: 95", RED, "left"),
        (45, 26, 74, "6. Evaluate composite score vs active policy", GREEN, "right"),
    ]

    for y, x1, x2, text, col, direction in steps:
        draw_arrow(ax, x1, y, x2, y, color=col)
        mid_x = (x1 + x2) / 2
        ax.text(mid_x, y + 2, text, color=TEXT_WHITE, fontsize=7.2, fontweight='bold', ha='center', zorder=5)

    # Decision block (ALT)
    alt_rect = patches.FancyBboxPatch((8, 14), 85, 27, boxstyle="round,pad=0.3", edgecolor=RED, facecolor='#131720', linewidth=1, linestyle='-', zorder=2)
    ax.add_patch(alt_rect)
    ax.text(12, 38.5, "[ALT: Policy Mode Decision]", color=RED, fontsize=7.5, fontweight='bold')

    # Enforce Mode
    ax.text(12, 34, "Case 1: Mode = ENFORCE (High Threat)", color=TEXT_WHITE, fontsize=7, fontweight='bold')
    draw_arrow(ax, 74, 30, 26, 30, color=RED)
    ax.text(50, 31.5, "Decision: BLOCK (Policy #2 triggered)", color=RED, fontsize=7, ha='center')
    draw_arrow(ax, 26, 26, 88, 26, color=CYAN)
    ax.text(57, 27.5, "Broadcast: DECISION = BLOCK, risk=95", color=CYAN, fontsize=7, ha='center')
    draw_arrow(ax, 26, 22, 10, 22, color=RED)
    ax.text(18, 23.5, "HTTP 403 Forbidden", color=RED, fontsize=7, ha='center')

    # Monitor Mode
    ax.plot([8, 93], [19, 19], color=PANEL_BORDER, linestyle=':', linewidth=1)
    ax.text(12, 16.5, "Case 2: Mode = MONITOR -> Action Allowed with Alert | HTTP 200 returned", color=AMBER, fontsize=7)

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print("Generated Sequence Diagram:", output_path)

# ==============================================================================
# 3. ENTITY-RELATIONSHIP DIAGRAM
# ==============================================================================
def generate_er_diagram(output_path="e:/Sentinel AI/diag_er.png"):
    fig, ax = plt.subplots(figsize=(13, 8.5), dpi=300)
    fig.patch.set_facecolor(BG_DARK)
    ax.set_facecolor(BG_DARK)
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis('off')

    ax.text(50, 97, "SENTINELMESH AI - RELATIONAL DATA MODEL (ERD)", color=TEXT_WHITE, fontsize=13, fontweight='bold', ha='center')
    ax.text(50, 94.2, "Schema Entities, Audit Fields, Privacy Protection & Forensics Linkages", color=CYAN, fontsize=9, ha='center')

    entities = [
        ("AGENT", 6, 60, 24, 28, [
            ("id (PK)", "VARCHAR(64)"),
            ("name", "VARCHAR(128)"),
            ("role", "VARCHAR(64)"),
            ("declared_purpose", "TEXT"),
            ("allowed_tools", "JSON"),
            ("baseline_stats", "JSON"),
            ("created_at", "DATETIME")
        ], VIOLET),

        ("AUDIT_EVENT", 37, 46, 26, 42, [
            ("id (PK)", "UUID"),
            ("trace_id", "VARCHAR(64) INDEX"),
            ("agent_id (FK)", "VARCHAR(64)"),
            ("session_id", "VARCHAR(64)"),
            ("tool_name", "VARCHAR(64)"),
            ("input_masked", "JSON"),
            ("input_raw_enc", "TEXT (AES)"),
            ("output_masked", "JSON"),
            ("taint_status", "BOOLEAN"),
            ("pii_entities", "JSON"),
            ("decision", "VARCHAR(32)"),
            ("risk_score", "INTEGER (0-100)"),
            ("risk_breakdown", "JSON"),
            ("latency_ms", "FLOAT"),
            ("timestamp", "DATETIME")
        ], CYAN),

        ("POLICY", 70, 62, 24, 26, [
            ("id (PK)", "VARCHAR(64)"),
            ("name", "VARCHAR(128)"),
            ("mode", "MONITOR | ENFORCE"),
            ("conditions", "JSON"),
            ("action", "ALLOW|BLOCK|REDACT"),
            ("is_active", "BOOLEAN"),
            ("version", "INTEGER")
        ], GREEN),

        ("INCIDENT", 6, 12, 24, 34, [
            ("id (PK)", "VARCHAR(64)"),
            ("trace_id", "VARCHAR(64)"),
            ("agent_id (FK)", "VARCHAR(64)"),
            ("severity", "LOW..CRITICAL"),
            ("confidence", "FLOAT"),
            ("title", "VARCHAR(256)"),
            ("summary", "TEXT"),
            ("mitre_category", "VARCHAR(64)"),
            ("status", "OPEN|REVIEWED")
        ], RED),

        ("ATTACK_CHAIN_STEP", 37, 14, 26, 24, [
            ("id (PK)", "UUID"),
            ("incident_id (FK)", "VARCHAR(64)"),
            ("step_order", "INTEGER"),
            ("icon", "VARCHAR(8)"),
            ("title", "VARCHAR(128)"),
            ("detail", "TEXT"),
            ("status", "VARCHAR(32)")
        ], RED),

        ("APPROVAL_REQUEST", 70, 34, 24, 22, [
            ("id (PK)", "VARCHAR(64)"),
            ("event_id (FK)", "UUID"),
            ("agent_id", "VARCHAR(64)"),
            ("tool_name", "VARCHAR(64)"),
            ("status", "PENDING|APPROVED"),
            ("reviewer_id", "VARCHAR(64)"),
            ("decided_at", "DATETIME")
        ], AMBER),

        ("USER_AUDIT", 70, 10, 24, 18, [
            ("id (PK)", "UUID"),
            ("actor_role", "VARCHAR(64)"),
            ("action", "VIEW_RAW_PAYLOAD"),
            ("target_event_id (FK)", "UUID"),
            ("timestamp", "DATETIME")
        ], TEXT_MUTED)
    ]

    for title, x, y, w, h, fields, border_col in entities:
        # Card header & body
        rect = patches.FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.015", edgecolor=border_col, facecolor=PANEL_BG, linewidth=1.2, zorder=2)
        ax.add_patch(rect)
        # Header banner
        hdr = patches.FancyBboxPatch((x, y + h - 5.5), w, 5.5, boxstyle="round,pad=0.015", edgecolor=border_col, facecolor=border_col, linewidth=1, zorder=3)
        ax.add_patch(hdr)
        ax.text(x + w/2, y + h - 2.8, title, color='#ffffff', fontsize=8.5, fontweight='bold', ha='center', va='center', zorder=4)

        # Fields
        cur_y = y + h - 8
        for fname, ftype in fields:
            ax.text(x + 1.2, cur_y, fname, color=TEXT_WHITE, fontsize=6.5, fontweight='bold', ha='left', va='center', zorder=4)
            ax.text(x + w - 1.2, cur_y, ftype, color=TEXT_MUTED, fontsize=6, ha='right', va='center', zorder=4)
            cur_y -= 2.2

    # Relationship connectors
    # AGENT -> AUDIT_EVENT
    draw_arrow(ax, 30, 74, 37, 74, label="1:N", color=VIOLET, label_pos=(0.5, 0.5), font_size=7)
    # POLICY -> AUDIT_EVENT
    draw_arrow(ax, 70, 75, 63, 75, label="1:N", color=GREEN, label_pos=(0.5, 0.5), font_size=7)
    # AGENT -> INCIDENT
    draw_arrow(ax, 18, 60, 18, 46, label="1:N", color=VIOLET, label_pos=(0.5, 0.5), font_size=7)
    # INCIDENT -> ATTACK_CHAIN_STEP
    draw_arrow(ax, 30, 26, 37, 26, label="1:N", color=RED, label_pos=(0.5, 0.5), font_size=7)
    # AUDIT_EVENT -> APPROVAL_REQUEST
    draw_arrow(ax, 63, 52, 70, 46, label="1:1", color=AMBER, label_pos=(0.5, 0.5), font_size=7)
    # AUDIT_EVENT -> USER_AUDIT
    draw_arrow(ax, 50, 46, 70, 18, label="1:N", color=TEXT_MUTED, label_pos=(0.4, 0.5), font_size=7, connectionstyle="arc3,rad=-0.1")

    plt.tight_layout()
    plt.savefig(output_path, facecolor=fig.get_facecolor(), edgecolor='none', bbox_inches='tight')
    plt.close()
    print("Generated ER Diagram:", output_path)

if __name__ == "__main__":
    generate_architecture_diagram()
    generate_sequence_diagram()
    generate_er_diagram()
