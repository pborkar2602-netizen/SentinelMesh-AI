from typing import Dict, Any

def send_email(to: str, subject: str, body: str) -> Dict[str, Any]:
    """Mock outbound email sender."""
    return {
        "status": "delivered",
        "to": to,
        "subject": subject,
        "body_preview": body[:80] + ("..." if len(body) > 80 else ""),
        "timestamp": "simulated"
    }
