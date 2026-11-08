from typing import Dict, Any, Optional

def external_api(method: str, url: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Mock external HTTP API caller."""
    return {
        "status_code": 200,
        "method": method.upper(),
        "url": url,
        "response": {"result": "success", "echo_payload": payload}
    }
