import json
from pathlib import Path
from typing import List, Dict, Any

DATA_DIR = Path(__file__).resolve().parent.parent / "synthetic_data"

def db_query(query: str) -> List[Dict[str, Any]]:
    """Mock SQL database query against synthetic records."""
    salaries_path = DATA_DIR / "salaries.json"
    with open(salaries_path, "r", encoding="utf-8") as f:
        records = json.load(f)

    q = query.lower()
    if "where" in q and "engineering" in q:
        return [r for r in records if r.get("department") == "Engineering"]
    elif "where" in q and "emp-101" in q:
        return [r for r in records if r.get("employee_id") == "EMP-101"]
    return records
