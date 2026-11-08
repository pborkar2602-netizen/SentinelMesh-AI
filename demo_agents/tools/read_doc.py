import os
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "synthetic_data"

def read_doc(file_path: str) -> str:
    """Reads a local document or synthetic file."""
    # Try direct path
    p = Path(file_path)
    if not p.is_file():
        # Try relative to synthetic_data
        p = DATA_DIR / file_path
    if not p.is_file():
        # Try matching base name
        candidates = list(DATA_DIR.glob(f"*{Path(file_path).name}*"))
        if candidates:
            p = candidates[0]

    if not p.is_file():
        raise FileNotFoundError(f"Document not found: {file_path}")

    with open(p, "r", encoding="utf-8") as f:
        content = f.read()
    return content
