from fastapi import APIRouter, HTTPException
import os

router = APIRouter()

WORDLISTS_DIR = os.getenv("WORDLISTS_DIR", "/wordlists")

WELL_KNOWN_PATHS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/opt/SecLists",
    WORDLISTS_DIR,
]


@router.get("/")
async def list_wordlists():
    """Return all wordlist files found across known locations."""
    wordlists = []
    seen = set()

    for base_dir in WELL_KNOWN_PATHS:
        if not os.path.isdir(base_dir):
            continue
        for root, dirs, files in os.walk(base_dir):
            # Skip hidden dirs
            dirs[:] = [d for d in dirs if not d.startswith(".")]
            for fname in files:
                if fname.endswith((".txt", ".lst", ".dict")):
                    full_path = os.path.join(root, fname)
                    if full_path not in seen:
                        seen.add(full_path)
                        size = os.path.getsize(full_path)
                        wordlists.append({
                            "path": full_path,
                            "name": fname,
                            "directory": os.path.relpath(root, base_dir),
                            "base": base_dir,
                            "size_bytes": size,
                            "size_human": _human_size(size),
                        })

    return sorted(wordlists, key=lambda w: w["path"])


@router.get("/dirs")
async def list_wordlist_dirs():
    """Return which known wordlist directories exist on this system."""
    return [
        {"path": p, "exists": os.path.isdir(p)}
        for p in WELL_KNOWN_PATHS
    ]


def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
