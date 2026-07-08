from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import os

router = APIRouter()

WORDLISTS_DIR    = os.getenv("WORDLISTS_DIR", "/wordlists")
CUSTOM_WORDLISTS_DIR = "/data/custom_wordlists"

WELL_KNOWN_PATHS = [
    "/usr/share/wordlists",
    "/usr/share/seclists",
    "/opt/SecLists",
    CUSTOM_WORDLISTS_DIR,
    WORDLISTS_DIR,
]


class WordlistCreate(BaseModel):
    name: str
    content: str


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
                            "custom": base_dir == CUSTOM_WORDLISTS_DIR,
                        })

    return sorted(wordlists, key=lambda w: w["path"])


@router.get("/dirs")
async def list_wordlist_dirs():
    """Return which known wordlist directories exist on this system."""
    return [
        {"path": p, "exists": os.path.isdir(p)}
        for p in WELL_KNOWN_PATHS
    ]


@router.post("/", status_code=201)
async def create_wordlist(body: WordlistCreate):
    os.makedirs(CUSTOM_WORDLISTS_DIR, exist_ok=True)
    name = os.path.basename(body.name.strip())
    if not name:
        raise HTTPException(status_code=400, detail="Name is required")
    if not any(name.endswith(ext) for ext in (".txt", ".lst", ".dict")):
        name += ".txt"
    path = os.path.join(CUSTOM_WORDLISTS_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(body.content)
    size = os.path.getsize(path)
    return {
        "path": path,
        "name": name,
        "directory": ".",
        "base": CUSTOM_WORDLISTS_DIR,
        "size_bytes": size,
        "size_human": _human_size(size),
        "custom": True,
    }


@router.delete("/")
async def delete_wordlist(path: str):
    real_path   = os.path.realpath(path)
    real_custom = os.path.realpath(CUSTOM_WORDLISTS_DIR)
    if not real_path.startswith(real_custom + os.sep):
        raise HTTPException(status_code=403, detail="Only custom wordlists can be deleted")
    if not os.path.isfile(real_path):
        raise HTTPException(status_code=404, detail="File not found")
    os.remove(real_path)


def _human_size(size: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"
