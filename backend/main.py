import asyncio
import json
import os
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
app = FastAPI(title="Sherlock OSINT API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)
scan_lock = asyncio.Semaphore(1)

class ScanRequest(BaseModel):
    username: str = Field(min_length=2, max_length=40)
    catalog: dict | None = None
    limit: int = Field(default=150, ge=1, le=200)

def clean_url(value):
    if not isinstance(value, str):
        return ""
    try:
        parsed = urlparse(value)
        if parsed.scheme == "https" and parsed.netloc:
            return value
    except Exception:
        pass
    return ""

@app.get("/api/health")
async def health():
    return {"ok": True, "engine": "official-sherlock-project"}

@app.post("/api/scan")
async def scan(payload: ScanRequest):
    username = payload.username.strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{2,40}", username):
        raise HTTPException(400, "Username: 2–40 символов, латиница, цифры, точка, дефис или подчёркивание.")
    async with scan_lock:
        with tempfile.TemporaryDirectory(prefix="sherlock-") as tmp:
            output = Path(tmp) / "results.json"
            command = [
                "sherlock", "--local", "--json", str(output),
                "--timeout", "10", "--print-all", "--no-color", username
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *command, stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise HTTPException(504, "Поиск превысил лимит времени. Попробуйте позже.")
            except FileNotFoundError:
                raise HTTPException(503, "Официальный движок Sherlock не установлен.")
            if not output.exists():
                detail = stdout.decode("utf-8", "replace")[-1200:]
                raise HTTPException(502, "Sherlock не создал JSON-результат: " + detail)
            try:
                raw = json.loads(output.read_text(encoding="utf-8"))
            except Exception:
                raise HTTPException(502, "Не удалось прочитать JSON-результат Sherlock.")

    results = []
    for site, item in list(raw.items())[:payload.limit]:
        if not isinstance(item, dict):
            continue
        url = clean_url(item.get("url_user") or item.get("url"))
        exists = item.get("exists")
        status = "found" if exists is True else "not_found" if exists is False else "unknown"
        row = {"site": site, "url": url, "status": status}
        if item.get("http_status") is not None:
            row["httpStatus"] = item["http_status"]
        if status == "found" and url:
            row["displayName"] = site
        results.append(row)
    found = sum(x["status"] == "found" for x in results)
    not_found = sum(x["status"] == "not_found" for x in results)
    unknown = len(results) - found - not_found
    return {
        "username": username, "checked": len(results), "found": found,
        "notFound": not_found, "unknown": unknown, "catalogCount": len(raw),
        "results": results, "engine": "official-sherlock-project"
    }

app.mount("/", StaticFiles(directory=PUBLIC, html=True), name="public")
