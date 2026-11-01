import asyncio
import csv
import io
import re
import tempfile
from pathlib import Path
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
app = FastAPI(title="Sherlock OSINT API", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET", "POST", "OPTIONS"], allow_headers=["*"])
scan_lock = asyncio.Semaphore(1)

class ScanRequest(BaseModel):
    username: str = Field(min_length=2, max_length=40)
    catalog: dict | None = None
    limit: int = Field(default=150, ge=1, le=200)

def safe_https(value):
    if not isinstance(value, str):
        return ""
    try:
        p = urlparse(value)
        return value if p.scheme == "https" and p.netloc else ""
    except Exception:
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
            output = Path(tmp) / f"{username}.csv"
            command = ["sherlock", "--local", "--csv", "--folderoutput", tmp, "--timeout", "10", "--print-all", "--no-color", username]
            try:
                proc = await asyncio.create_subprocess_exec(command[0], *command[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
                stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=240)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                raise HTTPException(504, "Поиск превысил лимит времени. Попробуйте позже.")
            except FileNotFoundError:
                raise HTTPException(503, "Официальный движок Sherlock не установлен.")
            if not output.exists():
                raise HTTPException(502, "Sherlock не создал CSV-результат: " + stdout.decode("utf-8", "replace")[-800:])
            try:
                with output.open(encoding="utf-8-sig", newline="") as stream:
                    raw = list(csv.DictReader(stream))
            except Exception:
                raise HTTPException(502, "Не удалось прочитать CSV-результат Sherlock.")

    results = []
    for item in raw[:payload.limit]:
        site = item.get("name") or item.get("site") or "Unknown site"
        url = safe_https(item.get("url_user") or item.get("url"))
        status_text = (item.get("exists") or item.get("status") or "").lower()
        if status_text in ("claimed", "found", "true", "yes"):
            status = "found"
        elif status_text in ("available", "not claimed", "not_found", "false", "no"):
            status = "not_found"
        else:
            status = "unknown"
        row = {"site": site, "url": url, "status": status}
        http_status = item.get("http_status")
        if http_status and str(http_status).isdigit():
            row["httpStatus"] = int(http_status)
        if status == "found":
            row["displayName"] = site
        results.append(row)
    found = sum(x["status"] == "found" for x in results)
    not_found = sum(x["status"] == "not_found" for x in results)
    return {"username": username, "checked": len(results), "found": found, "notFound": not_found,
            "unknown": len(results) - found - not_found, "catalogCount": len(raw),
            "results": results, "engine": "official-sherlock-project"}

app.mount("/", StaticFiles(directory=PUBLIC, html=True), name="public")
