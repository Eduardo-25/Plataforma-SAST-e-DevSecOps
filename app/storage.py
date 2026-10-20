"""CP3: histórico de análises em SQLite (biblioteca padrão; sem serviço extra)."""
from __future__ import annotations

import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from app.reports import history_row

MAX_STORED_SCANS = 1000


def db_path() -> Path:
    return Path(os.environ.get("SAST_DB_PATH", "data/sast.db"))


@contextmanager
def connect():
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("""CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, project TEXT NOT NULL, created_at TEXT NOT NULL,
        summary TEXT NOT NULL, report TEXT NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project, id)")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def save(report: dict) -> int:
    with connect() as conn:
        cur = conn.execute("INSERT INTO scans (project, created_at, summary, report) VALUES (?,?,?,?)",
                           (report["project"], report["generated_at"],
                            json.dumps(history_row(report), ensure_ascii=False),
                            json.dumps(report, ensure_ascii=False)))
        scan_id = cur.lastrowid
        # Retenção simples: mantém as análises mais recentes.
        conn.execute("DELETE FROM scans WHERE id <= ?", (scan_id - MAX_STORED_SCANS,))
    return scan_id


def history(project: str | None = None, limit: int = 30) -> list[dict]:
    sql, args = "SELECT id, summary FROM scans", []
    if project:
        sql += " WHERE project = ?"
        args.append(project)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    return [{**json.loads(r["summary"]), "id": r["id"]} for r in reversed(rows)]


def get(scan_id: int | None = None, project: str | None = None) -> dict | None:
    sql, args = "SELECT id, report FROM scans", []
    clauses = []
    if scan_id is not None:
        clauses.append("id = ?"); args.append(scan_id)
    if project:
        clauses.append("project = ?"); args.append(project)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT 1"
    with connect() as conn:
        row = conn.execute(sql, args).fetchone()
    return {**json.loads(row["report"]), "scan_id": row["id"]} if row else None


def projects() -> list[str]:
    with connect() as conn:
        return [r["project"] for r in conn.execute("SELECT DISTINCT project FROM scans ORDER BY project")]
