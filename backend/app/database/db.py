import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from ..core.config import DB_PATH

def get_connection():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_url TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        score INTEGER NOT NULL,
        grade TEXT NOT NULL,
        critical_count INTEGER DEFAULT 0,
        high_count INTEGER DEFAULT 0,
        medium_count INTEGER DEFAULT 0,
        low_count INTEGER DEFAULT 0,
        passed_count INTEGER DEFAULT 0,
        meta_info TEXT
    )
    """)

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER NOT NULL,
        category TEXT NOT NULL,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        description TEXT NOT NULL,
        impact TEXT NOT NULL,
        technical_evidence TEXT NOT NULL,
        remediation TEXT NOT NULL,
        cwe_owasp TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
    )
    """)
    conn.commit()
    conn.close()

def save_scan_result(scan_data: Dict[str, Any]) -> int:
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    INSERT INTO scans (
        target_url, timestamp, status, score, grade,
        critical_count, high_count, medium_count, low_count, passed_count, meta_info
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_data["target_url"],
        scan_data.get("timestamp", datetime.utcnow().isoformat()),
        scan_data.get("status", "completed"),
        scan_data.get("score", 0),
        scan_data.get("grade", "F"),
        scan_data.get("critical_count", 0),
        scan_data.get("high_count", 0),
        scan_data.get("medium_count", 0),
        scan_data.get("low_count", 0),
        scan_data.get("passed_count", 0),
        json.dumps(scan_data.get("meta_info", {}))
    ))
    scan_id = cursor.lastrowid

    for f in scan_data.get("findings", []):
        cursor.execute("""
        INSERT INTO findings (
            scan_id, category, title, severity, status,
            description, impact, technical_evidence, remediation, cwe_owasp
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_id,
            f.get("category", "General"),
            f.get("title", ""),
            f.get("severity", "LOW"),
            f.get("status", "FAILED"),
            f.get("description", ""),
            f.get("impact", ""),
            f.get("technical_evidence", ""),
            f.get("remediation", ""),
            f.get("cwe_owasp", "")
        ))

    conn.commit()
    conn.close()
    return scan_id

def get_all_scans(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM scans ORDER BY id DESC LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    results = [dict(row) for row in rows]
    conn.close()
    return results

def get_scan_by_id(scan_id: int) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None
    scan = dict(scan_row)
    if scan.get("meta_info"):
        try:
            scan["meta_info"] = json.loads(scan["meta_info"])
        except Exception:
            pass

    cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
    findings_rows = cursor.fetchall()
    scan["findings"] = [dict(f) for f in findings_rows]
    conn.close()
    return scan
