import sqlite3
import json
import logging
from enum import Enum
from datetime import datetime

from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from io import BytesIO

from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4

from scanner import run_scan

# =====================================================
# App Setup
# =====================================================

app = FastAPI(title="ThreatScope Cloud Endpoint Security Scanner")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# Database
# =====================================================

DB_FILE = "scans.db"

def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip TEXT,
                os_type TEXT,
                username TEXT,
                scan_date TEXT,
                threat_score INTEGER,
                threat_category TEXT,
                total_checks INTEGER,
                vulnerabilities_found INTEGER,
                checks_failed INTEGER,
                scan_duration REAL,
                findings TEXT
            )
        """)

init_db()

# =====================================================
# Enum
# =====================================================

class OSType(str, Enum):
    linux = "linux"
    windows = "windows"

# =====================================================
# Save Scan
# =====================================================

def save_scan_to_db(scan_data: dict) -> int:
    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (device_ip, os_type, username, scan_date,
             threat_score, threat_category,
             total_checks, vulnerabilities_found,
             checks_failed, scan_duration,
             findings)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data["device"],
            scan_data["os"],
            scan_data["username"],
            scan_data["date"],
            scan_data["threat_score"],
            scan_data["threat_category"],
            scan_data.get("total_checks", 0),
            scan_data.get("vulnerabilities_found", 0),
            scan_data.get("checks_failed", 0),
            scan_data.get("scan_duration_seconds", 0),
            json.dumps(scan_data.get("results", []))
        ))
        return cursor.lastrowid

# =====================================================
# Status Formatting (Professional Labeling)
# =====================================================

def format_status(result: dict) -> str:

    if result.get("scan_status") != "Pass":
        return result.get("scan_status", "CheckFailed")

    if result.get("vulnerable") is True:
        return "Vulnerable"

    return "Secure"

# =====================================================
# Recommendation Logic
# =====================================================

def generate_recommendation(result: dict) -> str:

    if result.get("scan_status") != "Pass":
        return "Check execution failed. Verify permissions, credentials, or remote configuration."

    if result.get("vulnerable") is True:
        return "Security control misconfigured. Immediate remediation is recommended to reduce exposure."

    return "Control properly configured. Continue routine monitoring."

# =====================================================
# Scan Endpoint
# =====================================================

@app.post("/scan")
async def scan_endpoint(
    os_type: OSType = Form(...),
    ip: str = Form(...),
    username: str = Form(...),
    password: str = Form(...)
):
    try:
        logger.info(f"Starting scan for {ip}")
        scan_data = run_scan(os_type.value, ip, username, password)

        if scan_data.get("threat_category") == "ScanFailed":
            raise HTTPException(status_code=500, detail="Scan failed")

        scan_id = save_scan_to_db(scan_data)
        scan_data["id"] = scan_id

        return scan_data

    except HTTPException:
        raise
    except Exception:
        logger.exception("Unexpected error during scan")
        raise HTTPException(status_code=500, detail="Internal server error")

# =====================================================
# Get All Scans
# =====================================================

@app.get("/scans")
async def get_all_scans():
    with get_db_connection() as conn:
        rows = conn.execute("""
            SELECT id, device_ip, os_type,
                   scan_date, threat_score,
                   threat_category
            FROM scans
            ORDER BY id DESC
        """).fetchall()

    return [dict(row) for row in rows]

# =====================================================
# Get Single Scan
# =====================================================

@app.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": row["id"],
        "device": row["device_ip"],
        "os": row["os_type"],
        "username": row["username"],
        "date": row["scan_date"],
        "threat_score": row["threat_score"],
        "threat_category": row["threat_category"],
        "total_checks": row["total_checks"],
        "vulnerabilities_found": row["vulnerabilities_found"],
        "checks_failed": row["checks_failed"],
        "scan_duration_seconds": row["scan_duration"],
        "results": json.loads(row["findings"])
    }

# =====================================================
# JSON Export (SIEM Integration Ready)
# =====================================================

@app.get("/export_json/{scan_id}")
async def export_json(scan_id: int):

    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "id": row["id"],
        "device": row["device_ip"],
        "os": row["os_type"],
        "username": row["username"],
        "date": row["scan_date"],
        "threat_score": row["threat_score"],
        "threat_category": row["threat_category"],
        "total_checks": row["total_checks"],
        "vulnerabilities_found": row["vulnerabilities_found"],
        "checks_failed": row["checks_failed"],
        "scan_duration_seconds": row["scan_duration"],
        "results": json.loads(row["findings"])
    }

# =====================================================
# PDF Download
# =====================================================

@app.get("/download_pdf/{scan_id}")
async def download_pdf(scan_id: int):

    with get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = json.loads(row["findings"])

    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []

    styles = getSampleStyleSheet()
    normal = styles["Normal"]

    # TITLE
    elements.append(Paragraph("<b>ThreatScope Security Assessment Report</b>", styles["Title"]))
    elements.append(Spacer(1, 0.3 * inch))

    # Executive Summary
    summary = [
        ["Device", row["device_ip"]],
        ["Operating System", row["os_type"]],
        ["Threat Score", f"{row['threat_score']} %"],
        ["Risk Level", row["threat_category"]],
        ["Total Checks", row["total_checks"]],
        ["Vulnerabilities Found", row["vulnerabilities_found"]],
        ["Checks Failed", row["checks_failed"]],
        ["Scan Duration (s)", str(row["scan_duration"])],
        ["Scan Date", row["scan_date"]],
    ]

    table = Table(summary, colWidths=[2.5*inch, 3.5*inch])
    table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.grey),
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#f0f0f0"))
    ]))

    elements.append(table)
    elements.append(Spacer(1, 0.5 * inch))

    # Findings Table
    data = [["Check", "Status", "Severity", "CVSS", "Recommendation"]]

    for r in findings:
        status_display = format_status(r)

        data.append([
            Paragraph(r.get("check", ""), normal),
            status_display,
            r.get("severity", "") if status_display == "Vulnerable" else "-",
            str(r.get("cvss_score", "")) if status_display == "Vulnerable" else "-",
            Paragraph(generate_recommendation(r), normal)
        ])

    findings_table = Table(data, repeatRows=1)
    findings_table.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.3, colors.grey),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#002b45")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.white),
    ]))

    elements.append(findings_table)

    doc.build(elements)
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=ThreatScope_Report_{scan_id}.pdf"}
    )
