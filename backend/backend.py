import sqlite3
import json
import logging
from enum import Enum
from typing import List

from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from scanner import run_scan  # Make sure this is your scanning function


# =====================================================
# App Setup
# =====================================================

app = FastAPI(title="Cloud Endpoint Security Scanner")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # your frontend
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
                findings TEXT,
                recommendations TEXT
            )
        """)


init_db()


# =====================================================
# Enums & Validation
# =====================================================

class OSType(str, Enum):
    linux = "linux"
    windows = "windows"


# =====================================================
# Database Operations
# =====================================================

def save_scan_to_db(scan_data: dict) -> int:
    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scans
            (device_ip, os_type, username, scan_date,
             threat_score, threat_category,
             findings, recommendations)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_data.get("device"),
            scan_data.get("os"),
            scan_data.get("username"),
            scan_data.get("date"),
            scan_data.get("threat_score", 0),
            scan_data.get("threat_category", "Low"),
            json.dumps(scan_data.get("results", [])),
            json.dumps(scan_data.get("recommendations", []))
        ))
        return cursor.lastrowid


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
        scan_data["id"] = scan_id  # numeric ID
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
    try:
        with get_db_connection() as conn:
            rows = conn.execute("""
                SELECT id, device_ip, os_type, username,
                       scan_date, threat_score, threat_category
                FROM scans
                ORDER BY id DESC
            """).fetchall()
        return [dict(row) for row in rows]

    except Exception:
        logger.exception("Error fetching scans")
        raise HTTPException(status_code=500, detail="Internal server error")


# =====================================================
# Get Single Scan
# =====================================================

@app.get("/scans/{scan_id}")
async def get_scan(scan_id: int):
    try:
        with get_db_connection() as conn:
            row = conn.execute("""
                SELECT * FROM scans WHERE id=?
            """, (scan_id,)).fetchone()

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
            "results": json.loads(row["findings"]),
            "recommendations": json.loads(row["recommendations"]),
        }

    except HTTPException:
        raise

    except Exception:
        logger.exception("Error fetching scan")
        raise HTTPException(status_code=500, detail="Internal server error")


# =====================================================
# Delete Scan
# =====================================================

@app.delete("/scans/{scan_id}")
async def delete_scan(scan_id: int):
    try:
        with get_db_connection() as conn:
            conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return {"message": "Scan deleted successfully"}

    except Exception:
        logger.exception("Error deleting scan")
        raise HTTPException(status_code=500, detail="Internal server error")


# =====================================================
# PDF Download
# =====================================================
def generate_recommendation(result: dict) -> str:
    status = result.get("scan_status")
    cvss = result.get("cvss_score")

    try:
        cvss = float(cvss)
    except (TypeError, ValueError):
        cvss = 0.0

    # ==============================
    # FAIL = Immediate Fix
    # ==============================
    if status == "Fail":
        return (
            "Security control is misconfigured or disabled. "
            "Immediate remediation required. Review system configuration, "
            "apply security hardening standards, and validate settings."
        )

    # ==============================
    # PASS + CVSS BASED LOGIC
    # ==============================
    if status == "Pass":

        if cvss < 4:
            return (
                "Control is properly configured. Risk exposure is minimal. "
                "Continue routine monitoring and periodic security review."
            )

        elif 4 <= cvss <= 6:
            return (
                "Control is active but moderate exposure detected. "
                "Review security posture, validate configuration, and ensure "
                "latest updates and patches are applied."
            )

        elif cvss > 7:
            return (
                "Control is enabled but associated with high-risk exposure. "
                "Immediate security review recommended. Reduce attack surface "
                "and implement additional compensating controls."
            )

    return "Further security validation recommended."

from fastapi import HTTPException
from fastapi.responses import StreamingResponse
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.pagesizes import A4
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics
from io import BytesIO
import json


@app.get("/download_pdf/{scan_id}")
async def download_pdf(scan_id: int):
    try:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE id=?",
                (scan_id,)
            ).fetchone()

        if not row:
            raise HTTPException(status_code=404, detail="Scan not found")

        findings = json.loads(row["findings"])

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        elements = []

        styles = getSampleStyleSheet()
        normal_style = styles["Normal"]

        # =============================
        # TITLE
        # =============================
        elements.append(
            Paragraph("<b>ThreatScope Cloud Endpoint Security Report</b>", styles["Title"])
        )
        elements.append(Spacer(1, 0.3 * inch))

        # =============================
        # SUMMARY TABLE
        # =============================
        summary_data = [
            ["Device", row["device_ip"]],
            ["Operating System", row["os_type"]],
            ["Threat Score", str(row["threat_score"])],
            ["Risk Level", row["threat_category"]],
            ["Scan Date", row["scan_date"]],
        ]

        summary_table = Table(summary_data, colWidths=[2.2 * inch, 3.8 * inch])
        summary_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))

        elements.append(summary_table)
        elements.append(Spacer(1, 0.5 * inch))

        # =============================
        # FINDINGS HEADER
        # =============================
        elements.append(
            Paragraph("<b>Detailed Security Findings</b>", styles["Heading2"])
        )
        elements.append(Spacer(1, 0.3 * inch))

        # =============================
        # TABLE HEADER
        # =============================
        table_data = [
            ["Check", "Status", "Severity", "CVSS", "Recommendation"]
        ]

        # =============================
        # ADD FINDINGS WITH LOGIC
        # =============================
        for result in findings:
            recommendation = generate_recommendation(result)

            table_data.append([
                Paragraph(result.get("check", ""), normal_style),
                result.get("scan_status", ""),
                result.get("severity", ""),
                str(result.get("cvss_score", "")),
                Paragraph(recommendation, normal_style),
            ])

        findings_table = Table(
            table_data,
            colWidths=[1.3 * inch, 0.9 * inch, 0.9 * inch, 0.6 * inch, 2.3 * inch],
            repeatRows=1
        )

        # =============================
        # TABLE STYLING
        # =============================
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#002b45")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ]

        # Severity-based row coloring
        for i, result in enumerate(findings, start=1):
            severity = (result.get("severity") or "").lower()

            if severity == "high":
                style_commands.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#ffe5e5"))
                )
            elif severity == "medium":
                style_commands.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fff8dc"))
                )
            elif severity == "low":
                style_commands.append(
                    ("BACKGROUND", (0, i), (-1, i), colors.HexColor("#e6f2ff"))
                )

        findings_table.setStyle(TableStyle(style_commands))
        elements.append(findings_table)

        # =============================
        # BUILD PDF
        # =============================
        doc.build(elements)
        buffer.seek(0)

        return StreamingResponse(
            buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=ThreatScope_Report_{scan_id}.pdf"
            },
        )

    except HTTPException:
        raise

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
