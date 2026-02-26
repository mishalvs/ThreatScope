from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from enum import Enum
from pydantic import BaseModel
from scanner import run_scan
from datetime import datetime
from pathlib import Path
import logging
import re
import json

# =====================================================
# App Initialization
# =====================================================

app = FastAPI(title="Cloud Endpoint Security Scanner API")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# =====================================================
# CORS Configuration
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # change in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =====================================================
# OS Enum (Cleaner Validation)
# =====================================================

class OSType(str, Enum):
    linux = "linux"
    windows = "windows"

# =====================================================
# Utility Functions
# =====================================================

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

def sanitize_ip(ip: str) -> str:
    """
    Basic IP validation (IPv4 only).
    """
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    if not re.match(pattern, ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    return ip

def save_report(data: dict, ip: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = REPORT_DIR / f"{ip}_{timestamp}.json"

    with filename.open("w") as f:
        json.dump(data, f, indent=4)

    return str(filename)

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
        ip = sanitize_ip(ip)

        logger.info(f"Starting scan for {ip} ({os_type})")

        scan_data = run_scan(
            os_type=os_type.value,
            ip=ip,
            username=username,
            password=password
        )

        if scan_data.get("threat_level") == "ScanFailed":
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "failed",
                    "error": scan_data.get("error"),
                    "device": ip,
                    "os": os_type
                }
            )

        report_file = save_report(scan_data, ip)

        return {
            "status": "success",
            "device": scan_data.get("device"),
            "os": scan_data.get("os"),
            "date": scan_data.get("date"),
            "threat_level": scan_data.get("threat_level"),
            "results": scan_data.get("results"),
            "report_file": report_file
        }

    except HTTPException:
        raise

    except Exception as e:
        logger.exception("Unexpected error during scan")
        raise HTTPException(
            status_code=500,
            detail="Internal server error"
        )
