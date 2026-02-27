from fastapi import FastAPI, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from enum import Enum
from scanner import run_scan
from datetime import datetime
from pathlib import Path
import logging
import ipaddress
import json

# =====================================================
# App Initialization
# =====================================================

app = FastAPI(title="ThreatScope Cloud Endpoint Security Scanner API")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("threatscope")

# =====================================================
# CORS Configuration
# =====================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # Change in production
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

def validate_ip(ip: str) -> str:
    """
    Strong IPv4 validation using ipaddress module.
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        if ip_obj.version != 4:
            raise ValueError("Only IPv4 supported")
        return str(ip_obj)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid IPv4 address")

def validate_input_length(value: str, field_name: str, max_length: int = 100):
    if len(value) > max_length:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} too long"
        )

def save_report(data: dict, ip: str) -> str:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_ip = ip.replace(".", "_")
    filename = REPORT_DIR / f"{safe_ip}_{timestamp}.json"

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
    password: str = Form(None),      # Optional (for Linux key-based)
    key_file: str = Form(None)       # Optional (Linux SSH key)
):
    try:
        # ==============================
        # Input Validation
        # ==============================
        ip = validate_ip(ip)

        validate_input_length(username, "Username")
        if password:
            validate_input_length(password, "Password", 200)

        logger.info(f"[SCAN START] Target={ip} OS={os_type}")

        # ==============================
        # Run Scan
        # ==============================
        scan_data = run_scan(
            os_type=os_type.value,
            ip=ip,
            username=username,
            password=password,
            key_file=key_file
        )

        # Normalize failure handling
        if scan_data.get("threat_category") == "ScanFailed":
            logger.error(f"[SCAN FAILED] {ip}")
            raise HTTPException(
                status_code=500,
                detail={
                    "status": "failed",
                    "error": scan_data.get("error"),
                    "device": ip,
                    "os": os_type.value
                }
            )

        # ==============================
        # Save Report
        # ==============================
        report_file = save_report(scan_data, ip)

        logger.info(f"[SCAN COMPLETE] Target={ip} Threat={scan_data.get('threat_category')}")

        return {
            "status": "success",
            "device": scan_data.get("device"),
            "os": scan_data.get("os"),
            "date": scan_data.get("date"),
            "threat_score": scan_data.get("threat_score"),
            "threat_category": scan_data.get("threat_category"),
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
