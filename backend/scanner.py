import linux_checks
import windows_checks
from utils import ssh_connect, winrm_connect
from datetime import datetime


# =====================================================
# Check Registries
# =====================================================

LINUX_CHECKS = [
    ("L-01", "SSH Root Login Disabled", linux_checks.check_ssh_root),
    ("L-02", "SSH Password Auth Disabled", linux_checks.check_ssh_password),
    ("L-03", "Firewall Enabled", linux_checks.check_firewall),
    ("L-04", "Default Firewall Deny", linux_checks.check_firewall_default),
    ("L-05", "Pending Updates", linux_checks.check_updates),
    ("L-06", "UFW Logging Enabled", linux_checks.check_ufw_logging),
    ("L-07", "World Writable Files", linux_checks.check_world_writable),
]

WINDOWS_CHECKS = [
    ("W-01", "Windows Defender Enabled", windows_checks.check_defender),
    ("W-02", "Firewall Enabled", windows_checks.check_firewall),
    ("W-03", "SMBv1 Disabled", windows_checks.check_smbv1),
    ("W-04", "RDP NLA Enabled", windows_checks.check_rdp_nla),
    ("W-05", "Pending Updates", windows_checks.check_updates),
    ("W-06", "PowerShell Logging Enabled", windows_checks.check_ps_logging),
    ("W-07", "Guest Account Disabled", windows_checks.check_guest_account),
]


# =====================================================
# Common Failure Result Builder
# =====================================================

def build_failed_result(error_message):
    return {
        "scan_status": "CheckFailed",
        "vulnerable": None,
        "severity": None,
        "cve_id": None,
        "cvss_score": None,
        "error_type": "UnknownError",
        "details": str(error_message)
    }


# =====================================================
# Linux Scan
# =====================================================

def scan_linux(ip, username, password=None, key_file=None):
    client = None
    results = []

    try:
        client = ssh_connect(ip, username, password, key_file)

        for cid, name, func in LINUX_CHECKS:
            try:
                result = func(client)
            except Exception as e:
                result = build_failed_result(e)

            results.append({
                "id": cid,
                "check": name,
                **result
            })

        return results

    finally:
        if client:
            client.close()


# =====================================================
# Windows Scan
# =====================================================

def scan_windows(ip, username, password):
    session = None
    results = []

    try:
        session = winrm_connect(ip, username, password)

        # Validate authentication
        test = session.run_cmd("whoami")
        if test.status_code != 0:
            raise RuntimeError("Authentication failed")

        for cid, name, func in WINDOWS_CHECKS:
            try:
                result = func(session)
            except Exception as e:
                result = build_failed_result(e)

            results.append({
                "id": cid,
                "check": name,
                **result
            })

        return results

    finally:
        if session:
            try:
                session.close()
            except Exception:
                pass


# =====================================================
# Threat Scoring Engine
# =====================================================

def calculate_threat(results):
    total_cvss = 0
    vuln_count = 0

    for r in results:
        if r.get("scan_status") == "Pass" and r.get("vulnerable") is True:
            cvss = r.get("cvss_score")
            if isinstance(cvss, (int, float)):
                total_cvss += cvss
                vuln_count += 1

    if vuln_count == 0:
        return 0, "Secure"

    avg_cvss = total_cvss / vuln_count
    percent_score = round(avg_cvss * 10)

    if avg_cvss >= 8:
        category = "Critical"
    elif avg_cvss >= 6:
        category = "High"
    elif avg_cvss >= 4:
        category = "Medium"
    else:
        category = "Low"

    return percent_score, category


# =====================================================
# Main Scan Orchestrator
# =====================================================

def run_scan(os_type, ip, username, password=None, key_file=None):
    os_type = os_type.lower()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        if os_type == "linux":
            results = scan_linux(ip, username, password, key_file)

        elif os_type == "windows":
            results = scan_windows(ip, username, password)

        else:
            raise ValueError("Unsupported OS")

        threat_score, threat_category = calculate_threat(results)

        return {
            "device": ip,
            "os": os_type,
            "username": username,
            "date": timestamp,
            "threat_score": threat_score,
            "threat_category": threat_category,
            "results": results
        }

    except Exception as e:
        return {
            "device": ip,
            "os": os_type,
            "username": username,
            "date": timestamp,
            "threat_score": 0,
            "threat_category": "ScanFailed",
            "error": str(e),
            "results": []
        }
