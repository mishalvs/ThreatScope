import linux_checks
import windows_checks
from utils import ssh_connect, winrm_connect
from datetime import datetime
import time


# =====================================================
# Linux Checks Registry
# =====================================================

LINUX_CHECKS = [
    ("L-01", "SSH Root Login", linux_checks.check_ssh_root),
    ("L-02", "SSH Password Authentication", linux_checks.check_ssh_password),
    ("L-03", "Firewall Enabled", linux_checks.check_firewall),
    ("L-04", "Default Firewall Policy", linux_checks.check_firewall_default),
    ("L-05", "Pending Updates", linux_checks.check_updates),
    ("L-06", "UFW Logging Enabled", linux_checks.check_ufw_logging),
    ("L-07", "World Writable Files", linux_checks.check_world_writable),
    ("L-08", "Sudo Without Password", linux_checks.check_sudo_nopasswd),
    ("L-09", "Root Cron Jobs", linux_checks.check_root_cron),
    ("L-10", "Sensitive File Permissions", linux_checks.check_sensitive_files),
    ("L-11", "Listening on Risky Ports", linux_checks.check_risky_ports),
    ("L-12", "Kernel Version Check", linux_checks.check_kernel_version),
]


# =====================================================
# Windows Checks Registry
# =====================================================

WINDOWS_CHECKS = [
    ("W-01", "Windows Defender Enabled", windows_checks.check_defender),
    ("W-02", "Firewall Enabled", windows_checks.check_firewall),
    ("W-03", "SMBv1 Disabled", windows_checks.check_smbv1),
    ("W-04", "RDP NLA Enabled", windows_checks.check_rdp_nla),
    ("W-05", "Pending Updates", windows_checks.check_updates),
    ("W-06", "PowerShell Logging Enabled", windows_checks.check_ps_logging),
    ("W-07", "Guest Account Disabled", windows_checks.check_guest_account),
    ("W-08", "Weak Local Accounts", windows_checks.check_weak_accounts),
    ("W-09", "Unencrypted SMB Shares", windows_checks.check_unencrypted_shares),
    ("W-10", "SMB Signing Enabled", windows_checks.check_smb_signing),
    ("W-11", "UAC Bypass", windows_checks.check_uac_bypass),
    ("W-12", "Critical Services Running", windows_checks.check_critical_services),
    ("W-13", "Listening Services on Risky Ports", windows_checks.check_listening_services),
    ("W-14", "Weak Password Policy", windows_checks.check_weak_password_policy),
]


# =====================================================
# Failure Result Builder
# =====================================================

def build_failed_result(error_message):
    return {
        "scan_status": "CheckFailed",
        "vulnerable": None,
        "severity": None,
        "cve_id": None,
        "cvss_score": None,
        "error_type": "ExecutionError",
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

        test = session.run_cmd("whoami")
        if test.status_code != 0:
            return [{
            "id": "AUTH",
            "check": "Authentication",
            "scan_status": "CheckFailed",
            "error_type": "AuthFailure",
        }]


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
# Improved Threat Scoring Engine
# =====================================================

def calculate_threat(results):
    total_cvss = 0
    total_valid_checks = 0
    vulnerability_count = 0
    failed_checks = 0

    for r in results:

        # Ignore failed checks completely
        if r.get("scan_status") != "Pass":
            failed_checks += 1
            continue

        total_valid_checks += 1

        cvss = r.get("cvss_score")

        # Only count real vulnerabilities
        if r.get("vulnerable") is True and isinstance(cvss, (int, float)):
            total_cvss += cvss
            vulnerability_count += 1

    if total_valid_checks == 0:
        return 0, "Secure", vulnerability_count, failed_checks

    # Maximum possible score = 10 per valid check
    max_possible = total_valid_checks * 10

    threat_score = round((total_cvss / max_possible) * 100)

    # Professional risk tiering
    if threat_score >= 75:
        category = "Critical"
    elif threat_score >= 50:
        category = "High"
    elif threat_score >= 25:
        category = "Medium"
    elif vulnerability_count == 0:
        category = "Secure"
    else:
        category = "Low"

    return threat_score, category, vulnerability_count, failed_checks


# =====================================================
# Main Orchestrator
# =====================================================

def run_scan(os_type, ip, username, password=None, key_file=None):
    os_type = os_type.lower()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    start_time = time.time()

    try:
        if os_type == "linux":
            results = scan_linux(ip, username, password, key_file)

        elif os_type == "windows":
            results = scan_windows(ip, username, password)

        else:
            raise ValueError("Unsupported OS")

        threat_score, threat_category, vuln_count, failed_count = calculate_threat(results)

        duration = round(time.time() - start_time, 2)

        return {
            "device": ip,
            "os": os_type,
            "username": username,
            "date": timestamp,
            "scan_duration_seconds": duration,
            "threat_score": threat_score,
            "threat_category": threat_category,
            "total_checks": len(results),
            "vulnerabilities_found": vuln_count,
            "checks_failed": failed_count,
            "results": results
        }

    except Exception as e:
        return {
            "device": ip,
            "os": os_type,
            "username": username,
            "date": timestamp,
            "scan_duration_seconds": 0,
            "threat_score": 0,
            "threat_category": "ScanFailed",
            "error": str(e),
            "results": []
        }
