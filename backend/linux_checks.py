# =====================================================
# Linux Security Checks (Cleaned & Production Ready)
# =====================================================

from functools import wraps


# =====================================================
# Common Result Formatter
# =====================================================

def _result(
    scan_status,
    vulnerable=None,
    severity=None,
    cve_id=None,
    cvss_score=None,
    error_type=None,
    details=""
):
    """
    scan_status:
        - Pass               -> Check executed successfully
        - CheckFailed        -> Could not execute properly
        - PermissionDenied   -> Insufficient privileges
        - AuthFailure        -> SSH authentication failed
        - UnknownError       -> Unexpected failure

    vulnerable:
        True / False only if scan_status == "Pass"
        None otherwise
    """

    # Enforce consistency
    if scan_status != "Pass":
        vulnerable = None
        severity = None
        cvss_score = None

    return {
        "scan_status": scan_status,
        "vulnerable": vulnerable,
        "severity": severity,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "error_type": error_type,
        "details": details or ""
    }


# =====================================================
# Safe Command Runner
# =====================================================

def run_cmd(client, command, timeout=15):
    """
    Executes remote command safely with timeout protection.
    """
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)

    output = stdout.read().decode(errors="ignore").strip()
    error = stderr.read().decode(errors="ignore").strip()

    return output, error


# =====================================================
# Error Handling Decorator
# =====================================================

def safe_check(func):
    @wraps(func)
    def wrapper(client):
        try:
            return func(client)
        except Exception as e:
            return _result(
                scan_status="UnknownError",
                error_type="UnknownError",
                details=str(e)
            )
    return wrapper


# =====================================================
# SSH CHECKS
# =====================================================

@safe_check
def check_ssh_root(client):
    out, err = run_cmd(client, "grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config")

    if "permission denied" in err.lower():
        return _result("PermissionDenied", error_type="PermissionDenied", details=err)

    if not out:
        return _result("CheckFailed", error_type="CheckFailed",
                       details="PermitRootLogin directive not found")

    vulnerable = "no" not in out.lower()

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="High" if vulnerable else "Low",
        cve_id="CWE-250",
        cvss_score=8.0 if vulnerable else None
    )


@safe_check
def check_ssh_password(client):
    out, err = run_cmd(client, "grep -Ei '^PasswordAuthentication' /etc/ssh/sshd_config")

    if "permission denied" in err.lower():
        return _result("PermissionDenied", error_type="PermissionDenied", details=err)

    if not out:
        return _result("CheckFailed", error_type="CheckFailed",
                       details="PasswordAuthentication directive not found")

    vulnerable = "no" not in out.lower()

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="High" if vulnerable else "Low",
        cve_id="CWE-307",
        cvss_score=7.5 if vulnerable else None
    )


# =====================================================
# FIREWALL CHECKS (Multi-Distro Aware)
# =====================================================

@safe_check
def check_firewall(client):
    # Check UFW first
    out, _ = run_cmd(client, "which ufw")
    if out:
        status, _ = run_cmd(client, "ufw status")
        if not status:
            return _result("CheckFailed", error_type="CheckFailed",
                           details="Unable to retrieve UFW status")

        vulnerable = "inactive" in status.lower()

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="High" if vulnerable else "Low",
            cve_id="CWE-284",
            cvss_score=7.0 if vulnerable else None,
            details="UFW firewall check"
        )

    # Check firewalld
    out, _ = run_cmd(client, "systemctl is-active firewalld")
    if "active" in out.lower():
        return _result(
            scan_status="Pass",
            vulnerable=False,
            severity="Low",
            details="firewalld active"
        )

    # No firewall detected
    return _result(
        scan_status="Pass",
        vulnerable=True,
        severity="High",
        cve_id="CWE-284",
        cvss_score=7.0,
        details="No active firewall detected"
    )


@safe_check
def check_firewall_default(client):
    out, err = run_cmd(client, "ufw status verbose")

    if not out:
        return _result("CheckFailed", error_type="CheckFailed",
                       details="UFW not accessible")

    vulnerable = "default: deny" not in out.lower()

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="High" if vulnerable else "Low",
        cve_id="CWE-276",
        cvss_score=6.5 if vulnerable else None
    )


# =====================================================
# UPDATE CHECK
# =====================================================

@safe_check
def check_updates(client):
    out, _ = run_cmd(
        client,
        "apt list --upgradable 2>/dev/null | grep -v Listing"
    )

    vulnerable = bool(out)

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="Medium" if vulnerable else "Low",
        cve_id="Multiple-CVE",
        cvss_score=6.0 if vulnerable else None,
        details="Pending system updates detected" if vulnerable else ""
    )


# =====================================================
# UFW LOGGING CHECK
# =====================================================

@safe_check
def check_ufw_logging(client):
    out, err = run_cmd(client, "ufw status verbose")

    if not out:
        return _result("CheckFailed", error_type="CheckFailed",
                       details="UFW not accessible")

    vulnerable = "logging: on" not in out.lower()

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="Medium" if vulnerable else "Low",
        cve_id="CWE-778",
        cvss_score=5.5 if vulnerable else None
    )


# =====================================================
# WORLD WRITABLE FILE CHECK
# =====================================================

@safe_check
def check_world_writable(client):
    out, _ = run_cmd(
        client,
        "find / -xdev -type f -perm -0002 2>/dev/null | head -n 5"
    )

    vulnerable = bool(out)

    return _result(
        scan_status="Pass",
        vulnerable=vulnerable,
        severity="High" if vulnerable else "Low",
        cve_id="CWE-732",
        cvss_score=8.5 if vulnerable else None,
        details=out if vulnerable else ""
    )
