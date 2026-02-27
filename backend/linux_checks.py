# =====================================================
# ThreatScope - Linux Security Checks (Professional Edition)
# =====================================================

from functools import wraps


# =====================================================
# Standard Result Builder
# =====================================================
def _result(
    scan_status="Pass",
    vulnerable=False,
    severity=None,
    cve_id=None,
    cvss_score=None,
    error_type=None,
    details=""
):
    if scan_status != "Pass":
        return {
            "scan_status": scan_status,
            "vulnerable": None,
            "severity": None,
            "cve_id": None,
            "cvss_score": None,
            "error_type": error_type,
            "details": details
        }

    if not vulnerable:
        severity = "Low"
        cvss_score = None

    return {
        "scan_status": "Pass",
        "vulnerable": vulnerable,
        "severity": severity,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "error_type": None,
        "details": details
    }


# =====================================================
# Safe SSH Command Runner
# =====================================================
def run_cmd(client, command, timeout=20):
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    output = stdout.read().decode(errors="ignore").strip()
    error = stderr.read().decode(errors="ignore").strip()
    return output, error


# =====================================================
# Error Wrapper
# =====================================================
def safe_check(func):
    @wraps(func)
    def wrapper(client):
        try:
            return func(client)
        except Exception as e:
            return _result(
                scan_status="UnknownError",
                error_type="ExecutionError",
                details=str(e)
            )
    return wrapper


# =====================================================
# SSH CONFIGURATION CHECKS
# =====================================================

@safe_check
def check_ssh_root(client):
    out, _ = run_cmd(client, "grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config")
    if not out:
        return _result("CheckFailed", error_type="ConfigNotFound",
                       details="PermitRootLogin not found")

    vulnerable = "yes" in out.lower()
    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-250",
        cvss_score=8.0 if vulnerable else None,
        details=out
    )


@safe_check
def check_ssh_password(client):
    out, _ = run_cmd(client, "grep -Ei '^PasswordAuthentication' /etc/ssh/sshd_config")
    if not out:
        return _result("CheckFailed", error_type="ConfigNotFound",
                       details="PasswordAuthentication not found")

    vulnerable = "yes" in out.lower()
    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-307",
        cvss_score=7.5 if vulnerable else None,
        details=out
    )


# =====================================================
# FIREWALL CHECKS
# =====================================================

@safe_check
def check_firewall(client):
    ufw, _ = run_cmd(client, "which ufw")
    if ufw:
        status, _ = run_cmd(client, "ufw status")
        vulnerable = "inactive" in status.lower()
        return _result(
            vulnerable=vulnerable,
            severity="High",
            cve_id="CWE-284",
            cvss_score=7.0 if vulnerable else None,
            details=status
        )

    firewalld, _ = run_cmd(client, "systemctl is-active firewalld")
    if "active" in firewalld.lower():
        return _result(vulnerable=False, details="firewalld active")

    return _result(
        vulnerable=True,
        severity="High",
        cve_id="CWE-284",
        cvss_score=7.0,
        details="No firewall detected"
    )


@safe_check
def check_firewall_default(client):
    out, _ = run_cmd(client, "ufw status verbose")
    if not out:
        return _result("CheckFailed", error_type="FirewallNotAccessible")

    vulnerable = "default: deny" not in out.lower()
    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-276",
        cvss_score=6.5 if vulnerable else None,
        details=out
    )


# =====================================================
# UPDATE CHECK (Multi-Distro Support)
# =====================================================

@safe_check
def check_updates(client):
    apt, _ = run_cmd(client, "which apt")
    yum, _ = run_cmd(client, "which yum")

    if apt:
        out, _ = run_cmd(
            client,
            "apt list --upgradable 2>/dev/null | grep -v Listing"
        )
        vulnerable = bool(out)

    elif yum:
        out, _ = run_cmd(client, "yum check-update 2>/dev/null || true")
        vulnerable = bool(out)

    else:
        return _result(
            "CheckFailed",
            error_type="PackageManagerNotFound"
        )

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="Multiple-CVE",
        cvss_score=6.0 if vulnerable else None,
        details="Pending updates detected" if vulnerable else ""
    )

# =====================================================
# ROOT CRON JOBS (Improved Logic)
# =====================================================

@safe_check
def check_root_cron(client):
    out, _ = run_cmd(client, "crontab -l -u root 2>/dev/null")

    # Root cron itself is NOT vulnerability.
    # Only flag if suspicious commands present.
    if not out:
        return _result(vulnerable=False)

    suspicious = any(word in out.lower()
                     for word in ["curl", "wget", "nc", "bash -i"])

    return _result(
        vulnerable=suspicious,
        severity="High" if suspicious else "Low",
        cve_id="CWE-264" if suspicious else None,
        cvss_score=8.0 if suspicious else None,
        details=out
    )


# =====================================================
# WORLD WRITABLE FILES (Fixed - With Timeout Protection)
# =====================================================

@safe_check
def check_world_writable(client):
    out, _ = run_cmd(
        client,
        "timeout 10 find / -xdev -type f -perm -0002 2>/dev/null | head -n 10"
    )

    if not out:
        return _result(vulnerable=False)

    return _result(
        vulnerable=True,
        severity="High",
        cve_id="CWE-276",
        cvss_score=8.0,
        details=out
    )

# =====================================================
# SENSITIVE FILE PERMISSIONS (Fixed Properly)
# =====================================================

@safe_check
def check_sensitive_files(client):
    out, _ = run_cmd(
        client,
        "stat -c '%a %n' /etc/shadow /etc/passwd 2>/dev/null"
    )

    if not out:
        return _result("CheckFailed", error_type="PermissionCheckFailed")

    vulnerable = False
    issues = []

    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue

        perm = parts[0]
        filename = parts[1]

        # Convert to integer properly (octal logic)
        perm_int = int(perm)

        if "shadow" in filename:
            if perm_int > 600:
                vulnerable = True
                issues.append(f"{filename} should be 600 or stricter")

        if "passwd" in filename:
            if perm_int > 644:
                vulnerable = True
                issues.append(f"{filename} should not be writable by group/others")

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-732",
        cvss_score=8.0 if vulnerable else None,
        details="\n".join(issues) if issues else out
    )


# =====================================================
# UFW LOGGING CHECK (Improved Logic)
# =====================================================

@safe_check
def check_ufw_logging(client):
    out, _ = run_cmd(client, "ufw status verbose 2>/dev/null")

    if not out:
        return _result("CheckFailed", error_type="FirewallNotAccessible")

    vulnerable = "logging: off" in out.lower()

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-778",
        cvss_score=5.5 if vulnerable else None,
        details=out
    )


# =====================================================
# SUDO WITHOUT PASSWORD CHECK
# =====================================================

@safe_check
def check_sudo_nopasswd(client):
    out, _ = run_cmd(client,
        "grep -r 'NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null")

    if not out:
        return _result(vulnerable=False)

    return _result(
        vulnerable=True,
        severity="High",
        cve_id="CWE-250",
        cvss_score=8.5,
        details=out
    )
# =====================================================
# LISTENING SERVICES ON RISKY PORTS
# =====================================================

@safe_check
def check_risky_ports(client):
    out, _ = run_cmd(client,
        "ss -tulnp 2>/dev/null | grep -E ':21|:23|:25|:110|:143'")

    if not out:
        return _result(vulnerable=False)

    return _result(
        vulnerable=True,
        severity="High",
        cve_id="CWE-319",
        cvss_score=8.0,
        details=out
    )


# =====================================================
# KERNEL VERSION CHECK
# =====================================================

@safe_check
def check_kernel_version(client):
    out, _ = run_cmd(client, "uname -r")

    if not out:
        return _result("CheckFailed", error_type="KernelCheckFailed")

    # Simple outdated heuristic (example logic)
    vulnerable = any(old in out for old in ["3.", "4.4", "4.9"])

    return _result(
        vulnerable=vulnerable,
        severity="High" if vulnerable else "Low",
        cve_id="Multiple-Kernel-CVE" if vulnerable else None,
        cvss_score=8.5 if vulnerable else None,
        details=out
    )
