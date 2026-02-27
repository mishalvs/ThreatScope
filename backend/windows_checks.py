# =====================================================
# ThreatScope - Windows Security Checks (Professional Edition)
# =====================================================

# -----------------------------------------------------
# Standard Result Builder
# -----------------------------------------------------
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


# -----------------------------------------------------
# Safe PowerShell Runner
# -----------------------------------------------------
def run_ps(session, command):
    r = session.run_ps(command)

    if r.status_code != 0:
        error_msg = r.std_err.decode(errors="ignore").strip()
        return None, error_msg or "PowerShell command failed"

    output = r.std_out.decode(errors="ignore").strip()
    return output, None


# =====================================================
# BASIC HARDENING CHECKS
# =====================================================

def check_defender(session):
    out, err = run_ps(session, "(Get-MpComputerStatus).AMRunning")
    if err or not out:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out.lower() != "true"

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-693",
        cvss_score=8.0 if vulnerable else None,
        details=f"Defender Running: {out}"
    )


def check_firewall(session):
    out, err = run_ps(session,
        "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    disabled = int(out) if out and out.isdigit() else 0
    vulnerable = disabled > 0

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-284",
        cvss_score=7.5 if vulnerable else None,
        details=f"{disabled} firewall profile(s) disabled"
    )


def check_smbv1(session):
    out, err = run_ps(session,
        "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out.lower() != "disabled"

    return _result(
        vulnerable=vulnerable,
        severity="Critical",
        cve_id="CVE-2017-0144",
        cvss_score=9.8 if vulnerable else None,
        details=f"SMBv1 State: {out}"
    )


def check_rdp_nla(session):
    out, err = run_ps(session,
        "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out != "1"

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-284",
        cvss_score=8.5 if vulnerable else None,
        details=f"NLA Value: {out}"
    )


def check_updates(session):
    out, err = run_ps(session,
        "(New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher().Search('IsInstalled=0').Updates.Count")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    pending = int(out) if out and out.isdigit() else 0
    vulnerable = pending > 0

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="Multiple-CVE",
        cvss_score=6.5 if vulnerable else None,
        details=f"{pending} update(s) pending"
    )


def check_ps_logging(session):
    out, err = run_ps(session,
        "(Get-ItemProperty HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out != "1"

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-778",
        cvss_score=5.5 if vulnerable else None,
        details=f"Logging Enabled: {out}"
    )


def check_guest_account(session):
    out, err = run_ps(session, "(Get-LocalUser -Name Guest).Enabled")
    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out.lower() == "true"

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-250",
        cvss_score=7.0 if vulnerable else None,
        details=f"Guest Enabled: {out}"
    )


# =====================================================
# ADVANCED HARDENING CHECKS
# =====================================================

def check_weak_accounts(session):
    out, err = run_ps(session,
        "Get-LocalUser | Where-Object {$_.Enabled -eq $true -and $_.PasswordRequired -eq $false} | Select-Object -ExpandProperty Name")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = bool(out)

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-521",
        cvss_score=8.0 if vulnerable else None,
        details=out
    )


def check_unencrypted_shares(session):
    out, err = run_ps(session,
        "Get-SmbShare | Where-Object {$_.EncryptData -eq $false -and $_.Name -ne 'IPC$'} | Select-Object -ExpandProperty Name")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = bool(out)

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-311",
        cvss_score=6.8 if vulnerable else None,
        details=out
    )


def check_smb_signing(session):
    out, err = run_ps(session,
        "(Get-SmbServerConfiguration).RequireSecuritySignature")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out.lower() == "false"

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-311",
        cvss_score=6.5 if vulnerable else None,
        details=f"Signing Required: {out}"
    )


def check_uac_bypass(session):
    out, err = run_ps(session,
        "(Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System').ConsentPromptBehaviorAdmin")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = out == "0"

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-264",
        cvss_score=8.0 if vulnerable else None,
        details=f"UAC Level: {out}"
    )


def check_critical_services(session):
    services = ["wuauserv", "bits", "winrm"]
    stopped = []

    for svc in services:
        out, _ = run_ps(session, f"(Get-Service {svc}).Status")
        if out.lower() != "running":
            stopped.append(svc)

    vulnerable = bool(stopped)

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-264",
        cvss_score=8.0 if vulnerable else None,
        details=", ".join(stopped)
    )


def check_listening_services(session):
    out, err = run_ps(session,
        "Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'} | Select-Object -ExpandProperty LocalPort")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    risky_ports = {"21", "23", "69"}
    ports = set(out.splitlines())

    vulnerable = bool(risky_ports.intersection(ports))

    return _result(
        vulnerable=vulnerable,
        severity="High",
        cve_id="CWE-284",
        cvss_score=8.0 if vulnerable else None,
        details=", ".join(risky_ports.intersection(ports))
    )


def check_weak_password_policy(session):
    out, err = run_ps(session,
        "(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters').MaximumPasswordAge")

    if err:
        return _result("CheckFailed", error_type="ExecutionError", details=err)

    vulnerable = False

    try:
        days = int(out)
        if days > 90:
            vulnerable = True
    except:
        pass

    return _result(
        vulnerable=vulnerable,
        severity="Medium",
        cve_id="CWE-521",
        cvss_score=6.5 if vulnerable else None,
        details=f"Max Password Age: {out} days"
    )
