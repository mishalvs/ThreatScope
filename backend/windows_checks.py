# =====================================================
# Windows Security Checks (Enterprise Clean Version)
# =====================================================

# ---------------------------
# Common Result Formatter
# ---------------------------

def _result(
    scan_status,
    vulnerable=None,
    severity=None,
    cve_id=None,
    cvss_score=None,
    error_type=None,
    details=""
):
    return {
        "scan_status": scan_status,
        "vulnerable": vulnerable,
        "severity": severity,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "error_type": error_type,
        "details": details or ""
    }


# ---------------------------
# Safe PowerShell Runner
# ---------------------------

def run_ps(session, command):
    """
    Executes PowerShell safely.
    Returns (output, error)
    """

    try:
        r = session.run_ps(command)

        if r.status_code != 0:
            error_msg = r.std_err.decode(errors="ignore").strip()
            return None, error_msg or "PowerShell command failed"

        output = r.std_out.decode(errors="ignore").strip()
        return output, None

    except Exception as e:
        raise Exception(f"PowerShell execution failed: {str(e)}")


# =====================================================
# WINDOWS DEFENDER
# =====================================================

def check_defender(session):
    try:
        out, err = run_ps(
            session,
            "(Get-MpComputerStatus).AMRunning"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        vulnerable = out.strip().lower() != "true"

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="High" if vulnerable else "Low",
            cve_id="CWE-693",
            cvss_score=8.5 if vulnerable else None,
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# FIREWALL
# =====================================================

def check_firewall(session):
    try:
        out, err = run_ps(
            session,
            "(Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}).Count"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        disabled_profiles = int(out or 0)
        vulnerable = disabled_profiles > 0

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="High" if vulnerable else "Low",
            cve_id="CWE-284",
            cvss_score=7.5 if vulnerable else None,
            details=f"{disabled_profiles} firewall profile(s) disabled" if vulnerable else ""
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# SMBv1
# =====================================================

def check_smbv1(session):
    try:
        out, err = run_ps(
            session,
            "(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol).State"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        vulnerable = out.strip().lower() != "disabled"

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="High" if vulnerable else "Low",
            cve_id="CVE-2017-0144",
            cvss_score=9.8 if vulnerable else None,
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# RDP NLA
# =====================================================

def check_rdp_nla(session):
    try:
        out, err = run_ps(
            session,
            "(Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp').UserAuthentication"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        vulnerable = out.strip() != "1"

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="High" if vulnerable else "Low",
            cve_id="CVE-2019-0708",
            cvss_score=9.8 if vulnerable else None,
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# WINDOWS UPDATES
# =====================================================

def check_updates(session):
    try:
        out, err = run_ps(
            session,
            "(New-Object -ComObject Microsoft.Update.Session)"
            ".CreateUpdateSearcher()"
            ".Search('IsInstalled=0').Updates.Count"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        pending = int(out or 0)
        vulnerable = pending > 0

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="Medium" if vulnerable else "Low",
            cve_id="Multiple-CVE",
            cvss_score=6.5 if vulnerable else None,
            details=f"{pending} update(s) pending" if vulnerable else ""
        )

    except ValueError:
        return _result("CheckFailed", error_type="ParsingError", details="Could not parse update count")

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# POWERSHELL LOGGING
# =====================================================

def check_ps_logging(session):
    try:
        out, err = run_ps(
            session,
            "(Get-ItemProperty "
            "HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging "
            "-ErrorAction SilentlyContinue).EnableScriptBlockLogging"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        vulnerable = out.strip() != "1"

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="Medium" if vulnerable else "Low",
            cve_id="CWE-778",
            cvss_score=5.5 if vulnerable else None,
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))


# =====================================================
# GUEST ACCOUNT
# =====================================================

def check_guest_account(session):
    try:
        out, err = run_ps(
            session,
            "(Get-LocalUser -Name Guest).Enabled"
        )

        if err:
            return _result("CheckFailed", error_type="CheckFailed", details=err)

        vulnerable = out.strip().lower() == "true"

        return _result(
            scan_status="Pass",
            vulnerable=vulnerable,
            severity="Medium" if vulnerable else "Low",
            cve_id="CWE-250",
            cvss_score=7.0 if vulnerable else None,
        )

    except Exception as e:
        return _result("UnknownError", error_type="UnknownError", details=str(e))
