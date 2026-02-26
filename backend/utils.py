import paramiko
import winrm
import socket
import requests


# ==================================================
# SSH CONNECTION (Linux)
# ==================================================

def ssh_connect(ip, username, password=None, key_file=None):
    """
    Establish SSH connection to Linux host.
    Supports password or private key authentication.

    Returns:
        paramiko.SSHClient object

    Raises:
        RuntimeError with classified error message
    """

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_args = {
            "hostname": ip,
            "username": username,
            "timeout": 20,
            "look_for_keys": False,
            "allow_agent": False
        }

        if key_file:
            connect_args["key_filename"] = key_file
        elif password:
            connect_args["password"] = password
        else:
            raise RuntimeError("AuthFailure: No authentication method provided")

        client.connect(**connect_args)
        return client

    # 🔐 Invalid credentials
    except paramiko.AuthenticationException:
        raise RuntimeError("AuthFailure: Invalid SSH credentials")

    # ⏳ Timeout
    except socket.timeout:
        raise RuntimeError("ConnectionTimeout: SSH connection timed out")

    # ❌ Host unreachable / port closed
    except socket.error:
        raise RuntimeError("ConnectionTimeout: Host unreachable or port closed")

    # 🧨 Unknown errors
    except Exception as e:
        raise RuntimeError(f"UnknownError: {str(e)}")


# ==================================================
# WINRM CONNECTION (Windows)
# ==================================================

def winrm_connect(ip, username, password):
    """
    Establish WinRM connection to Windows host using NTLM.

    Returns:
        winrm.Session object

    Raises:
        RuntimeError with classified error message
    """

    try:
        if not username or not password:
            raise RuntimeError("AuthFailure: Username or password missing")

        session = winrm.Session(
            f"http://{ip}:5985/wsman",
            auth=(username, password),
            transport="ntlm"
        )

        # Validate authentication
        test = session.run_cmd("whoami")

        if test.status_code != 0:
            raise RuntimeError("AuthFailure: Invalid WinRM credentials")

        return session

    # 🔐 Invalid credentials
    except winrm.exceptions.InvalidCredentialsError:
        raise RuntimeError("AuthFailure: Invalid WinRM credentials")

    # ⏳ Timeout
    except requests.exceptions.ConnectTimeout:
        raise RuntimeError("ConnectionTimeout: WinRM connection timed out")

    except requests.exceptions.ConnectionError:
        raise RuntimeError("ConnectionTimeout: WinRM host unreachable")

    # 🧨 Unknown errors
    except Exception as e:
        raise RuntimeError(f"UnknownError: {str(e)}")
