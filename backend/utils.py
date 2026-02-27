import paramiko
import winrm
import socket
import requests


# ==================================================
# SSH CONNECTION (Linux)
# ==================================================

def ssh_connect(ip, username, password=None, key_file=None, port=22, strict_host_key=False):
    """
    Establish SSH connection to Linux host.
    Supports password or private key authentication.
    """

    try:
        client = paramiko.SSHClient()

        if strict_host_key:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        else:
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_args = {
            "hostname": ip,
            "port": port,
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

    except paramiko.AuthenticationException:
        raise RuntimeError("AuthFailure: Invalid SSH credentials")

    except socket.timeout:
        raise RuntimeError("ConnectionTimeout: SSH connection timed out")

    except socket.gaierror:
        raise RuntimeError("ConnectionError: Invalid hostname")

    except ConnectionRefusedError:
        raise RuntimeError("ConnectionRefused: SSH port closed")

    except Exception as e:
        raise RuntimeError(f"UnknownError: {str(e)}")


# ==================================================
# WINRM CONNECTION (Windows)
# ==================================================

def winrm_connect(ip, username, password, use_https=False):
    """
    Establish WinRM connection to Windows host using NTLM.
    """

    try:
        if not username or not password:
            raise RuntimeError("AuthFailure: Username or password missing")

        protocol = "https" if use_https else "http"
        port = 5986 if use_https else 5985

        session = winrm.Session(
            f"{protocol}://{ip}:{port}/wsman",
            auth=(username, password),
            transport="ntlm",
            read_timeout_sec=30,
            operation_timeout_sec=20
        )

        # Validate authentication
        test = session.run_cmd("whoami")
        if test.status_code != 0:
            raise RuntimeError("AuthFailure: Invalid WinRM credentials")

        return session

    except winrm.exceptions.InvalidCredentialsError:
        raise RuntimeError("AuthFailure: Invalid WinRM credentials")

    except requests.exceptions.ConnectTimeout:
        raise RuntimeError("ConnectionTimeout: WinRM connection timed out")

    except requests.exceptions.ConnectionError:
        raise RuntimeError("ConnectionTimeout: WinRM host unreachable")

    except Exception as e:
        raise RuntimeError(f"UnknownError: {str(e)}")
