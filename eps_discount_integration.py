import subprocess
import os
import shutil
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import platform
import socket
import logging
from logging import FileHandler, Formatter

# --- Cross-platform Windows remote management via impacket ---
# impacket is optional: enables WMI, SMB, and Task Scheduler
# operations from Linux (Docker) to remote Windows servers.
IMPACKET_AVAILABLE = False
try:
    from impacket.dcerpc.v5.dcomrt import DCOMConnection
    from impacket.dcerpc.v5.dcom import wmi as impacket_wmi
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5 import tsch, scmr, transport as impacket_transport
    from impacket.smbconnection import SMBConnection as ImpacketSMBConnection
    IMPACKET_AVAILABLE = True
except ImportError:
    pass

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# --- File-based category loggers (read, write, response, failure) ---
def setup_category_file_loggers(log_dir: str = None):
    """Create a single date-based log file with all categories writing sequentially.

    File created:
      - eps_discount_integration_service_log_YYYY-MM-DD.log
    """
    if log_dir is None:
        log_dir = get_env_pref("LOG_DIR", "logs")
    log_dir = os.path.abspath(log_dir)
    os.makedirs(log_dir, exist_ok=True)

    date = datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"eps_discount_integration_service_log_{date}.log")

    fmt = Formatter("%(asctime)s %(levelname)-8s [%(category)s] %(message)s")

    # Attach to root logger for general/combined logging
    root_filter = logging.Filter()
    root_filter.filter = lambda record: setattr(record, 'category', getattr(record, 'category', 'GENERAL')) or True
    shared_handler_root = FileHandler(log_file, encoding="utf-8")
    shared_handler_root.setFormatter(fmt)
    shared_handler_root.setLevel(logging.INFO)
    shared_handler_root.addFilter(root_filter)
    logging.getLogger().addHandler(shared_handler_root)

    # Category-specific loggers all writing to the same file
    category_loggers = {}
    for name in ("read", "write", "response", "failure"):
        lvl = logging.INFO if name in ("read", "write", "response") else logging.ERROR
        h = FileHandler(log_file, encoding="utf-8")
        h.setFormatter(fmt)
        h.setLevel(lvl)

        # Add filter to inject category into log records
        cat_label = name.upper()
        cat_filter = logging.Filter()
        cat_filter.filter = lambda record, cat=cat_label: setattr(record, 'category', cat) or True
        h.addFilter(cat_filter)

        lg = logging.getLogger(f"eps.{name}")
        lg.setLevel(lvl)
        lg.addHandler(h)
        lg.propagate = False
        category_loggers[name] = lg

    return category_loggers


# Initialize file loggers (will call get_env_pref defined below; order matters)
app = FastAPI(title="EPS Discount Service API", version="1.0.0")


# Lightweight .env loader
def load_dotenv(dotenv_path: str = ".env"):
    if not os.path.exists(dotenv_path):
        return
    try:
        with open(dotenv_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                os.environ.setdefault(key, val)
    except Exception:
        pass


def get_env_pref(key: str, default: Optional[str] = None) -> Optional[str]:
    """Prefer EPS_<KEY> then <KEY> from environment. Empty strings are treated as unset."""
    v = os.environ.get(f"EPS_{key}")
    if v:  # truthy check: empty string is treated as "not set"
        return v
    v = os.environ.get(key)
    if v:
        return v
    return default


# Load .env at startup
load_dotenv()

# Now safe to setup file loggers
_category_loggers = setup_category_file_loggers()
read_logger = _category_loggers.get("read")
write_logger = _category_loggers.get("write")
response_logger = _category_loggers.get("response")
failure_logger = _category_loggers.get("failure")

# ============== Startup/Shutdown Event Handlers ==============
@app.on_event("startup")
async def on_startup():
    """Log when FastAPI server is fully initialized."""
    startup_ready_msg = f"[SERVER_READY] EPS Discount Integration API is now running and ready to accept requests"
    logger.info(startup_ready_msg)
    if response_logger:
        response_logger.info(startup_ready_msg)
    # Log runtime mode so operator knows if Windows tools will be available
    try:
        system = platform.system().lower()
        in_container = os.path.exists("/.dockerenv") or os.environ.get("RUNNING_IN_CONTAINER") is not None
        powershell_exists = bool(shutil.which("powershell")) or bool(shutil.which("powershell.exe"))
        psexec_path = get_env_pref("PSEXEC_PATH")
        mode_msg = (
            f"[MODE] platform={system}; in_container={in_container}; powershell={powershell_exists}; "
            f"psexec_set={'yes' if psexec_path else 'no'}; impacket={IMPACKET_AVAILABLE}"
        )
        logger.info(mode_msg)
        if response_logger:
            response_logger.info(mode_msg)
    except Exception:
        pass

@app.on_event("shutdown")
async def on_shutdown():
    """Log when FastAPI server is shutting down."""
    shutdown_msg = f"[SERVER_SHUTDOWN] EPS Discount Integration API is shutting down"
    logger.info(shutdown_msg)
    if response_logger:
        response_logger.info(shutdown_msg)

# ============== Pydantic Models ==============
class ServerInfo(BaseModel):
    outlet_code: str
    ip_address: str

class DeploymentRequest(BaseModel):
    servers: List[ServerInfo]
    # Defaults removed for security. Supply per-request or via environment variables.
    source_file: Optional[str] = None
    destination_path: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None

# ============== Utility Functions ==============
def is_server_online(ip_address: str) -> bool:
    """Check if a server is reachable via ping"""
    try:
        system = platform.system().lower()
        # Windows uses -n, POSIX uses -c
        flag = "-n" if system == "windows" else "-c"
        cmd = f"ping {flag} 1 {ip_address}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        up = result.returncode == 0
        # verbose logging for diagnostics
        if read_logger:
            read_logger.info(
                f"Ping {ip_address} using '{cmd}' returned {result.returncode}; stdout={ (result.stdout or '').strip() } stderr={ (result.stderr or '').strip() }"
            )
        else:
            logger.debug(f"Ping {ip_address} cmd='{cmd}' rc={result.returncode}")

        if up:
            return True

        # If ping failed due to missing utility (common in minimal containers), try TCP port probes
        # rc==127 often indicates command not found on POSIX; handle generically
        ports = [445, 3389, 135]
        for p in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip_address, p))
                sock.close()
                if read_logger:
                    read_logger.info(f"TCP probe to {ip_address}:{p} succeeded (fallback reachability)")
                return True
            except Exception as e:
                if read_logger:
                    read_logger.info(f"TCP probe to {ip_address}:{p} failed: {e}")
                continue

        return False
    except Exception as e:
        logger.error(f"Error pinging {ip_address}: {e}")
        if failure_logger:
            failure_logger.exception(f"Ping error {ip_address}: {e}")
        return False

# ============== Cross-Platform Remote Windows Management Helpers ==============

def _wmi_check_process(ip_address: str, process_name: str, username: str, password: str):
    """Check if a process is running on a remote Windows server using WMI over DCOM.

    Requires: impacket library, remote ports 135 + dynamic RPC (49152-65535).

    Returns:
        True  -- process is running
        False -- process is NOT running (WMI query succeeded, no results)
        None  -- WMI query failed (connection error, auth error, etc.)
    """
    dcom = None
    try:
        if read_logger:
            read_logger.info(f"[WMI] Attempting DCOM connection to {ip_address} (user={username})...")

        dcom = DCOMConnection(
            ip_address,
            username=username,
            password=password,
            domain='',
            lmhash='',
            nthash='',
            oxidResolver=True,
        )
        iInterface = dcom.CoCreateInstanceEx(
            impacket_wmi.CLSID_WbemLevel1Login,
            impacket_wmi.IID_IWbemLevel1Login,
        )
        iWbemLevel1Login = impacket_wmi.IWbemLevel1Login(iInterface)
        iWbemServices = iWbemLevel1Login.NTLMLogin('//./root/cimv2', NULL, NULL)
        iWbemLevel1Login.RemRelease()

        wql = f"SELECT Name FROM Win32_Process WHERE Name = '{process_name}'"
        if read_logger:
            read_logger.info(f"[WMI] Executing query on {ip_address}: {wql}")

        iEnum = iWbemServices.ExecQuery(wql)

        try:
            iEnum.Next(0xffffffff, 1)
            if read_logger:
                read_logger.info(f"[WMI] Process '{process_name}' FOUND on {ip_address}")
            return True
        except Exception:
            if read_logger:
                read_logger.info(f"[WMI] Process '{process_name}' NOT found on {ip_address}")
            return False

    except Exception as e:
        if read_logger:
            read_logger.info(f"[WMI] Failed for {ip_address}: {type(e).__name__}: {str(e)[:200]}")
        if failure_logger:
            failure_logger.error(f"[WMI] Connection to {ip_address} failed: {e}")
        return None
    finally:
        if dcom:
            try:
                dcom.disconnect()
            except Exception:
                pass


def _tsch_exec_command(ip_address: str, exe_path: str, username: str, password: str) -> bool:
    """Start an executable on a remote Windows server using Task Scheduler RPC (MS-TSCH).

    Creates a temporary scheduled task, runs it immediately, then deletes the task.
    The started process continues running independently after the task completes.

    Requires: impacket library, remote port 445 (SMB named pipe \\pipe\\atsvc).

    Returns:
        True  -- task created and triggered successfully
        False -- failed at any step
    """
    import uuid
    import ntpath
    import time
    task_name = f'\\EPS_TMP_{uuid.uuid4().hex[:8]}'

    # Derive the working directory from the exe path (e.g. D:\EPSNew\EPSDiscount.exe -> D:\EPSNew)
    exe_dir = ntpath.dirname(exe_path) or exe_path.rsplit('\\', 1)[0] if '\\' in exe_path else ''

    xml_task = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
<Triggers>
<CalendarTrigger>
<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>
<Enabled>true</Enabled>
<ScheduleByDay>
<DaysInterval>1</DaysInterval>
</ScheduleByDay>
</CalendarTrigger>
</Triggers>
<Principals>
<Principal id="Author">
<UserId>{username}</UserId>
<LogonType>InteractiveToken</LogonType>
<RunLevel>HighestAvailable</RunLevel>
</Principal>
</Principals>
<Settings>
<MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
<AllowHardTerminate>true</AllowHardTerminate>
<RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
<IdleSettings>
<StopOnIdleEnd>true</StopOnIdleEnd>
<RestartOnIdle>false</RestartOnIdle>
</IdleSettings>
<AllowStartOnDemand>true</AllowStartOnDemand>
<Enabled>true</Enabled>
<Hidden>true</Hidden>
<RunOnlyIfIdle>false</RunOnlyIfIdle>
<WakeToRun>false</WakeToRun>
<ExecutionTimeLimit>P3D</ExecutionTimeLimit>
<Priority>7</Priority>
</Settings>
<Actions Context="Author">
<Exec>
<Command>{exe_path}</Command>
<WorkingDirectory>{exe_dir}</WorkingDirectory>
</Exec>
</Actions>
</Task>"""

    if write_logger:
        write_logger.info(f"[TSCH] exe_path='{exe_path}' | exe_dir='{exe_dir}' | user='{username}' | target={ip_address}")

    # InteractiveToken (3) runs in the logged-in user's desktop session
    logon_type = getattr(tsch, 'TASK_LOGON_INTERACTIVE_TOKEN', 3)

    dce = None
    try:
        if write_logger:
            write_logger.info(f"[TSCH] Connecting to {ip_address} Task Scheduler (user={username})...")

        stringbinding = f'ncacn_np:{ip_address}[\\pipe\\atsvc]'
        rpctransport = impacket_transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_credentials(username, password, '', '', '')

        dce = rpctransport.get_dce_rpc()
        dce.set_credentials(*rpctransport.get_credentials())
        dce.connect()
        dce.bind(tsch.MSRPC_UUID_TSCHS)

        tsch.hSchRpcRegisterTask(
            dce, task_name, xml_task,
            tsch.TASK_CREATE, NULL, logon_type
        )
        if write_logger:
            write_logger.info(f"[TSCH] Task '{task_name}' registered on {ip_address}")

        tsch.hSchRpcRun(dce, task_name)
        if write_logger:
            write_logger.info(f"[TSCH] Task '{task_name}' triggered on {ip_address}")

        # Allow Windows Task Scheduler enough time to spawn the process
        # before deleting the task definition. Without this delay, the task
        # may be removed before the exe actually starts.
        time.sleep(3)

        tsch.hSchRpcDelete(dce, task_name)
        if write_logger:
            write_logger.info(f"[TSCH] Task '{task_name}' deleted from {ip_address}")

        if response_logger:
            response_logger.info(f"[TSCH] Successfully started '{exe_path}' on {ip_address} via Task Scheduler")
        return True

    except Exception as e:
        if failure_logger:
            failure_logger.error(f"[TSCH] Failed to execute on {ip_address}: {type(e).__name__}: {e}")
        if dce:
            try:
                tsch.hSchRpcDelete(dce, task_name)
            except Exception:
                pass
        raise  # propagate so caller gets the actual error detail
    finally:
        if dce:
            try:
                dce.disconnect()
            except Exception:
                pass


def _smb_copy_file(ip_address: str, local_path: str, share: str, remote_path: str,
                   username: str, password: str) -> None:
    """Copy a local file to a remote Windows server via SMB.

    Requires: impacket library, remote port 445 (SMB).

    Args:
        ip_address: Remote server IP address.
        local_path: Full path to the local source file.
        share: SMB share name (e.g., 'D$' for the D: drive admin share).
        remote_path: Path within the share (e.g., 'EPS_New\\EPSDiscount.exe').
        username: Remote server username.
        password: Remote server password.

    Raises:
        Exception: on any connection or file transfer error.
    """
    conn = None
    try:
        if write_logger:
            write_logger.info(f"[SMB] Connecting to {ip_address} share '{share}' (user={username})...")

        conn = ImpacketSMBConnection(ip_address, ip_address, timeout=30)
        conn.login(username, password, '')

        with open(local_path, 'rb') as fh:
            conn.putFile(share, remote_path, fh.read)

        if write_logger:
            write_logger.info(f"[SMB] Successfully copied '{local_path}' -> \\\\{ip_address}\\{share}\\{remote_path}")

    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def _smb_exec_command(ip_address: str, command: str, username: str, password: str, timeout: int = 30):
    """Execute a command on a remote Windows server via SVCCTL over SMB (port 445 ONLY).

    Uses the Windows Service Control Manager (\\pipe\\svcctl) to create a temporary
    service that runs the command via cmd.exe. Output is captured to a temp file on
    the remote C$ share and read back via SMB. This is the same mechanism used by
    PsExec and impacket's smbexec.py.

    Requires: impacket, remote port 445 (SMB pipes \\pipe\\svcctl + C$ admin share).
    Compatible with: Windows Server 2003 through Server 2022.

    Returns:
        str:  command stdout/stderr on success
        None: on failure (connection error, auth error, etc.)
    """
    import uuid
    import time

    service_name = f'EPSTMP{uuid.uuid4().hex[:8]}'
    output_filename = f'__eps_{uuid.uuid4().hex[:8]}.tmp'
    output_remote_path = f'Windows\\Temp\\{output_filename}'
    output_full_path = f'C:\\Windows\\Temp\\{output_filename}'

    # cmd.exe runs the command and redirects all output to the temp file
    bin_path = f'%COMSPEC% /Q /c {command} > {output_full_path} 2>&1'

    dce = None
    svc_handle = None
    scm_handle = None
    smb_conn = None

    try:
        if read_logger:
            read_logger.info(f"[SVCCTL] Connecting to {ip_address} via \\pipe\\svcctl (user={username})...")

        # Step 1: Connect to SVCCTL named pipe over SMB (port 445)
        stringbinding = f'ncacn_np:{ip_address}[\\pipe\\svcctl]'
        rpctransport = impacket_transport.DCERPCTransportFactory(stringbinding)
        rpctransport.set_credentials(username, password, '', '', '')

        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(scmr.MSRPC_UUID_SVCCTL)

        # Step 2: Open Service Control Manager
        resp = scmr.hROpenSCManagerW(dce)
        scm_handle = resp['lpScHandle']

        # Step 3: Create temporary service
        try:
            resp = scmr.hRCreateServiceW(
                dce,
                scm_handle,
                service_name,
                service_name,
                lpBinaryPathName=bin_path,
                dwStartType=scmr.SERVICE_DEMAND_START,
            )
            svc_handle = resp['lpServiceHandle']
        except Exception as e:
            if read_logger:
                read_logger.info(f"[SVCCTL] Failed to create service on {ip_address}: {e}")
            return None

        # Step 4: Start the service (this runs the command)
        # cmd.exe is not a real Windows service, so StartService will raise an error
        # after the command completes. This is expected and harmless.
        try:
            scmr.hRStartServiceW(dce, svc_handle)
        except Exception:
            pass

        # Brief pause to let command complete and flush output
        time.sleep(2)

        # Step 5: Clean up the temporary service
        try:
            scmr.hRDeleteService(dce, svc_handle)
        except Exception:
            pass
        try:
            scmr.hRCloseServiceHandle(dce, svc_handle)
            svc_handle = None
        except Exception:
            pass

        # Step 6: Read command output via separate SMB connection
        output = ''
        try:
            smb_conn = ImpacketSMBConnection(ip_address, ip_address, timeout=timeout)
            smb_conn.login(username, password, '')

            from io import BytesIO
            buf = BytesIO()
            smb_conn.getFile('C$', output_remote_path, buf.write)
            output = buf.getvalue().decode('utf-8', errors='replace').strip()

            # Delete the temp output file
            try:
                smb_conn.deleteFile('C$', output_remote_path)
            except Exception:
                pass
        except Exception as e:
            if read_logger:
                read_logger.info(f"[SVCCTL] Could not read output file from {ip_address}: {e}")

        if read_logger:
            read_logger.info(f"[SVCCTL] Command on {ip_address} completed, output_len={len(output)}")

        return output

    except Exception as e:
        if read_logger:
            read_logger.info(f"[SVCCTL] Failed on {ip_address}: {type(e).__name__}: {str(e)[:200]}")
        if failure_logger:
            failure_logger.error(f"[SVCCTL] Error on {ip_address}: {e}")
        return None
    finally:
        if svc_handle:
            try:
                scmr.hRDeleteService(dce, svc_handle)
            except Exception:
                pass
            try:
                scmr.hRCloseServiceHandle(dce, svc_handle)
            except Exception:
                pass
        if scm_handle:
            try:
                scmr.hRCloseServiceHandle(dce, scm_handle)
            except Exception:
                pass
        if dce:
            try:
                dce.disconnect()
            except Exception:
                pass
        if smb_conn:
            try:
                smb_conn.close()
            except Exception:
                pass


def _smb_check_process(ip_address: str, process_name: str, username: str, password: str):
    """Check if a process is running on a remote Windows server via SVCCTL + tasklist.

    Uses _smb_exec_command to run 'tasklist' remotely over port 445 only.
    This is the most firewall-friendly approach — only requires SMB (port 445).

    Returns:
        True  -- process is running
        False -- process is NOT running (tasklist succeeded, process not in output)
        None  -- command execution failed (connection/auth error)
    """
    command = f'tasklist /FI "IMAGENAME eq {process_name}"'
    output = _smb_exec_command(ip_address, command, username, password)

    if output is None:
        return None

    # tasklist includes the process name in its output table if it's running
    if process_name.lower() in output.lower():
        if read_logger:
            read_logger.info(f"[SVCCTL] Process '{process_name}' FOUND on {ip_address}")
        return True
    else:
        if read_logger:
            read_logger.info(f"[SVCCTL] Process '{process_name}' NOT found on {ip_address}")
        return False


# ============== Core Utility Functions ==============

def is_service_running(ip_address: str, service_name: str, username: str, password: str):
    """Check if a service is running on remote server.

    Returns:
      - True: verified running (tasklist/WMI succeeded)
      - False: verified not running (tasklist/WMI returned not found)
      - None: reachable but verification not available (e.g., running from Linux container without impacket)
    """
    # Prefer an accurate Windows-side check when running on a Windows host
    try:
        system = platform.system().lower()
        attempted_check = False

        # If running on Windows, attempt tasklist command (most reliable)
        if system == "windows" and username and password:
            attempted_check = True
            try:
                # tasklist is more reliable than WMI for remote process checking
                # Escape special characters in password for command line
                escaped_password = password.replace('^', '^^').replace('"', '""').replace('&', '^&').replace('|', '^|')
                tasklist_cmd = f'tasklist /S {ip_address} /U {username} /P "{escaped_password}" /FI "IMAGENAME eq {service_name}"'
                if read_logger:
                    read_logger.info(f"Attempting tasklist on {ip_address} for {service_name} (user={username})...")

                result = subprocess.run(tasklist_cmd, shell=True, capture_output=True, text=True, timeout=20)

                if read_logger:
                    try:
                        read_logger.info(f"tasklist on {ip_address}: rc={result.returncode}, stdout_len={len(result.stdout)}, stderr_len={len(result.stderr)}")
                        if result.returncode == 0:
                            read_logger.info(f"  tasklist output: {result.stdout[:300]}")
                    except:
                        pass

                # tasklist returns 0 if process is found, 1 if not found
                if result.returncode == 0 and service_name.lower() in result.stdout.lower():
                    if read_logger:
                        read_logger.info(f"Process {service_name} FOUND on {ip_address}")
                    return True
                else:
                    if read_logger:
                        read_logger.info(f"Process {service_name} NOT found on {ip_address}")
                    return False
            except subprocess.TimeoutExpired:
                if read_logger:
                    read_logger.info(f"tasklist TIMED OUT on {ip_address} - falling back")
                # Continue to next method
            except Exception as e:
                if read_logger:
                    read_logger.info(f"tasklist exception on {ip_address}: {type(e).__name__}: {str(e)[:100]}")

        # If running on Linux (Docker container), try WMI via impacket (ports 135+dynamic RPC)
        if not attempted_check and IMPACKET_AVAILABLE and username and password:
            attempted_check = True
            try:
                wmi_result = _wmi_check_process(ip_address, service_name, username, password)
                if wmi_result is not None:
                    # WMI gave a definitive answer (True or False)
                    return wmi_result
                # wmi_result is None means WMI connection failed; fall through to SVCCTL
                if read_logger:
                    read_logger.info(f"[WMI] Returned None for {ip_address}, falling through to SVCCTL")
            except Exception as e:
                if read_logger:
                    read_logger.info(f"[WMI] Exception for {ip_address}: {type(e).__name__}: {str(e)[:100]}")

        # Fallback: SVCCTL over SMB (port 445 only) — most firewall-friendly
        if IMPACKET_AVAILABLE and username and password:
            try:
                svcctl_result = _smb_check_process(ip_address, service_name, username, password)
                if svcctl_result is not None:
                    return svcctl_result
                if read_logger:
                    read_logger.info(f"[SVCCTL] Returned None for {ip_address}, falling through to TCP probe")
            except Exception as e:
                if read_logger:
                    read_logger.info(f"[SVCCTL] Exception for {ip_address}: {type(e).__name__}: {str(e)[:100]}")

        # Fallback: quick TCP probe to common Windows management ports (SMB/RDP/RPC)
        if read_logger:
            read_logger.info(f"Checking TCP reachability on {ip_address}...")

        ports = [445, 3389, 135]
        for p in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip_address, p))
                sock.close()
                if read_logger:
                    read_logger.info(f"TCP port {p} on {ip_address} is reachable")

                # If we attempted tasklist/WMI and it completed (didn't return True), process wasn't found
                if attempted_check:
                    if read_logger:
                        read_logger.info(f"Note: process check was attempted but didn't find the process")
                    return False

                # Otherwise we can't verify process status, return None (unverified)
                return None
            except Exception as e:
                if read_logger:
                    read_logger.info(f"TCP port {p} on {ip_address}: unreachable")
                continue

        # No TCP ports responded, server is unreachable
        if read_logger:
            read_logger.info(f"{ip_address} is not reachable on any port")
        return False
    except Exception as e:
        if failure_logger:
            failure_logger.exception(f"is_service_running error for {ip_address}: {e}")
        return False

def copy_file_to_server(outlet_code: str, ip_address: str, src_file: str, username: str, password: str, dest_path: str = None) -> dict:
    """Copy deployment file to remote server.

    On Windows: uses net use + shutil.copy (existing behavior).
    On Linux/Docker: uses impacket SMB client.

    dest_path: remote folder path relative to D$ (e.g. 'EPS_New', 'EPS\\EPS').
               Defaults to EPS_DEST_PATH env var or 'EPS_New'.
    """
    if dest_path is None:
        dest_path = get_env_pref("DEST_PATH", "EPS_New")
    system = platform.system().lower()

    # --- Cross-platform path: use impacket SMB ---
    if system != "windows" and IMPACKET_AVAILABLE:
        try:
            share = 'D$'
            remote_filename = dest_path + '\\' + os.path.basename(src_file)

            _smb_copy_file(ip_address, src_file, share, remote_filename, username, password)

            logger.info(f"Successfully copied {src_file} to {ip_address} via SMB")
            if write_logger:
                write_logger.info(f"[SMB] Copied {src_file} -> \\\\{ip_address}\\{share}\\{remote_filename} (outlet {outlet_code})")
            return {
                "outlet_code": outlet_code,
                "ip_address": ip_address,
                "success": True,
                "message": "Exe deployed successfully via SMB"
            }
        except Exception as e:
            logger.error(f"SMB copy to {ip_address} failed: {e}")
            if failure_logger:
                failure_logger.exception(f"[SMB] Copy error {ip_address}: {e}")
            return {
                "outlet_code": outlet_code,
                "ip_address": ip_address,
                "success": False,
                "message": f"SMB copy failed: {str(e)}"
            }

    if system != "windows" and not IMPACKET_AVAILABLE:
        msg = "File copy unavailable: not running on Windows and impacket is not installed"
        logger.error(msg)
        if failure_logger:
            failure_logger.error(f"[COPY] {msg} (outlet {outlet_code}, ip {ip_address})")
        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "success": False,
            "message": msg
        }

    # --- Windows-native path (existing behavior) ---
    dest_file = os.path.normpath(f'\\\\{ip_address}\\D$\\{dest_path}')
    try:
        # Authenticate and map network drive
        subprocess.run(
            f"net use \\\\{ip_address} /user:{username} {password}",
            shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
        )

        # Copy file
        shutil.copy(src_file, dest_file)
        logger.info(f"Successfully copied {src_file} to {ip_address}")
        if write_logger:
            write_logger.info(f"Copied {src_file} -> {dest_file} on {ip_address} (outlet {outlet_code})")

        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "success": True,
            "message": "Exe deployed successfully"
        }
    except Exception as e:
        logger.error(f"Error copying file to {ip_address}: {e}")
        if failure_logger:
            failure_logger.exception(f"Copy error {ip_address}: {e}")
        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "success": False,
            "message": str(e)
        }
    finally:
        # Unmap the drive
        try:
            subprocess.run(
                f"net use \\\\{ip_address} /delete",
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=5
            )
        except:
            pass

def run_exe_on_server(outlet_code: str, ip_address: str, username: str, password: str) -> dict:
    """Run EPSDiscount.exe on remote server.

    Method selection is platform-aware:
      - Windows: impacket TSCH → PowerShell
      - Linux/Docker: impacket TSCH only (PowerShell is Windows-only)
    """
    dest_folder = get_env_pref("DEST_PATH", "EPS_New")
    exe_path = f"D:\\{dest_folder}\\EPSDiscount.exe"
    system = platform.system().lower()
    is_windows = system == "windows"
    attempts = []  # track each method tried for diagnostics

    # --- Method 1: impacket Task Scheduler (cross-platform, works from Linux/Docker) ---
    if IMPACKET_AVAILABLE:
        try:
            if write_logger:
                write_logger.info(f"[TSCH] Attempting Task Scheduler execution on {ip_address}...")
            success = _tsch_exec_command(ip_address, exe_path, username, password)
            if success:
                logger.info(f"Successfully executed {exe_path} on {ip_address} via Task Scheduler")
                if response_logger:
                    response_logger.info(f"Executed {exe_path} on {ip_address} (outlet {outlet_code}) via TSCH")
                return {"outlet_code": outlet_code, "ip_address": ip_address, "success": True, "message": "Exe executed via Task Scheduler (impacket)"}
            else:
                attempts.append("TSCH: task creation/trigger failed")
                logger.warning(f"Task Scheduler execution returned failure on {ip_address}")
        except Exception as e:
            attempts.append(f"TSCH: {e}")
            logger.warning(f"Task Scheduler execution failed for {ip_address}: {e}")
            if failure_logger:
                failure_logger.error(f"[TSCH] Exception on {ip_address} (outlet {outlet_code}): {e}")
    else:
        attempts.append("TSCH: impacket not available")
        logger.warning(f"impacket not available — cannot use Task Scheduler for {ip_address}")

    # --- Method 2: PowerShell remote start (Windows-only) ---
    if is_windows:
        try:
            ps_cmd = (
                'powershell -NoProfile -NonInteractive -Command '
                '"$sec = ConvertTo-SecureString \\"{pw}\\" -AsPlainText -Force; '
                '$cred = New-Object System.Management.Automation.PSCredential(\\"{user}\\", $sec); '
                'Invoke-Command -ComputerName {ip} -Credential $cred -ScriptBlock {{ Start-Process -FilePath \\\"{exe}\\\" -WindowStyle Hidden }} -ErrorAction Stop"'
            ).format(pw=password, user=username, ip=ip_address, exe=exe_path)

            result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True, timeout=40)
            if result.returncode == 0:
                logger.info(f"Started {exe_path} on {ip_address} via PowerShell Invoke-Command")
                if response_logger:
                    response_logger.info(f"Started {exe_path} on {ip_address} (outlet {outlet_code}) via PowerShell")
                return {"outlet_code": outlet_code, "ip_address": ip_address, "success": True, "message": "Exe started via PowerShell"}
            else:
                error_detail = result.stderr.strip()
                attempts.append(f"PowerShell: {error_detail}")
                logger.warning(f"PowerShell start returned code {result.returncode} on {ip_address}: {error_detail}")
        except Exception as e:
            attempts.append(f"PowerShell: {e}")
            logger.error(f"Error starting exe on {ip_address}: {e}")
            if failure_logger:
                failure_logger.exception(f"Start exe error on {ip_address}: {e}")

    # All methods exhausted
    summary = "; ".join(attempts) if attempts else "No execution method available for this platform"
    logger.error(f"All execution methods failed for {ip_address} (outlet {outlet_code}): {summary}")
    if failure_logger:
        failure_logger.error(f"All methods failed for {ip_address} (outlet {outlet_code}): {summary}")
    return {"outlet_code": outlet_code, "ip_address": ip_address, "success": False, "message": summary}

def check_exe_status(outlet_code: str, ip_address: str, username: str, password: str) -> dict:
    """Check exe availability on server"""
    if not is_server_online(ip_address):
        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "status": "Offline",
            "available": False,
            "message": "Server is not reachable"
        }

    svc_name = "EPSDiscount.exe"
    try:
        running = is_service_running(ip_address, svc_name, username, password)
    except Exception as e:
        logger.error(f"Error during service check for {ip_address}: {e}")
        running = False

    # Interpret the three possible results from is_service_running():
    #   True  -> verified running
    #   False -> verified not running
    #   None  -> reachable but verification unavailable (e.g., running inside Linux container without impacket)
    if running is True:
        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "status": "Running",
            "available": True,
            "message": f"{svc_name} is running"
        }
    if running is None:
        return {
            "outlet_code": outlet_code,
            "ip_address": ip_address,
            "status": "Unknown",
            "available": False,
            "message": f"{svc_name} reachability verified but process check unavailable from this runtime. Run service natively on Windows to verify."
        }

    # Not running. Optionally attempt to start if AUTO_START_EXE is enabled
    auto_start = os.environ.get("AUTO_START_EXE", "false").lower() in ("1", "true", "yes")

    if auto_start and username and password:
        start_result = run_exe_on_server(outlet_code, ip_address, username, password)
        if start_result.get("success"):
            # After starting, re-check quickly
            recheck = is_service_running(ip_address, svc_name, username, password)
            return {
                "outlet_code": outlet_code,
                "ip_address": ip_address,
                "status": "Running" if recheck else "Starting",
                "available": recheck,
                "message": start_result.get("message")
            }
        else:
            return {
                "outlet_code": outlet_code,
                "ip_address": ip_address,
                "status": "Not Running",
                "available": False,
                "message": f"Start attempt failed: {start_result.get('message')}"
            }

    return {
        "outlet_code": outlet_code,
        "ip_address": ip_address,
        "status": "Not Running",
        "available": False,
        "message": f"{svc_name} is not running"
    }

# ============== API Endpoints ==============

@app.get("/api/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}

@app.post("/api/check-exe-status")
async def check_exe_availability(servers: List[ServerInfo]):
    """
    Endpoint 1: Check if EPSDiscount.exe is running on specified servers
    """
    if not servers:
        raise HTTPException(status_code=400, detail="No servers provided")

    logger.info(f"Checking exe status on {len(servers)} servers")
    default_user = get_env_pref("USERNAME")
    default_pass = get_env_pref("PASSWORD")
    results = []

    try:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(check_exe_status, s.outlet_code, s.ip_address, default_user, default_pass)
                for s in servers
            ]
            for future in futures:
                try:
                    result = future.result()
                    results.append(result)
                    # Log with detailed response info
                    if response_logger:
                        response_logger.info(
                            f"outlet_code: {result.get('outlet_code')} | "
                            f"ip_address: {result.get('ip_address')} | "
                            f"status: {result.get('status')} | "
                            f"available: {result.get('available')} | "
                            f"message: {result.get('message')}"
                        )
                except Exception as e:
                    logger.error(f"Error checking a server: {e}")
                    if failure_logger:
                        failure_logger.exception(f"Worker exception: {e}")
                    error_result = {"outlet_code": "unknown", "ip_address": "unknown", "status": "Error", "available": False, "message": str(e)}
                    results.append(error_result)
                    if failure_logger:
                        failure_logger.error(f"outlet_code: unknown | ip_address: unknown | status: Error | message: {e}")
    except Exception as e:
        logger.critical(f"Unhandled error in check_exe_availability: {e}")
        if failure_logger:
            failure_logger.exception(f"check_exe_availability crashed: {e}")
        raise

    return {
        "endpoint": "check-exe-status",
        "timestamp": datetime.now().isoformat(),
        "total_servers": len(servers),
        "data": results
    }

@app.post("/api/run-exe")
async def run_exe_on_servers(servers: List[ServerInfo]):
    """
    Endpoint 2: Run EPSDiscount.exe on servers that are online
    """
    if not servers:
        raise HTTPException(status_code=400, detail="No servers provided")

    logger.info(f"Running exe on {len(servers)} servers")
    default_user = get_env_pref("USERNAME")
    default_pass = get_env_pref("PASSWORD")
    results = []

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for s in servers:
            # First check if server is online
            if is_server_online(s.ip_address):
                futures.append(
                    (s, executor.submit(run_exe_on_server, s.outlet_code, s.ip_address, default_user, default_pass))
                )
            else:
                offline_result = {
                    "outlet_code": s.outlet_code,
                    "ip_address": s.ip_address,
                    "success": False,
                    "message": "Server is offline"
                }
                results.append(offline_result)
                if response_logger:
                    response_logger.info(f"outlet_code: {s.outlet_code} | ip_address: {s.ip_address} | success: False | message: Server is offline")

        for server_info, future in futures:
            try:
                result = future.result()
                results.append(result)
                if response_logger:
                    response_logger.info(
                        f"outlet_code: {result.get('outlet_code')} | "
                        f"ip_address: {result.get('ip_address')} | "
                        f"success: {result.get('success')} | "
                        f"message: {result.get('message')}"
                    )
            except Exception as e:
                error_result = {
                    "outlet_code": server_info.outlet_code,
                    "ip_address": server_info.ip_address,
                    "success": False,
                    "message": str(e)
                }
                results.append(error_result)
                if failure_logger:
                    failure_logger.error(f"outlet_code: {server_info.outlet_code} | ip_address: {server_info.ip_address} | success: False | message: {e}")

    return {
        "endpoint": "run-exe",
        "timestamp": datetime.now().isoformat(),
        "total_servers": len(servers),
        "data": results
    }

@app.post("/api/deploy-new-outlet")
async def deploy_new_outlet(servers: List[ServerInfo]):
    """
    Endpoint 3: Deploy file to new outlet (copy only, no exe execution)
    Request body: [ { "outlet_code": "D007", "ip_address": "172.16.51.41" } ]
    """
    if not servers:
        raise HTTPException(status_code=400, detail="No servers provided")

    source_path = get_env_pref("SOURCE_FILE")
    dest_path = get_env_pref("DEST_PATH", "EPS_New")
    username = get_env_pref("USERNAME")
    password = get_env_pref("PASSWORD")

    if not source_path:
        raise HTTPException(status_code=400, detail="SOURCE_FILE not configured")

    # Skip os.path.exists() for UNC paths — network shares need auth first
    # The copy operation will report errors per-server if the source is missing
    if not source_path.startswith("\\\\") and not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail=f"Source file not found: {source_path}")

    logger.info(f"Deploying {os.path.basename(source_path)} to {len(servers)} outlets -> D$\\{dest_path}")
    results = []

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = []

        for s in servers:
            if not is_server_online(s.ip_address):
                results.append({
                    "outlet_code": s.outlet_code,
                    "ip_address": s.ip_address,
                    "success": False,
                    "message": f"Server is offline for Outlet {s.outlet_code}"
                })
                continue

            copy_future = executor.submit(
                copy_file_to_server, s.outlet_code, s.ip_address,
                source_path, username, password, dest_path
            )
            futures.append((s.outlet_code, s.ip_address, copy_future))

        for outlet_code, ip_address, copy_future in futures:
            try:
                copy_result = copy_future.result()
                if copy_result["success"]:
                    copy_result["message"] = f"Exe has been Successfully Deployed On Outlet {outlet_code}"
                    if response_logger:
                        response_logger.info(
                            f"outlet_code: {outlet_code} | ip_address: {ip_address} | "
                            f"deployed: {os.path.basename(source_path)} -> D$\\{dest_path}"
                        )
                else:
                    copy_result["message"] = f"Failed to Deploy Exe On Outlet {outlet_code}: {copy_result.get('message', 'Unknown error')}"
                    if failure_logger:
                        failure_logger.warning(
                            f"outlet_code: {outlet_code} | ip_address: {ip_address} | "
                            f"deployment_failed: {copy_result.get('message', 'Unknown error')}"
                        )
                results.append(copy_result)
            except Exception as e:
                results.append({
                    "outlet_code": outlet_code,
                    "ip_address": ip_address,
                    "success": False,
                    "message": f"Failed to Deploy Exe On Outlet {outlet_code}: {str(e)}"
                })
                if failure_logger:
                    failure_logger.error(f"outlet_code: {outlet_code} | ip_address: {ip_address} | error: {e}")

    return {
        "endpoint": "deploy-new-outlet",
        "timestamp": datetime.now().isoformat(),
        "total_outlets": len(servers),
        "data": results
    }

@app.get("/api/docs")
async def api_documentation():
    """API Documentation"""
    return {
        "title": "EPS Discount Service API",
        "version": "1.0.0",
        "endpoints": [
            {
                "name": "Check Exe Status",
                "path": "/api/check-exe-status",
                "method": "POST",
                "description": "Check if EPSDiscount.exe is running on servers"
            },
            {
                "name": "Run Exe",
                "path": "/api/run-exe",
                "method": "POST",
                "description": "Run EPSDiscount.exe on online servers"
            },
            {
                "name": "Deploy New Outlet",
                "path": "/api/deploy-new-outlet",
                "method": "POST",
                "description": "Deploy exe to new outlets and run it"
            }
        ],
        "swagger_url": "/docs",
        "redoc_url": "/redoc"
    }

if __name__ == "__main__":
    import uvicorn
    import signal
    import sys

    # Load .env and setup loggers
    load_dotenv()
    category_loggers = setup_category_file_loggers()
    failure_log = category_loggers.get("failure", logger)

    port = int(get_env_pref("SERVER_PORT", "8000"))
    host = get_env_pref("SERVER_HOST", "0.0.0.0")

    # Log startup attempt
    startup_msg = f"[STARTUP] EPS Discount Integration Service starting on {host}:{port}"
    logger.info(startup_msg)
    print(f"✓ {startup_msg}")

    # Graceful shutdown handler
    def shutdown_handler(sig, frame):
        shutdown_msg = f"[SHUTDOWN] Service received signal {sig}. Shutting down gracefully..."
        logger.info(shutdown_msg)
        print(f"✓ {shutdown_msg}")
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown_handler)
    signal.signal(signal.SIGTERM, shutdown_handler)

    try:
        logger.info(f"[STARTUP] Loading environment from .env and initializing loggers")
        uvicorn.run(app, host=host, port=port, reload=True)
    except KeyboardInterrupt:
        shutdown_msg = "[SHUTDOWN] Service interrupted by user (Ctrl+C)"
        logger.info(shutdown_msg)
        print(f"✓ {shutdown_msg}")
    except Exception as e:
        error_msg = f"[STARTUP_FAILED] Service failed to start: {str(e)}"
        logger.critical(error_msg)
        failure_log.error(f"[STARTUP_FAILED] {error_msg}\nTraceback: {type(e).__name__}: {e}")
        print(f"✗ {error_msg}")
        print(f"  Check logs in 'logs/' directory for details.")
        sys.exit(1)
