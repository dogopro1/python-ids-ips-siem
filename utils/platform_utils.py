import ipaddress
import platform
import subprocess
import logging

logger = logging.getLogger("ids_ips")


def get_os() -> str:
    s = platform.system().lower()
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "darwin"
    return "linux"


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def block_ip(ip: str) -> bool:
    if not _validate_ip(ip):
        logger.error("block_ip: invalid IP address '%s'", ip)
        return False

    os_name = get_os()
    try:
        if os_name == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=IDS_BLOCK_{ip}",
                "dir=in", "action=block", f"remoteip={ip}",
            ]
        elif os_name == "linux":
            cmd = ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            _pf_add(ip)
            return True

        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            logger.warning("block_ip failed for %s: %s", ip, result.stderr.decode(errors="replace"))
            return False
        return True
    except PermissionError:
        logger.warning("block_ip: insufficient privileges for %s", ip)
        return False
    except Exception as e:
        logger.error("block_ip error for %s: %s", ip, e)
        return False


def unblock_ip(ip: str) -> bool:
    if not _validate_ip(ip):
        logger.error("unblock_ip: invalid IP address '%s'", ip)
        return False

    os_name = get_os()
    try:
        if os_name == "windows":
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                f"name=IDS_BLOCK_{ip}",
            ]
        elif os_name == "linux":
            cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            _pf_remove(ip)
            return True

        result = subprocess.run(cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            logger.warning("unblock_ip failed for %s: %s", ip, result.stderr.decode(errors="replace"))
            return False
        return True
    except PermissionError:
        logger.warning("unblock_ip: insufficient privileges for %s", ip)
        return False
    except Exception as e:
        logger.error("unblock_ip error for %s: %s", ip, e)
        return False


def _pf_add(ip: str) -> None:
    anchor_file = "/etc/pf.anchors/ids_ips"
    rule = f"block in from {ip} to any\n"
    try:
        with open(anchor_file, "a") as f:
            f.write(rule)
        subprocess.run(["pfctl", "-f", "/etc/pf.conf"], capture_output=True, timeout=10)
        subprocess.run(["pfctl", "-e"], capture_output=True, timeout=10)
    except PermissionError:
        raise
    except Exception as e:
        logger.error("_pf_add error for %s: %s", ip, e)
        raise


def _pf_remove(ip: str) -> None:
    anchor_file = "/etc/pf.anchors/ids_ips"
    rule = f"block in from {ip} to any\n"
    try:
        with open(anchor_file, "r") as f:
            lines = f.readlines()
        with open(anchor_file, "w") as f:
            f.writelines(ln for ln in lines if ln != rule)
        subprocess.run(["pfctl", "-f", "/etc/pf.conf"], capture_output=True, timeout=10)
    except FileNotFoundError:
        pass
    except Exception as e:
        logger.error("_pf_remove error for %s: %s", ip, e)
        raise
