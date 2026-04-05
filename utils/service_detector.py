_SERVICES: dict = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    119: "NNTP", 123: "NTP", 135: "MSRPC", 137: "NetBIOS-NS",
    138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
    161: "SNMP", 162: "SNMP-TRAP", 179: "BGP", 194: "IRC",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS",
    500: "IKE", 514: "Syslog", 515: "LPD", 520: "RIP",
    554: "RTSP", 587: "SMTP-TLS", 631: "IPP", 636: "LDAPS",
    873: "rsync", 902: "VMware", 993: "IMAPS", 995: "POP3S",
    1080: "SOCKS5", 1194: "OpenVPN", 1433: "MSSQL",
    1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2181: "ZooKeeper", 3306: "MySQL", 3389: "RDP",
    4369: "EPMD", 5432: "PostgreSQL", 5672: "AMQP",
    5900: "VNC", 6379: "Redis", 6667: "IRC",
    7001: "WebLogic", 8080: "HTTP-ALT", 8443: "HTTPS-ALT",
    8888: "Jupyter", 9200: "Elasticsearch", 9300: "Elasticsearch",
    9092: "Kafka", 11211: "Memcached", 27017: "MongoDB",
    27018: "MongoDB", 50070: "Hadoop",
    4444: "Metasploit", 5555: "Backdoor/ADB",
    6666: "IRC/Backdoor", 31337: "Elite/Backdoor",
    12345: "NetBus", 1234: "Backdoor", 7777: "Backdoor",
}

_SUSPICIOUS = {4444, 5555, 6666, 31337, 12345, 1234, 7777, 9999, 6543, 1337}
_HIGH_RISK_PORTS = {23, 135, 137, 138, 139, 445, 1080}


def get_service(port: int) -> str:
    return _SERVICES.get(port, f":{port}")


def is_suspicious(port: int) -> bool:
    return port in _SUSPICIOUS


def get_risk(port: int) -> str:
    if port in _SUSPICIOUS:
        return "HIGH"
    if port in _HIGH_RISK_PORTS:
        return "MEDIUM"
    return "LOW"


def all_services() -> dict:
    return dict(_SERVICES)
