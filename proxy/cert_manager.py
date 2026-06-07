"""
CA certificate generator and per-host cert factory for the HTTPS intercepting proxy.

On first call, generates a root CA (stored in data/proxy/ca.key + ca.crt).
Per-host certs are generated on demand and cached in memory (max 512 entries).
Import ca.crt into your browser's trusted CA store to avoid certificate warnings.
"""
import os
import datetime
import threading
import ipaddress
import logging
from collections import OrderedDict

logger = logging.getLogger("ids_ips")

_ca_key = None
_ca_cert = None
_host_cache: OrderedDict = OrderedDict()
_cache_lock = threading.Lock()
_CACHE_MAX = 512

_DEFAULT_CA_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "proxy",
)


def _crypto_available() -> bool:
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


def init_ca(ca_dir: str = _DEFAULT_CA_DIR) -> bool:
    """Generate (or load) the root CA. Returns True on success."""
    global _ca_key, _ca_cert
    if not _crypto_available():
        logger.warning("proxy: 'cryptography' package not installed — proxy disabled")
        return False

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    os.makedirs(ca_dir, exist_ok=True)
    key_path = os.path.join(ca_dir, "ca.key")
    crt_path = os.path.join(ca_dir, "ca.crt")

    if os.path.exists(key_path) and os.path.exists(crt_path):
        with open(key_path, "rb") as f:
            _ca_key = serialization.load_pem_private_key(f.read(), password=None)
        with open(crt_path, "rb") as f:
            _ca_cert = x509.load_pem_x509_certificate(f.read())
        logger.info("proxy: loaded existing CA from %s", ca_dir)
        return True

    # Generate new CA
    _ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PL"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "IDS-IPS Security Console"),
        x509.NameAttribute(NameOID.COMMON_NAME, "IDS-IPS Local CA"),
    ])
    now = datetime.datetime.utcnow()
    _ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(_ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(_ca_key.public_key()), critical=False)
        .sign(_ca_key, hashes.SHA256())
    )
    with open(key_path, "wb") as f:
        f.write(_ca_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(crt_path, "wb") as f:
        f.write(_ca_cert.public_bytes(serialization.Encoding.PEM))
    logger.info("proxy: generated new CA at %s — import ca.crt into browser to avoid warnings", crt_path)
    return True


def get_ca_cert_path() -> str:
    return os.path.join(_DEFAULT_CA_DIR, "ca.crt")


def get_host_cert(hostname: str) -> tuple:
    """Return (cert_pem_path, key_pem_path) for hostname, generating if needed."""
    if _ca_key is None or _ca_cert is None:
        raise RuntimeError("CA not initialised — call init_ca() first")

    with _cache_lock:
        if hostname in _host_cache:
            return _host_cache[hostname]

    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.utcnow()
    san_list = []
    try:
        ipaddress.ip_address(hostname)
        san_list.append(x509.IPAddress(ipaddress.ip_address(hostname)))
    except ValueError:
        san_list.append(x509.DNSName(hostname))

    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)]))
        .issuer_name(_ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(san_list), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(_ca_key, hashes.SHA256())
    )

    ca_dir = _DEFAULT_CA_DIR
    safe = hostname.replace("*", "_star_").replace(":", "_")
    key_path = os.path.join(ca_dir, f"{safe}.key")
    crt_path = os.path.join(ca_dir, f"{safe}.crt")

    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
    with open(crt_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    with _cache_lock:
        if len(_host_cache) >= _CACHE_MAX:
            _host_cache.popitem(last=False)
        _host_cache[hostname] = (crt_path, key_path)

    return crt_path, key_path
