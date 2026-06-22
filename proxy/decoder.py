"""
BurpSuite Decoder equivalent.

Supported operations:
  Encode: base64, base64url, url, html, hex, binary, gzip, zlib
  Decode: base64, base64url, url, html, hex, binary, gzip, zlib
  Hash  : md5, sha1, sha256, sha512, sha3_256
  Special: jwt_decode, unicode_escape, unicode_encode, rot13, reverse

Input/output are strings. Binary data is represented as hex for display.
"""
import base64
import binascii
import html
import hashlib
import json
import urllib.parse
import zlib
import gzip
import io
import codecs
import re


def encode(data: str, method: str) -> dict:
    """Encode data using method. Returns {result, method, error?}."""
    try:
        b = data.encode("utf-8")
        if method == "base64":
            return {"result": base64.b64encode(b).decode(), "method": method}
        if method == "base64url":
            return {"result": base64.urlsafe_b64encode(b).rstrip(b"=").decode(), "method": method}
        if method == "url":
            return {"result": urllib.parse.quote(data, safe=""), "method": method}
        if method == "url_form":
            return {"result": urllib.parse.quote_plus(data), "method": method}
        if method == "html":
            return {"result": html.escape(data, quote=True), "method": method}
        if method == "hex":
            return {"result": b.hex(), "method": method}
        if method == "hex_spaces":
            return {"result": " ".join(f"{byte:02x}" for byte in b), "method": method}
        if method == "binary":
            return {"result": " ".join(f"{byte:08b}" for byte in b), "method": method}
        if method == "gzip":
            buf = io.BytesIO()
            with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
                gz.write(b)
            return {"result": base64.b64encode(buf.getvalue()).decode(), "method": method,
                    "note": "Result is base64(gzip(input))"}
        if method == "zlib":
            compressed = zlib.compress(b)
            return {"result": base64.b64encode(compressed).decode(), "method": method,
                    "note": "Result is base64(zlib(input))"}
        if method == "unicode_escape":
            return {"result": data.encode("unicode_escape").decode(), "method": method}
        if method == "rot13":
            return {"result": codecs.encode(data, "rot_13"), "method": method}
        if method == "reverse":
            return {"result": data[::-1], "method": method}
        if method == "octal":
            return {"result": " ".join(f"\\{byte:03o}" for byte in b), "method": method}
        return {"result": "", "method": method, "error": f"Unknown method: {method}"}
    except Exception as exc:
        return {"result": "", "method": method, "error": str(exc)}


def decode(data: str, method: str) -> dict:
    """Decode data using method. Returns {result, method, error?}."""
    try:
        if method == "base64":
            # Add padding if needed
            pad = (4 - len(data) % 4) % 4
            return {"result": base64.b64decode(data + "=" * pad).decode("utf-8", errors="replace"),
                    "method": method}
        if method == "base64url":
            pad = (4 - len(data) % 4) % 4
            return {"result": base64.urlsafe_b64decode(data + "=" * pad).decode("utf-8", errors="replace"),
                    "method": method}
        if method == "url":
            return {"result": urllib.parse.unquote(data), "method": method}
        if method == "url_form":
            return {"result": urllib.parse.unquote_plus(data), "method": method}
        if method == "html":
            return {"result": html.unescape(data), "method": method}
        if method == "hex":
            clean = data.replace(" ", "").replace("0x", "").replace("\\x", "")
            return {"result": bytes.fromhex(clean).decode("utf-8", errors="replace"), "method": method}
        if method == "binary":
            bits = data.replace(" ", "")
            n = int(bits, 2) if bits else 0
            byte_len = (len(bits) + 7) // 8
            return {"result": n.to_bytes(byte_len, "big").decode("utf-8", errors="replace"),
                    "method": method}
        if method == "gzip":
            raw = base64.b64decode(data + "==")
            buf = io.BytesIO(raw)
            with gzip.GzipFile(fileobj=buf, mode="rb") as gz:
                return {"result": gz.read().decode("utf-8", errors="replace"), "method": method}
        if method == "zlib":
            raw = base64.b64decode(data + "==")
            return {"result": zlib.decompress(raw).decode("utf-8", errors="replace"), "method": method}
        if method == "unicode_escape":
            return {"result": data.encode().decode("unicode_escape"), "method": method}
        if method == "rot13":
            return {"result": codecs.encode(data, "rot_13"), "method": method}
        if method == "reverse":
            return {"result": data[::-1], "method": method}
        return {"result": "", "method": method, "error": f"Unknown method: {method}"}
    except Exception as exc:
        return {"result": "", "method": method, "error": str(exc)}


def hash_data(data: str, algorithm: str) -> dict:
    """Hash data with algorithm. Returns {result, algorithm, hex_digest}."""
    try:
        b = data.encode("utf-8")
        if algorithm == "md5":
            digest = hashlib.md5(b).hexdigest()
        elif algorithm == "sha1":
            digest = hashlib.sha1(b).hexdigest()
        elif algorithm == "sha256":
            digest = hashlib.sha256(b).hexdigest()
        elif algorithm == "sha512":
            digest = hashlib.sha512(b).hexdigest()
        elif algorithm == "sha3_256":
            digest = hashlib.sha3_256(b).hexdigest()
        elif algorithm == "sha3_512":
            digest = hashlib.sha3_512(b).hexdigest()
        else:
            return {"result": "", "algorithm": algorithm, "error": f"Unknown algorithm: {algorithm}"}
        return {"result": digest, "algorithm": algorithm, "length": len(digest) // 2}
    except Exception as exc:
        return {"result": "", "algorithm": algorithm, "error": str(exc)}


def jwt_decode(token: str) -> dict:
    """Decode a JWT token (no signature verification)."""
    try:
        parts = token.strip().split(".")
        if len(parts) < 2:
            return {"error": "Invalid JWT format (expected header.payload.signature)"}

        def _decode_part(part: str) -> dict:
            pad = (4 - len(part) % 4) % 4
            raw = base64.urlsafe_b64decode(part + "=" * pad)
            return json.loads(raw)

        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
        sig_raw = parts[2] if len(parts) > 2 else ""
        signature_b64 = sig_raw

        result = {
            "header": header,
            "payload": payload,
            "signature_b64": signature_b64,
            "parts": len(parts),
        }

        # Check expiration
        if "exp" in payload:
            import time
            exp = payload["exp"]
            now = time.time()
            result["expired"] = now > exp
            result["exp_human"] = _ts_human(exp)
        if "iat" in payload:
            result["iat_human"] = _ts_human(payload["iat"])
        if "nbf" in payload:
            result["nbf_human"] = _ts_human(payload["nbf"])

        return result
    except Exception as exc:
        return {"error": str(exc)}


def _ts_human(ts) -> str:
    import time
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(float(ts)))
    except Exception:
        return str(ts)


def detect_encoding(data: str) -> list:
    """Heuristically detect likely encodings of the input."""
    detected = []
    stripped = data.strip()

    # Base64
    if re.match(r"^[A-Za-z0-9+/]+=*$", stripped) and len(stripped) % 4 == 0:
        detected.append("base64")
    # Base64URL
    if re.match(r"^[A-Za-z0-9\-_]*$", stripped) and len(stripped) > 4:
        detected.append("base64url")
    # Hex
    if re.match(r"^[0-9a-fA-F]+$", stripped.replace(" ", "")) and len(stripped.replace(" ", "")) % 2 == 0:
        detected.append("hex")
    # URL encoded
    if "%" in stripped and re.search(r"%[0-9a-fA-F]{2}", stripped):
        detected.append("url")
    # HTML entities
    if "&amp;" in stripped or "&lt;" in stripped or "&#" in stripped:
        detected.append("html")
    # JWT
    if stripped.count(".") == 2 and all(re.match(r"^[A-Za-z0-9\-_]+$", p) for p in stripped.split(".")):
        detected.append("jwt")
    # Binary
    if re.match(r"^[01 ]+$", stripped) and len(stripped.replace(" ", "")) % 8 == 0:
        detected.append("binary")

    return detected or ["unknown"]
