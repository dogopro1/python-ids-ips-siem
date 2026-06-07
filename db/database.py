import sqlite3
import threading
import os
import time
import json

_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "ids.db")


class Database:
    _instance = None
    _singleton_lock = threading.Lock()

    def __init__(self, path: str = _DB_PATH):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA cache_size=-8192")
        self._write_lock = threading.Lock()
        self._packet_batch: list = []
        self._batch_lock = threading.Lock()
        self._stop = threading.Event()
        self._flush_thread = threading.Thread(target=self._flush_loop, daemon=True, name="DB-Flush")
        self._create_tables()
        self._flush_thread.start()

    @classmethod
    def get(cls) -> "Database":
        if cls._instance is None:
            with cls._singleton_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls):
        cls._instance = None

    def _create_tables(self):
        with self._write_lock:
            self._conn.executescript("""
                -- ── Original tables ──────────────────────────────────────────
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
                    protocol TEXT, tcp_flags INTEGER, size INTEGER,
                    timestamp REAL, src_hostname TEXT, service TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_pkt_src ON packets(src_ip);
                CREATE INDEX IF NOT EXISTS idx_pkt_ts  ON packets(timestamp);

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT, src_ip TEXT, message TEXT,
                    severity TEXT, timestamp REAL
                );
                CREATE INDEX IF NOT EXISTS idx_alt_src  ON alerts(src_ip);
                CREATE INDEX IF NOT EXISTS idx_alt_type ON alerts(type);
                CREATE INDEX IF NOT EXISTS idx_alt_ts   ON alerts(timestamp);

                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT, blocked_at REAL, unblocked_at REAL,
                    reason TEXT, block_type TEXT DEFAULT 'auto',
                    timeout_sec INTEGER DEFAULT 600, active INTEGER DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_blk_ip ON blocked_ips(ip);

                CREATE TABLE IF NOT EXISTS whitelist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE, added_at REAL, note TEXT
                );

                CREATE TABLE IF NOT EXISTS blacklist_manual (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE, added_at REAL, note TEXT
                );

                CREATE TABLE IF NOT EXISTS domain_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT, scan_data TEXT, scanned_at REAL
                );

                CREATE TABLE IF NOT EXISTS dns_cache (
                    ip TEXT PRIMARY KEY, hostname TEXT, resolved_at REAL
                );

                CREATE TABLE IF NOT EXISTS ip_analysis_cache (
                    ip TEXT PRIMARY KEY, data TEXT, cached_at REAL
                );

                -- ── Module 1: Intercepting Proxy ──────────────────────────────
                CREATE TABLE IF NOT EXISTS proxy_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    method TEXT, scheme TEXT, host TEXT, port INTEGER,
                    path TEXT, req_headers TEXT, req_body TEXT,
                    resp_status INTEGER, resp_headers TEXT, resp_body TEXT,
                    client_ip TEXT, timestamp REAL
                );
                CREATE INDEX IF NOT EXISTS idx_prx_host ON proxy_requests(host);
                CREATE INDEX IF NOT EXISTS idx_prx_ts   ON proxy_requests(timestamp);

                -- ── Module 3: Threat Intelligence cache ───────────────────────
                CREATE TABLE IF NOT EXISTS intel_cache (
                    cache_key TEXT PRIMARY KEY,
                    data TEXT,
                    cached_at REAL
                );

                -- ── Module 5: ARP events ───────────────────────────────────────
                CREATE TABLE IF NOT EXISTS arp_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT, severity TEXT, ip TEXT,
                    old_mac TEXT, new_mac TEXT,
                    is_gratuitous INTEGER DEFAULT 0,
                    message TEXT, timestamp REAL
                );
                CREATE INDEX IF NOT EXISTS idx_arp_ip ON arp_events(ip);
                CREATE INDEX IF NOT EXISTS idx_arp_ts ON arp_events(timestamp);

                -- ── Module 5: Network devices ─────────────────────────────────
                CREATE TABLE IF NOT EXISTS network_devices (
                    ip TEXT PRIMARY KEY,
                    mac TEXT, hostname TEXT, vendor TEXT,
                    first_seen REAL, last_seen REAL, status TEXT
                );

                -- ── Module 6: Vulnerability scan results ──────────────────────
                CREATE TABLE IF NOT EXISTS vuln_scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT, scan_data TEXT, risk_score INTEGER,
                    findings_count INTEGER, scanned_at REAL
                );
                CREATE INDEX IF NOT EXISTS idx_vuln_url ON vuln_scans(url);
                CREATE INDEX IF NOT EXISTS idx_vuln_ts  ON vuln_scans(scanned_at);
            """)
            self._conn.commit()

    # ── Packet batch write ─────────────────────────────────────────────────────

    def queue_packet(self, packet: dict, hostname: str = None, service: str = None):
        with self._batch_lock:
            self._packet_batch.append((packet, hostname, service))

    def _flush_loop(self):
        while not self._stop.is_set():
            self._stop.wait(10)
            self._flush_packets()

    def _flush_packets(self):
        with self._batch_lock:
            batch = self._packet_batch[:]
            self._packet_batch.clear()
        if not batch:
            return
        rows = [
            (p.get("src_ip"), p.get("dst_ip"), p.get("dst_port"),
             p.get("protocol"), p.get("tcp_flags"), p.get("size"),
             p.get("timestamp"), h, s)
            for p, h, s in batch
        ]
        with self._write_lock:
            try:
                self._conn.executemany(
                    "INSERT INTO packets (src_ip,dst_ip,dst_port,protocol,tcp_flags,size,timestamp,src_hostname,service) VALUES (?,?,?,?,?,?,?,?,?)",
                    rows,
                )
                self._conn.execute(
                    "DELETE FROM packets WHERE id <= (SELECT id FROM packets ORDER BY id DESC LIMIT 1 OFFSET 100000)"
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ── Alerts ─────────────────────────────────────────────────────────────────

    def insert_alert(self, alert: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT INTO alerts (type,src_ip,message,severity,timestamp) VALUES (?,?,?,?,?)",
                    (alert.get("type"), alert.get("src_ip"), alert.get("message"),
                     alert.get("severity"), alert.get("timestamp")),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ── Firewall ───────────────────────────────────────────────────────────────

    def insert_blocked(self, ip: str, reason: str = None, block_type: str = "auto", timeout: int = 600):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT INTO blocked_ips (ip,blocked_at,reason,block_type,timeout_sec,active) VALUES (?,?,?,?,?,1)",
                    (ip, time.time(), reason, block_type, timeout),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def mark_unblocked(self, ip: str):
        with self._write_lock:
            try:
                self._conn.execute(
                    "UPDATE blocked_ips SET unblocked_at=?,active=0 WHERE ip=? AND active=1",
                    (time.time(), ip),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ── Query: alerts ──────────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 200, severity: str = None, search: str = None,
                   alert_type: str = None, from_ts: float = None, to_ts: float = None) -> list:
        q = "SELECT * FROM alerts WHERE 1=1"
        p: list = []
        if severity:
            q += " AND severity=?"; p.append(severity)
        if alert_type:
            q += " AND type=?"; p.append(alert_type)
        if search:
            q += " AND (message LIKE ? OR src_ip LIKE ? OR type LIKE ?)"
            p += [f"%{search}%"] * 3
        if from_ts is not None:
            q += " AND timestamp>=?"; p.append(from_ts)
        if to_ts is not None:
            q += " AND timestamp<=?"; p.append(to_ts)
        q += " ORDER BY timestamp DESC LIMIT ?"
        p.append(limit)
        return [dict(r) for r in self._conn.execute(q, p).fetchall()]

    # ── Query: packets ─────────────────────────────────────────────────────────

    def get_packets(self, limit: int = 200, protocol: str = None, src_ip: str = None,
                    dst_ip: str = None, dst_port: int = None,
                    from_ts: float = None, to_ts: float = None) -> list:
        q = "SELECT * FROM packets WHERE 1=1"
        p: list = []
        if protocol:
            q += " AND protocol=?"; p.append(protocol)
        if src_ip:
            q += " AND (src_ip=? OR dst_ip=?)"; p += [src_ip, src_ip]
        if dst_ip:
            q += " AND dst_ip=?"; p.append(dst_ip)
        if dst_port is not None:
            q += " AND dst_port=?"; p.append(dst_port)
        if from_ts is not None:
            q += " AND timestamp>=?"; p.append(from_ts)
        if to_ts is not None:
            q += " AND timestamp<=?"; p.append(to_ts)
        q += " ORDER BY timestamp DESC LIMIT ?"
        p.append(limit)
        return [dict(r) for r in self._conn.execute(q, p).fetchall()]

    # ── Query: firewall ────────────────────────────────────────────────────────

    def get_blocked_history(self, limit: int = 200) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC LIMIT ?", (limit,)
        ).fetchall()]

    def get_active_blocked(self) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM blocked_ips WHERE active=1 ORDER BY blocked_at DESC"
        ).fetchall()]

    # ── Whitelist / Blacklist ──────────────────────────────────────────────────

    def get_whitelist(self) -> list:
        return [dict(r) for r in self._conn.execute("SELECT * FROM whitelist ORDER BY added_at DESC").fetchall()]

    def add_whitelist(self, ip: str, note: str = None):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO whitelist (ip,added_at,note) VALUES (?,?,?)",
                    (ip, time.time(), note),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def remove_whitelist(self, ip: str):
        with self._write_lock:
            try:
                self._conn.execute("DELETE FROM whitelist WHERE ip=?", (ip,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def is_whitelisted(self, ip: str) -> bool:
        return self._conn.execute("SELECT 1 FROM whitelist WHERE ip=?", (ip,)).fetchone() is not None

    def get_blacklist(self) -> list:
        return [dict(r) for r in self._conn.execute("SELECT * FROM blacklist_manual ORDER BY added_at DESC").fetchall()]

    def add_blacklist(self, ip: str, note: str = None):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO blacklist_manual (ip,added_at,note) VALUES (?,?,?)",
                    (ip, time.time(), note),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def remove_blacklist(self, ip: str):
        with self._write_lock:
            try:
                self._conn.execute("DELETE FROM blacklist_manual WHERE ip=?", (ip,))
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ── Statistics ─────────────────────────────────────────────────────────────

    def get_stats_summary(self) -> dict:
        now = time.time()
        d = now - 86400
        return {
            "total_packets_db": self._conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0],
            "total_alerts_db": self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0],
            "alerts_24h": self._conn.execute("SELECT COUNT(*) FROM alerts WHERE timestamp>?", (d,)).fetchone()[0],
            "packets_24h": self._conn.execute("SELECT COUNT(*) FROM packets WHERE timestamp>?", (d,)).fetchone()[0],
            "blocked_total": self._conn.execute("SELECT COUNT(*) FROM blocked_ips").fetchone()[0],
            "blocked_active": self._conn.execute("SELECT COUNT(*) FROM blocked_ips WHERE active=1").fetchone()[0],
            "proxy_requests": self._conn.execute("SELECT COUNT(*) FROM proxy_requests").fetchone()[0],
            "vuln_scans": self._conn.execute("SELECT COUNT(*) FROM vuln_scans").fetchone()[0],
            "network_devices": self._conn.execute("SELECT COUNT(*) FROM network_devices").fetchone()[0],
            "arp_events": self._conn.execute("SELECT COUNT(*) FROM arp_events").fetchone()[0],
        }

    def get_top_ports(self, limit: int = 10) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT dst_port,COUNT(*) cnt FROM packets WHERE dst_port>0 GROUP BY dst_port ORDER BY cnt DESC LIMIT ?",
            (limit,)
        ).fetchall()]

    def get_top_sources(self, limit: int = 10) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT src_ip,COUNT(*) cnt FROM packets GROUP BY src_ip ORDER BY cnt DESC LIMIT ?",
            (limit,)
        ).fetchall()]

    def get_alert_types(self) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT type,severity,COUNT(*) cnt FROM alerts GROUP BY type,severity ORDER BY cnt DESC"
        ).fetchall()]

    def get_timeline(self, hours: int = 24) -> list:
        now = time.time()
        start = now - hours * 3600
        return [dict(r) for r in self._conn.execute(
            """SELECT CAST((timestamp-?)/3600 AS INTEGER) h, COUNT(*) cnt
               FROM packets WHERE timestamp>? GROUP BY h ORDER BY h""",
            (start, start),
        ).fetchall()]

    def get_ip_history(self, ip: str) -> dict:
        pkts = [dict(r) for r in self._conn.execute(
            "SELECT * FROM packets WHERE src_ip=? OR dst_ip=? ORDER BY timestamp DESC LIMIT 100",
            (ip, ip),
        ).fetchall()]
        alts = [dict(r) for r in self._conn.execute(
            "SELECT * FROM alerts WHERE src_ip=? ORDER BY timestamp DESC LIMIT 50", (ip,)
        ).fetchall()]
        blk = [dict(r) for r in self._conn.execute(
            "SELECT * FROM blocked_ips WHERE ip=? ORDER BY blocked_at DESC LIMIT 20", (ip,)
        ).fetchall()]
        return {"packets": pkts, "alerts": alts, "blocked_history": blk}

    # ── Domain scans ───────────────────────────────────────────────────────────

    def save_domain_scan(self, url: str, data: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT INTO domain_scans (url,scan_data,scanned_at) VALUES (?,?,?)",
                    (url, json.dumps(data, default=str), time.time()),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def get_domain_history(self, limit: int = 20) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT id,url,scanned_at FROM domain_scans ORDER BY scanned_at DESC LIMIT ?", (limit,)
        ).fetchall()]

    # ── DNS / IP cache ─────────────────────────────────────────────────────────

    def cache_hostname(self, ip: str, hostname: str):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO dns_cache (ip,hostname,resolved_at) VALUES (?,?,?)",
                    (ip, hostname, time.time()),
                )
                self._conn.commit()
            except Exception:
                pass

    def get_cached_hostname(self, ip: str):
        r = self._conn.execute(
            "SELECT hostname,resolved_at FROM dns_cache WHERE ip=?", (ip,)
        ).fetchone()
        if r and time.time() - r["resolved_at"] < 3600:
            return r["hostname"]
        return None

    def cache_ip_analysis(self, ip: str, data: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO ip_analysis_cache (ip,data,cached_at) VALUES (?,?,?)",
                    (ip, json.dumps(data, default=str), time.time()),
                )
                self._conn.commit()
            except Exception:
                pass

    def get_cached_ip_analysis(self, ip: str):
        r = self._conn.execute(
            "SELECT data,cached_at FROM ip_analysis_cache WHERE ip=?", (ip,)
        ).fetchone()
        if r and time.time() - r["cached_at"] < 1800:
            return json.loads(r["data"])
        return None

    # ── Module 1: Proxy requests ───────────────────────────────────────────────

    def save_proxy_request(self, req: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    """INSERT INTO proxy_requests
                       (method,scheme,host,port,path,req_headers,req_body,
                        resp_status,resp_headers,resp_body,client_ip,timestamp)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (req.get("method"), req.get("scheme"), req.get("host"), req.get("port"),
                     req.get("path"), req.get("req_headers"), req.get("req_body"),
                     req.get("resp_status"), req.get("resp_headers"), req.get("resp_body"),
                     req.get("client_ip"), req.get("timestamp", time.time())),
                )
                # Prune old rows
                self._conn.execute(
                    "DELETE FROM proxy_requests WHERE id <= "
                    "(SELECT id FROM proxy_requests ORDER BY id DESC LIMIT 1 OFFSET 5000)"
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def get_proxy_requests(self, limit: int = 100, host: str = None,
                           method: str = None, status: int = None) -> list:
        q = "SELECT * FROM proxy_requests WHERE 1=1"
        p = []
        if host:
            q += " AND host LIKE ?"; p.append(f"%{host}%")
        if method:
            q += " AND method=?"; p.append(method.upper())
        if status:
            q += " AND resp_status=?"; p.append(status)
        q += " ORDER BY timestamp DESC LIMIT ?"
        p.append(limit)
        return [dict(r) for r in self._conn.execute(q, p).fetchall()]

    def get_proxy_request_by_id(self, rid: int) -> dict:
        r = self._conn.execute("SELECT * FROM proxy_requests WHERE id=?", (rid,)).fetchone()
        return dict(r) if r else {}

    # ── Module 3: Threat intel cache ──────────────────────────────────────────

    def get_intel_cache(self, cache_key: str, ttl: int = 3600):
        r = self._conn.execute(
            "SELECT data,cached_at FROM intel_cache WHERE cache_key=?", (cache_key,)
        ).fetchone()
        if r and time.time() - r["cached_at"] < ttl:
            try:
                return json.loads(r["data"])
            except Exception:
                return None
        return None

    def set_intel_cache(self, cache_key: str, data: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO intel_cache (cache_key,data,cached_at) VALUES (?,?,?)",
                    (cache_key, json.dumps(data, default=str), time.time()),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    # ── Module 5: ARP events ───────────────────────────────────────────────────

    def save_arp_event(self, event: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    """INSERT INTO arp_events
                       (type,severity,ip,old_mac,new_mac,is_gratuitous,message,timestamp)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (event.get("type"), event.get("severity"), event.get("ip"),
                     event.get("old_mac"), event.get("new_mac"),
                     1 if event.get("is_gratuitous") else 0,
                     event.get("message"), event.get("timestamp", time.time())),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def get_arp_events(self, limit: int = 100) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM arp_events ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()]

    # ── Module 5: Network devices ──────────────────────────────────────────────

    def upsert_network_device(self, dev: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    """INSERT INTO network_devices (ip,mac,hostname,vendor,first_seen,last_seen,status)
                       VALUES (?,?,?,?,?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET
                         mac=excluded.mac, hostname=excluded.hostname,
                         vendor=excluded.vendor, last_seen=excluded.last_seen,
                         status=excluded.status""",
                    (dev.get("ip"), dev.get("mac"), dev.get("hostname"),
                     dev.get("vendor"), dev.get("first_seen", time.time()),
                     dev.get("last_seen", time.time()), dev.get("status", "up")),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def get_network_devices(self) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT * FROM network_devices ORDER BY last_seen DESC"
        ).fetchall()]

    # ── Module 6: Vulnerability scans ─────────────────────────────────────────

    def save_vuln_scan(self, url: str, data: dict):
        with self._write_lock:
            try:
                self._conn.execute(
                    """INSERT INTO vuln_scans (url,scan_data,risk_score,findings_count,scanned_at)
                       VALUES (?,?,?,?,?)""",
                    (url, json.dumps(data, default=str),
                     data.get("risk_score", 0), len(data.get("findings", [])),
                     time.time()),
                )
                self._conn.commit()
            except Exception:
                self._conn.rollback()

    def get_vuln_scans(self, limit: int = 20) -> list:
        return [dict(r) for r in self._conn.execute(
            "SELECT id,url,risk_score,findings_count,scanned_at FROM vuln_scans ORDER BY scanned_at DESC LIMIT ?",
            (limit,)
        ).fetchall()]

    def get_vuln_scan_detail(self, scan_id: int) -> dict:
        r = self._conn.execute("SELECT * FROM vuln_scans WHERE id=?", (scan_id,)).fetchone()
        if r:
            d = dict(r)
            try:
                d["scan_data"] = json.loads(d["scan_data"])
            except Exception:
                pass
            return d
        return {}

    # ── Export ─────────────────────────────────────────────────────────────────

    def export_alerts_csv(self) -> str:
        rows = self._conn.execute(
            "SELECT type,src_ip,message,severity,timestamp FROM alerts ORDER BY timestamp DESC"
        ).fetchall()
        lines = ["type,src_ip,message,severity,timestamp"]
        for r in rows:
            ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["timestamp"]))
            lines.append(f"{r['type']},{r['src_ip']},\"{r['message']}\",{r['severity']},{ts}")
        return "\n".join(lines)

    def close(self):
        self._stop.set()
        self._flush_packets()
        if self._conn:
            self._conn.close()
