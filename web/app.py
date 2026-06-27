import logging
import ipaddress
import os
import threading
from flask import Flask, render_template, jsonify, request, Response

logger = logging.getLogger("ids_ips")

app = Flask(__name__, template_folder="templates", static_folder="static")

_sniffer = None
_ids = None
_ips = None
_conn_tracker = None
_traffic_series = None


def init_app(sniffer, ids, ips, conn_tracker=None, traffic_series=None) -> None:
    global _sniffer, _ids, _ips, _conn_tracker, _traffic_series
    _sniffer = sniffer
    _ids = ids
    _ips = ips
    _conn_tracker = conn_tracker
    _traffic_series = traffic_series


def _get_db():
    try:
        from db.database import Database
        return Database.get()
    except Exception:
        return None


def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


@app.after_request
def _security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("Server", None)
    return response


# ── Pages ──────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


# ── Core monitoring ────────────────────────────────────────────────────────────

@app.route("/api/packets")
def api_packets():
    try:
        limit = min(int(request.args.get("limit", 20)), 200)
        if _sniffer is None:
            return jsonify([])
        packets = _sniffer.get_recent_packets(limit)
        try:
            from utils.dns_resolver import DNSResolver
            resolver = DNSResolver.get()
            for p in packets:
                src = p.get("src_ip", "")
                h = resolver.resolve_async(src)
                if h and h != src:
                    p["src_hostname"] = h
        except Exception:
            pass
        return jsonify(packets)
    except Exception as e:
        logger.error("GET /api/packets: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/stats")
def api_stats():
    try:
        if _ids is None:
            return jsonify({})
        stats = _ids.get_stats()
        if _conn_tracker is not None:
            stats["active_connections"] = _conn_tracker.get_active_count()
            stats["total_connections"] = _conn_tracker.total_seen
        try:
            from proxy.intercepting_proxy import get_stats as proxy_stats
            stats["proxy"] = proxy_stats()
        except Exception:
            pass
        return jsonify(stats)
    except Exception as e:
        logger.error("GET /api/stats: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/blocked")
def api_blocked():
    try:
        if _ips is None:
            return jsonify([])
        return jsonify(_ips.get_blocked())
    except Exception as e:
        logger.error("GET /api/blocked: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/alerts")
def api_alerts():
    try:
        limit = min(int(request.args.get("limit", 50)), 500)
        severity = request.args.get("severity")
        search = request.args.get("search")
        alert_type = request.args.get("type")
        from_ts = float(request.args["from_ts"]) if request.args.get("from_ts") else None
        to_ts = float(request.args["to_ts"]) if request.args.get("to_ts") else None
        db = _get_db()
        if db is not None:
            return jsonify(db.get_alerts(limit=limit, severity=severity, search=search,
                                         alert_type=alert_type, from_ts=from_ts, to_ts=to_ts))
        if _ids is None:
            return jsonify([])
        return jsonify(_ids.get_alerts(limit))
    except Exception as e:
        logger.error("GET /api/alerts: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/health")
def api_health():
    try:
        sniffer_ok = _sniffer is not None and not _sniffer.degraded
        degraded = _sniffer is not None and _sniffer.degraded
        try:
            from proxy.intercepting_proxy import get_stats as ps
            proxy_running = ps().get("running", False)
        except Exception:
            proxy_running = False
        try:
            from network.arp_monitor import _running as arp_running
        except Exception:
            arp_running = False
        return jsonify({
            "sniffer": sniffer_ok,
            "ids": _ids is not None,
            "ips": _ips is not None,
            "degraded": degraded,
            "proxy": proxy_running,
            "arp_monitor": arp_running,
        })
    except Exception as e:
        logger.error("GET /api/health: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/traffic/series")
def api_traffic_series():
    try:
        if _traffic_series is None:
            return jsonify([])
        return jsonify(_traffic_series.get_series())
    except Exception as e:
        logger.error("GET /api/traffic/series: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Connections ────────────────────────────────────────────────────────────────

@app.route("/api/connections")
def api_connections():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        if _conn_tracker is None:
            return jsonify([])
        return jsonify(_conn_tracker.get_connections(limit))
    except Exception as e:
        logger.error("GET /api/connections: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/connections/top")
def api_top_talkers():
    try:
        limit = min(int(request.args.get("limit", 10)), 50)
        if _conn_tracker is None:
            return jsonify([])
        return jsonify(_conn_tracker.get_top_talkers(limit))
    except Exception as e:
        logger.error("GET /api/connections/top: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Statistics / DB ────────────────────────────────────────────────────────────

@app.route("/api/db/stats")
def api_db_stats():
    try:
        db = _get_db()
        if db is None:
            return jsonify({})
        return jsonify(db.get_stats_summary())
    except Exception as e:
        logger.error("GET /api/db/stats: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/db/top_ports")
def api_db_top_ports():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_top_ports(10))
    except Exception as e:
        logger.error("GET /api/db/top_ports: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/db/top_sources")
def api_top_sources():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_top_sources(10))
    except Exception as e:
        logger.error("GET /api/db/top_sources: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/db/alert_types")
def api_alert_types():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_alert_types())
    except Exception as e:
        logger.error("GET /api/db/alert_types: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/db/timeline")
def api_timeline():
    try:
        hours = min(int(request.args.get("hours", 24)), 168)
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_timeline(hours))
    except Exception as e:
        logger.error("GET /api/db/timeline: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/db/packets")
def api_db_packets():
    try:
        limit = min(int(request.args.get("limit", 200)), 2000)
        protocol = request.args.get("protocol")
        src_ip = request.args.get("src_ip")
        dst_ip = request.args.get("dst_ip")
        dst_port = int(request.args["dst_port"]) if request.args.get("dst_port") else None
        from_ts = float(request.args["from_ts"]) if request.args.get("from_ts") else None
        to_ts = float(request.args["to_ts"]) if request.args.get("to_ts") else None
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_packets(limit=limit, protocol=protocol, src_ip=src_ip,
                                      dst_ip=dst_ip, dst_port=dst_port,
                                      from_ts=from_ts, to_ts=to_ts))
    except Exception as e:
        logger.error("GET /api/db/packets: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── IP Analysis ────────────────────────────────────────────────────────────────

@app.route("/api/ip/analyze")
def api_ip_analyze():
    try:
        ip = request.args.get("ip", "").strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        result = {"ip": ip}
        try:
            from utils.geo_lookup import lookup
            result["geo"] = lookup(ip)
        except Exception as e:
            result["geo"] = {"error": str(e)}
        try:
            from utils.dns_resolver import DNSResolver
            result["hostname"] = DNSResolver.get().resolve_sync(ip)
        except Exception:
            result["hostname"] = None
        db = _get_db()
        if db is not None:
            result["history"] = db.get_ip_history(ip)
        else:
            result["history"] = {}
        if _ips is not None:
            result["is_blocked"] = _ips.is_blocked(ip)
        if db is not None:
            result["is_whitelisted"] = db.is_whitelisted(ip)
        return jsonify(result)
    except Exception as e:
        logger.error("GET /api/ip/analyze: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/ip/history")
def api_ip_history():
    try:
        ip = request.args.get("ip", "").strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        db = _get_db()
        if db is None:
            return jsonify({})
        return jsonify(db.get_ip_history(ip))
    except Exception as e:
        logger.error("GET /api/ip/history: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Domain / URL Scanner ───────────────────────────────────────────────────────

@app.route("/api/scan/domain", methods=["POST"])
def api_scan_domain():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        from utils.scanner import analyze
        result = analyze(url)
        db = _get_db()
        if db is not None:
            try:
                db.save_domain_scan(url, result)
            except Exception:
                pass
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/scan/domain: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/scan/history")
def api_scan_history():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_domain_history())
    except Exception as e:
        logger.error("GET /api/scan/history: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/scan/tech", methods=["POST"])
def api_scan_tech():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        from utils.scanner import analyze, detect_tech
        result = analyze(url, crawl=True, save_html=True)
        headers = {
            "server": result.get("server", ""),
            "x-powered-by": (result.get("security_headers") or {}).get("X-Powered-By", {}).get("value", ""),
        }
        result["tech"] = detect_tech(result.get("html_preview") or "", headers)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/scan/tech: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/scan/crawl", methods=["POST"])
def api_scan_crawl():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        max_pages = min(int(body.get("max_pages", 8)), 20)
        fake_ua = bool(body.get("fake_ua", True))
        if not url:
            return jsonify({"error": "url required"}), 400
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        from utils.scanner import crawl_anon
        return jsonify(crawl_anon(url, max_pages=max_pages, fake_ua=fake_ua))
    except Exception as e:
        logger.error("POST /api/scan/crawl: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/scan/scrape", methods=["POST"])
def api_scan_scrape():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        save_dir = str(body.get("save_dir", "")).strip()
        include_assets = bool(body.get("include_assets", False))
        if not url:
            return jsonify({"error": "url required"}), 400
        if not save_dir:
            return jsonify({"error": "save_dir required"}), 400
        save_dir = os.path.realpath(save_dir)
        from utils.scanner import scrape_page
        result = scrape_page(url, save_dir, include_assets=include_assets)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/scan/scrape: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Network Tools ──────────────────────────────────────────────────────────────

@app.route("/api/tools/ping", methods=["POST"])
def api_ping():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        count = min(int(body.get("count", 4)), 10)
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import ping
        return jsonify(ping(host, count))
    except Exception as e:
        logger.error("POST /api/tools/ping: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/traceroute", methods=["POST"])
def api_traceroute():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import traceroute
        return jsonify(traceroute(host))
    except Exception as e:
        logger.error("POST /api/tools/traceroute: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/nslookup", methods=["POST"])
def api_nslookup():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import dns_lookup_all
        return jsonify(dns_lookup_all(host))
    except Exception as e:
        logger.error("POST /api/tools/nslookup: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/whois", methods=["POST"])
def api_whois():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import whois
        return jsonify(whois(host))
    except Exception as e:
        logger.error("POST /api/tools/whois: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/portscan", methods=["POST"])
def api_portscan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports_raw = body.get("ports", "1-1024")
        timing = int(body.get("timing", 3))
        banner = bool(body.get("banner", True))
        os_detect = bool(body.get("os_detect", False))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import port_scan
        return jsonify(port_scan(host, str(ports_raw), timing=timing,
                                 banner=banner, os_detect=os_detect))
    except Exception as e:
        logger.error("POST /api/tools/portscan: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/udpscan", methods=["POST"])
def api_udpscan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "53,67,123,161,500,1900"))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import udp_scan
        return jsonify(udp_scan(host, ports))
    except Exception as e:
        logger.error("POST /api/tools/udpscan: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/banner", methods=["POST"])
def api_banner():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        port = int(body.get("port", 80))
        use_ssl = bool(body.get("ssl", False))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import banner_grab
        banner = banner_grab(host, port, use_ssl=use_ssl)
        return jsonify({"host": host, "port": port, "banner": banner})
    except Exception as e:
        logger.error("POST /api/tools/banner: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/osfingerprint", methods=["POST"])
def api_osfingerprint():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import os_fingerprint
        return jsonify(os_fingerprint(host))
    except Exception as e:
        logger.error("POST /api/tools/osfingerprint: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/arpscan", methods=["POST"])
def api_arpscan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        subnet = body.get("subnet")
        from utils.net_tools import arp_scan
        return jsonify(arp_scan(subnet))
    except Exception as e:
        logger.error("POST /api/tools/arpscan: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Firewall Management ────────────────────────────────────────────────────────

@app.route("/api/firewall/block", methods=["POST"])
def api_firewall_block():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        reason = str(body.get("reason", "manual")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        if _ips is None:
            return jsonify({"error": "IPS not initialized"}), 503
        ok = _ips.block_manual(ip, reason=reason)
        if not ok:
            return jsonify({"error": "IP already blocked or whitelisted"}), 409
        return jsonify({"status": "blocked", "ip": ip})
    except Exception as e:
        logger.error("POST /api/firewall/block: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/firewall/unblock", methods=["POST"])
def api_firewall_unblock():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        if _ips is None:
            return jsonify({"error": "IPS not initialized"}), 503
        ok = _ips.unblock_manual(ip)
        if not ok:
            return jsonify({"error": "IP not currently blocked"}), 404
        return jsonify({"status": "unblocked", "ip": ip})
    except Exception as e:
        logger.error("POST /api/firewall/unblock: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/firewall/blocked_history")
def api_blocked_history():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_blocked_history())
    except Exception as e:
        logger.error("GET /api/firewall/blocked_history: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Whitelist / Blacklist ──────────────────────────────────────────────────────

@app.route("/api/whitelist", methods=["GET"])
def api_whitelist_get():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_whitelist())
    except Exception as e:
        logger.error("GET /api/whitelist: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/whitelist", methods=["POST"])
def api_whitelist_add():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        note = str(body.get("note", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        db.add_whitelist(ip, note or None)
        return jsonify({"status": "added", "ip": ip})
    except Exception as e:
        logger.error("POST /api/whitelist: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/whitelist", methods=["DELETE"])
def api_whitelist_remove():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        db.remove_whitelist(ip)
        return jsonify({"status": "removed", "ip": ip})
    except Exception as e:
        logger.error("DELETE /api/whitelist: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/blacklist", methods=["GET"])
def api_blacklist_get():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_blacklist())
    except Exception as e:
        logger.error("GET /api/blacklist: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/blacklist", methods=["POST"])
def api_blacklist_add():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        note = str(body.get("note", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        db.add_blacklist(ip, note or None)
        return jsonify({"status": "added", "ip": ip})
    except Exception as e:
        logger.error("POST /api/blacklist: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/blacklist", methods=["DELETE"])
def api_blacklist_remove():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        db.remove_blacklist(ip)
        return jsonify({"status": "removed", "ip": ip})
    except Exception as e:
        logger.error("DELETE /api/blacklist: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Module 1: Proxy API ────────────────────────────────────────────────────────

@app.route("/api/proxy/requests")
def api_proxy_requests():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        host = request.args.get("host")
        method = request.args.get("method")
        status = int(request.args["status"]) if request.args.get("status") else None
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_proxy_requests(limit=limit, host=host, method=method, status=status))
    except Exception as e:
        logger.error("GET /api/proxy/requests: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/proxy/request/<int:rid>")
def api_proxy_request_detail(rid: int):
    try:
        db = _get_db()
        if db is None:
            return jsonify({})
        return jsonify(db.get_proxy_request_by_id(rid))
    except Exception as e:
        logger.error("GET /api/proxy/request/%d: %s", rid, e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/proxy/replay", methods=["POST"])
def api_proxy_replay():
    """Repeater: resend a stored request (optionally with modified body/headers)."""
    try:
        body = request.get_json(force=True, silent=True) or {}
        rid = body.get("id")
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        stored = db.get_proxy_request_by_id(int(rid)) if rid else {}
        method = str(body.get("method") or stored.get("method") or "GET").upper()
        scheme = str(body.get("scheme") or stored.get("scheme") or "https")
        host = str(body.get("host") or stored.get("host") or "").strip()
        port = int(body.get("port") or stored.get("port") or 443)
        path = str(body.get("path") or stored.get("path") or "/").strip()
        req_body = body.get("body") or stored.get("req_body") or ""
        extra_headers = body.get("headers") or {}
        if not host:
            return jsonify({"error": "host required"}), 400

        import json as _json
        stored_headers = {}
        try:
            stored_headers = _json.loads(stored.get("req_headers") or "{}")
        except Exception:
            pass
        merged_headers = {**stored_headers, **extra_headers}

        import socket as _sock, ssl as _ssl, time as _time
        url = f"{scheme}://{host}:{port}{path}"
        t0 = _time.time()
        try:
            import requests as _requests
            sess = _requests.Session()
            sess.verify = False
            r = sess.request(method, url, headers=merged_headers,
                             data=req_body.encode() if req_body else None, timeout=15,
                             allow_redirects=False)
            elapsed = (_time.time() - t0) * 1000
            return jsonify({
                "status": r.status_code, "elapsed_ms": round(elapsed, 1),
                "headers": dict(r.headers),
                "body": r.text[:8192],
                "url": url,
            })
        except ImportError:
            return jsonify({"error": "requests library required for replay"}), 503
    except Exception as e:
        logger.error("POST /api/proxy/replay: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/proxy/ca_cert")
def api_proxy_ca_cert():
    """Download the CA certificate for browser import."""
    try:
        from proxy.cert_manager import get_ca_cert_path
        path = get_ca_cert_path()
        if not os.path.exists(path):
            return jsonify({"error": "CA cert not generated yet — start proxy first"}), 404
        with open(path, "rb") as f:
            data = f.read()
        return Response(data, mimetype="application/x-x509-ca-cert",
                        headers={"Content-Disposition": "attachment; filename=ids_ips_ca.crt"})
    except Exception as e:
        logger.error("GET /api/proxy/ca_cert: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/proxy/toggle", methods=["POST"])
def api_proxy_toggle():
    try:
        from proxy.intercepting_proxy import start as proxy_start, stop as proxy_stop, get_stats
        from utils.config_loader import Config
        cfg = Config.load()
        stats = get_stats()
        if stats.get("running"):
            proxy_stop()
            return jsonify({"running": False})
        else:
            ok = proxy_start(cfg.get("proxy_host", "127.0.0.1"),
                             int(cfg.get("proxy_port", 8080)))
            return jsonify({"running": ok})
    except Exception as e:
        logger.error("POST /api/proxy/toggle: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Module 2: DPI API ──────────────────────────────────────────────────────────

@app.route("/api/dpi/streams")
def api_dpi_streams():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        from dpi.tcp_reassembler import TCPReassembler
        return jsonify(TCPReassembler.get().get_all_streams(limit))
    except Exception as e:
        logger.error("GET /api/dpi/streams: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/stream")
def api_dpi_stream_detail():
    try:
        src_ip = request.args.get("src_ip", "")
        dst_ip = request.args.get("dst_ip", "")
        src_port = int(request.args.get("src_port", 0))
        dst_port = int(request.args.get("dst_port", 0))
        from dpi.tcp_reassembler import TCPReassembler
        return jsonify(TCPReassembler.get().get_stream(src_ip, dst_ip, src_port, dst_port))
    except Exception as e:
        logger.error("GET /api/dpi/stream: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/pcap/export", methods=["POST"])
def api_dpi_pcap_export():
    try:
        body = request.get_json(force=True, silent=True) or {}
        limit = min(int(body.get("limit", 1000)), 50000)
        filename = str(body.get("filename", "")).strip()
        db = _get_db()
        if db is None:
            return jsonify({"error": "DB not available"}), 503
        packets = db.get_packets(limit=limit)
        from dpi.pcap_manager import export_pcap
        result = export_pcap(packets, filename or None)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/dpi/pcap/export: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/pcap/import", methods=["POST"])
def api_dpi_pcap_import():
    try:
        body = request.get_json(force=True, silent=True) or {}
        path = str(body.get("path", "")).strip()
        if not path:
            return jsonify({"error": "path required"}), 400
        path = os.path.realpath(path)
        from dpi.pcap_manager import import_pcap
        return jsonify(import_pcap(path))
    except Exception as e:
        logger.error("POST /api/dpi/pcap/import: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/pcap/files")
def api_dpi_pcap_files():
    try:
        from dpi.pcap_manager import list_pcap_files
        return jsonify(list_pcap_files())
    except Exception as e:
        logger.error("GET /api/dpi/pcap/files: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Module 3: Threat Intelligence API ─────────────────────────────────────────

@app.route("/api/intel/ip", methods=["POST"])
def api_intel_ip():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP"}), 400
        sources = body.get("sources", ["virustotal", "abuseipdb", "shodan"])
        result = {}
        from intel import threat_intel as ti
        if "virustotal" in sources:
            result["virustotal"] = ti.virustotal_ip(ip)
        if "abuseipdb" in sources:
            result["abuseipdb"] = ti.abuseipdb_check(ip)
        if "shodan" in sources:
            result["shodan"] = ti.shodan_host(ip)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/intel/ip: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intel/domain", methods=["POST"])
def api_intel_domain():
    try:
        body = request.get_json(force=True, silent=True) or {}
        domain = str(body.get("domain", "")).strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from intel.threat_intel import virustotal_domain
        return jsonify({"virustotal": virustotal_domain(domain)})
    except Exception as e:
        logger.error("POST /api/intel/domain: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intel/hash", methods=["POST"])
def api_intel_hash():
    try:
        body = request.get_json(force=True, silent=True) or {}
        file_hash = str(body.get("hash", "")).strip()
        if not file_hash:
            return jsonify({"error": "hash required"}), 400
        from intel.threat_intel import virustotal_hash
        return jsonify({"virustotal": virustotal_hash(file_hash)})
    except Exception as e:
        logger.error("POST /api/intel/hash: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intel/rdap", methods=["POST"])
def api_intel_rdap():
    try:
        body = request.get_json(force=True, silent=True) or {}
        target = str(body.get("target", "")).strip()
        if not target:
            return jsonify({"error": "target required"}), 400
        import ipaddress as _ip
        try:
            _ip.ip_address(target)
            from intel.rdap_lookup import rdap_ip
            return jsonify(rdap_ip(target))
        except ValueError:
            from intel.rdap_lookup import rdap_domain
            return jsonify(rdap_domain(target))
    except Exception as e:
        logger.error("POST /api/intel/rdap: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intel/bgp", methods=["POST"])
def api_intel_bgp():
    try:
        body = request.get_json(force=True, silent=True) or {}
        ip = str(body.get("ip", "")).strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP"}), 400
        from intel.rdap_lookup import bgp_lookup
        return jsonify(bgp_lookup(ip))
    except Exception as e:
        logger.error("POST /api/intel/bgp: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Module 5: Home Network API ─────────────────────────────────────────────────

@app.route("/api/network/devices")
def api_network_devices():
    try:
        from network.network_mapper import get_devices
        return jsonify(get_devices())
    except Exception as e:
        logger.error("GET /api/network/devices: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/network/scan", methods=["POST"])
def api_network_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        subnet = body.get("subnet")
        from network.network_mapper import scan_network
        result = scan_network(subnet)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/network/scan: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/network/arp_table")
def api_network_arp_table():
    try:
        from network.arp_monitor import get_arp_table
        return jsonify(get_arp_table())
    except Exception as e:
        logger.error("GET /api/network/arp_table: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/network/arp_events")
def api_network_arp_events():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        from network.arp_monitor import get_events
        return jsonify(get_events(limit))
    except Exception as e:
        logger.error("GET /api/network/arp_events: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/network/bandwidth")
def api_network_bandwidth():
    try:
        from network.bandwidth_monitor import get_all_stats, get_top_talkers
        limit = min(int(request.args.get("limit", 20)), 100)
        return jsonify(get_top_talkers(limit))
    except Exception as e:
        logger.error("GET /api/network/bandwidth: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Module 6: Vulnerability Scanner API ───────────────────────────────────────

@app.route("/api/vuln/scan", methods=["POST"])
def api_vuln_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        checks = body.get("checks")  # None = all checks
        if not url:
            return jsonify({"error": "url required"}), 400
        from vuln.vuln_scanner import full_scan
        result = full_scan(url, checks)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/vuln/scan: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/vuln/history")
def api_vuln_history():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_vuln_scans())
    except Exception as e:
        logger.error("GET /api/vuln/history: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/vuln/detail/<int:scan_id>")
def api_vuln_detail(scan_id: int):
    try:
        db = _get_db()
        if db is None:
            return jsonify({})
        return jsonify(db.get_vuln_scan_detail(scan_id))
    except Exception as e:
        logger.error("GET /api/vuln/detail/%d: %s", scan_id, e)
        return jsonify({"error": "internal error"}), 500


# ── Logs ───────────────────────────────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    try:
        from utils.config_loader import Config
        cfg = Config.load()
        log_file = cfg["log_file"]
        if not os.path.isabs(log_file):
            base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            log_file = os.path.join(base, log_file)
        lines = int(request.args.get("lines", 200))
        if not os.path.exists(log_file):
            return jsonify({"lines": [], "path": log_file})
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_lines = f.readlines()
        return jsonify({"lines": all_lines[-lines:], "path": log_file})
    except Exception as e:
        logger.error("GET /api/logs: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Export ─────────────────────────────────────────────────────────────────────

@app.route("/api/export/packets.csv")
def api_export_packets():
    try:
        db = _get_db()
        if db is None:
            return Response("error,db not available", mimetype="text/csv")
        limit = min(int(request.args.get("limit", 5000)), 50000)
        packets = db.get_packets(limit=limit)
        fields = ["id", "timestamp", "src_ip", "dst_ip", "dst_port",
                  "protocol", "tcp_flags", "size", "src_hostname", "service"]
        lines = [",".join(fields)]
        for p in packets:
            lines.append(",".join(str(p.get(f, "")) for f in fields))
        return Response(
            "\n".join(lines), mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=packets.csv"},
        )
    except Exception as e:
        logger.error("GET /api/export/packets.csv: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Intruder API ───────────────────────────────────────────────────────────────

@app.route("/api/intruder/run", methods=["POST"])
def api_intruder_run():
    try:
        body = request.get_json(force=True, silent=True) or {}
        method = str(body.get("method", "GET")).upper()
        url = str(body.get("url", "")).strip()
        body_template = str(body.get("body_template", ""))
        headers = body.get("headers") or {}
        attack_type = str(body.get("attack_type", "sniper")).lower()
        payload_sets = body.get("payload_sets") or [[]]
        max_req = min(int(body.get("max_requests", 200)), 500)
        concurrency = min(int(body.get("concurrency", 10)), 30)
        if not url:
            return jsonify({"error": "url required"}), 400
        from proxy.intruder import run_attack
        result = run_attack(method, url, body_template, headers,
                            attack_type, payload_sets, max_req,
                            concurrency=concurrency)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/intruder/run: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intruder/history")
def api_intruder_history():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_intruder_runs())
    except Exception as e:
        logger.error("GET /api/intruder/history: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intruder/detail/<int:run_id>")
def api_intruder_detail(run_id: int):
    try:
        db = _get_db()
        if db is None:
            return jsonify({})
        return jsonify(db.get_intruder_run_detail(run_id))
    except Exception as e:
        logger.error("GET /api/intruder/detail/%d: %s", run_id, e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/intruder/payloads")
def api_intruder_payloads():
    try:
        from proxy.intruder import PAYLOADS
        key = request.args.get("key")
        if key:
            return jsonify(PAYLOADS.get(key, []))
        return jsonify(PAYLOADS)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Decoder API ────────────────────────────────────────────────────────────────

@app.route("/api/decoder/encode", methods=["POST"])
def api_decoder_encode():
    try:
        body = request.get_json(force=True, silent=True) or {}
        data = str(body.get("data", ""))
        method = str(body.get("method", "base64")).lower()
        from proxy.decoder import encode
        return jsonify(encode(data, method))
    except Exception as e:
        logger.error("POST /api/decoder/encode: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/decoder/decode", methods=["POST"])
def api_decoder_decode():
    try:
        body = request.get_json(force=True, silent=True) or {}
        data = str(body.get("data", ""))
        method = str(body.get("method", "base64")).lower()
        from proxy.decoder import decode
        return jsonify(decode(data, method))
    except Exception as e:
        logger.error("POST /api/decoder/decode: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/decoder/hash", methods=["POST"])
def api_decoder_hash():
    try:
        body = request.get_json(force=True, silent=True) or {}
        data = str(body.get("data", ""))
        algorithm = str(body.get("algorithm", "sha256")).lower()
        from proxy.decoder import hash_data
        return jsonify(hash_data(data, algorithm))
    except Exception as e:
        logger.error("POST /api/decoder/hash: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/decoder/jwt", methods=["POST"])
def api_decoder_jwt():
    try:
        body = request.get_json(force=True, silent=True) or {}
        token = str(body.get("token", "")).strip()
        if not token:
            return jsonify({"error": "token required"}), 400
        from proxy.decoder import jwt_decode
        return jsonify(jwt_decode(token))
    except Exception as e:
        logger.error("POST /api/decoder/jwt: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/decoder/detect", methods=["POST"])
def api_decoder_detect():
    try:
        body = request.get_json(force=True, silent=True) or {}
        data = str(body.get("data", ""))
        from proxy.decoder import detect_encoding
        return jsonify({"detected": detect_encoding(data)})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Comparer API ───────────────────────────────────────────────────────────────

@app.route("/api/comparer/compare", methods=["POST"])
def api_comparer_compare():
    try:
        body = request.get_json(force=True, silent=True) or {}
        left = str(body.get("left", ""))
        right = str(body.get("right", ""))
        mode = str(body.get("mode", "words")).lower()
        from proxy.comparer import compare
        return jsonify(compare(left, right, mode))
    except Exception as e:
        logger.error("POST /api/comparer/compare: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Spider API ─────────────────────────────────────────────────────────────────

@app.route("/api/spider/crawl", methods=["POST"])
def api_spider_crawl():
    try:
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        max_pages = min(int(body.get("max_pages", 30)), 100)
        max_depth = min(int(body.get("max_depth", 3)), 5)
        if not url:
            return jsonify({"error": "url required"}), 400
        from proxy.spider import crawl
        result = crawl(url, max_pages=max_pages, max_depth=max_depth)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/spider/crawl: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/spider/history")
def api_spider_history():
    try:
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_spider_results())
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/spider/results", methods=["POST"])
def api_spider_results():
    try:
        body = request.get_json(force=True, silent=True) or {}
        base_url = str(body.get("base_url", "")).strip()
        db = _get_db()
        if db is None:
            return jsonify([])
        return jsonify(db.get_spider_results(base_url))
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── DPI Extended API ───────────────────────────────────────────────────────────

@app.route("/api/dpi/filter", methods=["POST"])
def api_dpi_filter():
    try:
        body = request.get_json(force=True, silent=True) or {}
        expr = str(body.get("expression") or body.get("filter") or "").strip()
        limit = min(int(body.get("limit", 200)), 2000)
        db = _get_db()
        if db is None:
            return jsonify({"packets": [], "total_inspected": 0})
        packets = db.get_packets(limit=limit)
        if not expr:
            return jsonify({"packets": packets, "total_inspected": len(packets)})
        from dpi.display_filter import filter_packets
        matched = filter_packets(packets, expr)
        return jsonify({"packets": matched, "total_inspected": len(packets)})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.error("POST /api/dpi/filter: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/stats", methods=["POST"])
def api_dpi_stats():
    try:
        body = request.get_json(force=True, silent=True) or {}
        stat_type = str(body.get("type", "hierarchy"))
        limit = min(int(body.get("limit", 500)), 5000)
        db = _get_db()
        if db is None:
            return jsonify({})
        packets = db.get_packets(limit=limit)
        from dpi import protocol_stats as ps
        if stat_type == "hierarchy":
            return jsonify({"data": ps.protocol_hierarchy(packets), "type": stat_type})
        if stat_type == "conversations":
            return jsonify({"data": ps.conversations(packets), "type": stat_type})
        if stat_type == "endpoints":
            return jsonify({"data": ps.endpoints(packets), "type": stat_type})
        if stat_type == "io_graph":
            interval = float(body.get("interval", 1.0))
            return jsonify({"data": ps.io_graph(packets, interval), "type": stat_type})
        if stat_type == "services":
            return jsonify({"data": ps.service_stats(packets), "type": stat_type})
        if stat_type == "expert":
            return jsonify({"data": ps.expert_info(packets), "type": stat_type})
        return jsonify({"error": f"Unknown stat type: {stat_type}"}), 400
    except Exception as e:
        logger.error("POST /api/dpi/stats: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/dpi/udp/streams")
def api_dpi_udp_streams():
    try:
        limit = min(int(request.args.get("limit", 100)), 500)
        # single-stream lookup
        src_ip = request.args.get("src_ip")
        dst_ip = request.args.get("dst_ip")
        src_port = request.args.get("src_port")
        dst_port = request.args.get("dst_port")
        from dpi.tcp_reassembler import UDPTracker
        tracker = UDPTracker.get()
        if src_ip and dst_ip and src_port and dst_port:
            stream = tracker.get_stream(src_ip, dst_ip, int(src_port), int(dst_port))
            return jsonify({"stream": stream})
        streams = tracker.get_all_streams(limit)
        return jsonify({"streams": streams, "count": len(streams)})
    except Exception as e:
        logger.error("GET /api/dpi/udp/streams: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Advanced scan API (new Nmap features) ──────────────────────────────────────

@app.route("/api/tools/syn_scan", methods=["POST"])
def api_syn_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        timing = int(body.get("timing", 3))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import syn_scan
        return jsonify(syn_scan(host, ports, timing))
    except Exception as e:
        logger.error("POST /api/tools/syn_scan: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/null_scan", methods=["POST"])
def api_null_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import null_scan
        return jsonify(null_scan(host, ports))
    except Exception as e:
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/fin_scan", methods=["POST"])
def api_fin_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import fin_scan
        return jsonify(fin_scan(host, ports))
    except Exception as e:
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/xmas_scan", methods=["POST"])
def api_xmas_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import xmas_scan
        return jsonify(xmas_scan(host, ports))
    except Exception as e:
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/ack_scan", methods=["POST"])
def api_ack_scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import ack_scan
        return jsonify(ack_scan(host, ports))
    except Exception as e:
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/top_ports", methods=["POST"])
def api_top_ports():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        n = min(int(body.get("n", 100)), 1000)
        timing = int(body.get("timing", 3))
        banner = bool(body.get("banner", True))
        os_detect = bool(body.get("os_detect", False))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import top_ports_scan
        return jsonify(top_ports_scan(host, n, timing, banner, os_detect))
    except Exception as e:
        logger.error("POST /api/tools/top_ports: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/nse", methods=["POST"])
def api_nse():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        scripts = body.get("scripts") or ["http-title", "ssl-cert", "ftp-anon", "ssh-hostkey"]
        open_ports = body.get("open_ports") or []
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import nse_run
        return jsonify(nse_run(host, scripts, open_ports))
    except Exception as e:
        logger.error("POST /api/tools/nse: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/ping_sweep", methods=["POST"])
def api_ping_sweep():
    try:
        body = request.get_json(force=True, silent=True) or {}
        subnet = body.get("subnet")
        from utils.net_tools import ping_sweep
        return jsonify(ping_sweep(subnet))
    except Exception as e:
        logger.error("POST /api/tools/ping_sweep: %s", e)
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/ipv6scan", methods=["POST"])
def api_ipv6scan():
    try:
        body = request.get_json(force=True, silent=True) or {}
        host = str(body.get("host", "")).strip()
        ports = str(body.get("ports", "1-1024"))
        timing = int(body.get("timing", 3))
        if not host:
            return jsonify({"error": "host required"}), 400
        from utils.net_tools import ipv6_scan
        return jsonify(ipv6_scan(host, ports, timing))
    except Exception as e:
        return jsonify({"error": "internal error"}), 500


@app.route("/api/tools/scan_export", methods=["POST"])
def api_scan_export():
    try:
        body = request.get_json(force=True, silent=True) or {}
        fmt = str(body.get("format", "normal")).lower()
        from utils.net_tools import scan_to_xml, scan_to_grepable, scan_to_normal, top_ports_scan
        # Accept either pre-built scan_result or run a quick scan from host
        scan_result = body.get("scan_result") or {}
        if not scan_result:
            host = str(body.get("host", "")).strip()
            if not host:
                return jsonify({"error": "host required"}), 400
            scan_result = top_ports_scan(host, n=100, timing=3, banner=False, os_detect=False)
        if fmt == "xml":
            return Response(scan_to_xml(scan_result), mimetype="application/xml",
                            headers={"Content-Disposition": "attachment; filename=scan.xml"})
        if fmt == "grepable":
            return Response(scan_to_grepable(scan_result), mimetype="text/plain",
                            headers={"Content-Disposition": "attachment; filename=scan.gnmap"})
        return Response(scan_to_normal(scan_result), mimetype="text/plain",
                        headers={"Content-Disposition": "attachment; filename=scan.txt"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Recon endpoints ────────────────────────────────────────────────────────────

@app.route("/api/recon/subdomains", methods=["POST"])
def api_recon_subdomains():
    try:
        body = request.get_json(silent=True) or {}
        domain = (body.get("domain") or "").strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from recon.subdomain_enum import run
        result = run(
            domain,
            probe_http=body.get("probe_http", True),
            bruteforce=body.get("bruteforce", False),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("recon/subdomains: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/dns", methods=["POST"])
def api_recon_dns():
    try:
        body = request.get_json(silent=True) or {}
        domain = (body.get("domain") or "").strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from recon.dns_tools import lookup
        result = lookup(domain, record_types=body.get("record_types"))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/dns: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/dns/zone", methods=["POST"])
def api_recon_dns_zone():
    try:
        body = request.get_json(silent=True) or {}
        domain = (body.get("domain") or "").strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from recon.dns_tools import zone_transfer
        result = zone_transfer(domain)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/dns/zone: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/wayback", methods=["POST"])
def api_recon_wayback():
    try:
        body = request.get_json(silent=True) or {}
        domain = (body.get("domain") or "").strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from recon.wayback import fetch
        result = fetch(
            domain,
            limit=body.get("limit", 2000),
            from_year=body.get("from_year"),
            to_year=body.get("to_year"),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("recon/wayback: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/favicon", methods=["POST"])
def api_recon_favicon():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.favicon import fetch
        result = fetch(url)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/favicon: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/reverse_ip", methods=["POST"])
def api_recon_reverse_ip():
    try:
        body = request.get_json(silent=True) or {}
        ip = (body.get("ip") or body.get("domain") or "").strip()
        if not ip:
            return jsonify({"error": "ip or domain required"}), 400
        from recon.reverse_ip import lookup
        result = lookup(ip)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/reverse_ip: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/js_files", methods=["POST"])
def api_recon_js_files():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.js_analyzer import run
        result = run(url, max_js=body.get("max_js", 30))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/js_files: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/asn", methods=["POST"])
def api_recon_asn():
    try:
        body = request.get_json(silent=True) or {}
        query = (body.get("query") or body.get("ip") or body.get("domain") or "").strip()
        if not query:
            return jsonify({"error": "ip or domain required"}), 400
        from recon.asn_lookup import lookup
        result = lookup(query, include_prefixes=body.get("include_prefixes", False))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/asn: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/emails", methods=["POST"])
def api_recon_emails():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.email_harvester import run
        result = run(url, max_pages=body.get("max_pages", 20))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/emails: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/http_probe", methods=["POST"])
def api_recon_http_probe():
    try:
        body = request.get_json(silent=True) or {}
        targets = body.get("targets") or []
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.splitlines() if t.strip()]
        if not targets:
            return jsonify({"error": "targets list required"}), 400
        from recon.http_probe import probe
        result = probe(targets[:100], concurrency=body.get("concurrency", 20))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/http_probe: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/security_headers", methods=["POST"])
def api_recon_security_headers():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.security_headers import analyze
        result = analyze(url)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/security_headers: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/tech", methods=["POST"])
def api_recon_tech():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.tech_detector import detect
        result = detect(url)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/tech: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/broken_links", methods=["POST"])
def api_recon_broken_links():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.broken_links import run
        result = run(url, max_pages=body.get("max_pages", 20))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/broken_links: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/whois", methods=["POST"])
def api_recon_whois():
    try:
        body = request.get_json(silent=True) or {}
        domain = (body.get("domain") or body.get("query") or "").strip()
        if not domain:
            return jsonify({"error": "domain required"}), 400
        from recon.whois_lookup import lookup
        result = lookup(domain)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/whois: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/robots", methods=["POST"])
def api_recon_robots():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.robots_sitemap import fetch
        result = fetch(url, max_sitemap_urls=body.get("max_sitemap_urls", 500))
        return jsonify(result)
    except Exception as e:
        logger.error("recon/robots: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/crawl", methods=["POST"])
def api_recon_crawl():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.web_crawler import crawl
        result = crawl(
            url,
            max_pages=body.get("max_pages", 50),
            max_depth=body.get("max_depth", 3),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("recon/crawl: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/status_codes", methods=["POST"])
def api_recon_status_codes():
    try:
        body = request.get_json(silent=True) or {}
        targets = body.get("targets") or []
        if isinstance(targets, str):
            targets = [t.strip() for t in targets.splitlines() if t.strip()]
        base_url = (body.get("base_url") or "").strip() or None
        if not targets:
            return jsonify({"error": "targets list required"}), 400
        from recon.status_codes import check
        result = check(targets[:500], base_url=base_url)
        return jsonify(result)
    except Exception as e:
        logger.error("recon/status_codes: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/recon/response_headers", methods=["POST"])
def api_recon_response_headers():
    try:
        body = request.get_json(silent=True) or {}
        url = (body.get("url") or "").strip()
        if not url:
            return jsonify({"error": "url required"}), 400
        from recon.response_headers import fetch
        result = fetch(
            url,
            method=body.get("method", "GET"),
            follow_redirects=body.get("follow_redirects", True),
        )
        return jsonify(result)
    except Exception as e:
        logger.error("recon/response_headers: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/alerts.csv")
def api_export_alerts():
    try:
        db = _get_db()
        if db is None:
            return Response("error,db not available", mimetype="text/csv")
        csv_data = db.export_alerts_csv()
        return Response(
            csv_data, mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )
    except Exception as e:
        logger.error("GET /api/export/alerts.csv: %s", e)
        return jsonify({"error": "internal error"}), 500
