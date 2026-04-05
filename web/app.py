import logging
import ipaddress
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
    """Minimal hardening for a local monitoring dashboard."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers.pop("Server", None)
    return response


# ── Pages ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html")


# ── Core monitoring API ───────────────────────────────────────────────────────

@app.route("/api/packets")
def api_packets():
    try:
        limit = min(int(request.args.get("limit", 20)), 200)
        if _sniffer is None:
            return jsonify([])
        packets = _sniffer.get_recent_packets(limit)
        # Enrich with hostname if DNS resolver available
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
        return jsonify({
            "sniffer": sniffer_ok,
            "ids": _ids is not None,
            "ips": _ips is not None,
            "degraded": degraded,
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


# ── Connections ───────────────────────────────────────────────────────────────

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


# ── Statistics / DB ───────────────────────────────────────────────────────────

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
def api_top_ports():
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


# ── IP Analysis ───────────────────────────────────────────────────────────────

@app.route("/api/ip/analyze")
def api_ip_analyze():
    try:
        ip = request.args.get("ip", "").strip()
        if not _validate_ip(ip):
            return jsonify({"error": "Invalid IP address"}), 400

        result = {"ip": ip}

        # Geo / ASN
        try:
            from utils.geo_lookup import lookup
            result["geo"] = lookup(ip)
        except Exception as e:
            result["geo"] = {"error": str(e)}

        # Reverse DNS
        try:
            from utils.dns_resolver import DNSResolver
            result["hostname"] = DNSResolver.get().resolve_sync(ip)
        except Exception:
            result["hostname"] = None

        # DB history
        db = _get_db()
        if db is not None:
            result["history"] = db.get_ip_history(ip)
        else:
            result["history"] = {}

        # Is blocked / whitelisted
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


# ── Domain / URL Scanner ──────────────────────────────────────────────────────

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
        import os
        body = request.get_json(force=True, silent=True) or {}
        url = str(body.get("url", "")).strip()
        save_dir = str(body.get("save_dir", "")).strip()
        include_assets = bool(body.get("include_assets", False))
        if not url:
            return jsonify({"error": "url required"}), 400
        if not save_dir:
            return jsonify({"error": "save_dir required"}), 400
        # Resolve to absolute path; disallow parent traversal fragments
        save_dir = os.path.realpath(save_dir)
        from utils.scanner import scrape_page
        result = scrape_page(url, save_dir, include_assets=include_assets)
        return jsonify(result)
    except Exception as e:
        logger.error("POST /api/scan/scrape: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Network Tools ─────────────────────────────────────────────────────────────

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
        rtype = str(body.get("type", "A")).upper()
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
        if not host:
            return jsonify({"error": "host required"}), 400

        from utils.net_tools import port_scan
        return jsonify(port_scan(host, str(ports_raw)))
    except Exception as e:
        logger.error("POST /api/tools/portscan: %s", e)
        return jsonify({"error": "internal error"}), 500


# ── Firewall Management ───────────────────────────────────────────────────────

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


# ── Whitelist Management ──────────────────────────────────────────────────────

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


# ── Blacklist Management ──────────────────────────────────────────────────────

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


# ── Logs ──────────────────────────────────────────────────────────────────────

@app.route("/api/logs")
def api_logs():
    try:
        import os
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


# ── Export ────────────────────────────────────────────────────────────────────

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


@app.route("/api/export/alerts.csv")
def api_export_alerts():
    try:
        db = _get_db()
        if db is None:
            return Response("error,db not available", mimetype="text/csv")
        csv_data = db.export_alerts_csv()
        return Response(
            csv_data,
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=alerts.csv"},
        )
    except Exception as e:
        logger.error("GET /api/export/alerts.csv: %s", e)
        return jsonify({"error": "internal error"}), 500
