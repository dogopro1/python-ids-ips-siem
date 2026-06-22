"""
Subdomain Enumeration — Recon Module.

Sources:
  1. crt.sh (certificate transparency) — passive, no key required
  2. DNS bruteforce with built-in 200-word list (optional, active)
  3. HTTP probe for each live host (optional)

Returns: {domain, subdomains:[...], total, live, elapsed_s}
"""
import re
import time
import socket
import logging
import threading
import concurrent.futures
import warnings

logger = logging.getLogger("ids_ips")

_WORDLIST = [
    "www","mail","ftp","smtp","pop","pop3","imap","webmail","ns1","ns2","ns3","ns4",
    "mx","mx1","mx2","api","dev","staging","stage","prod","beta","alpha","test","demo",
    "admin","portal","dashboard","app","apps","mobile","m","web","static","cdn","assets",
    "media","images","img","video","shop","store","blog","news","forum","community",
    "support","help","docs","doc","documentation","kb","wiki","status","monitor","vpn",
    "remote","ssh","ftp2","sftp","files","download","downloads","upload","uploads",
    "backup","backups","db","database","mysql","redis","mongo","elasticsearch","kibana",
    "grafana","prometheus","jenkins","gitlab","github","jira","confluence","git","svn",
    "code","ci","cd","deploy","build","docker","k8s","kubernetes","registry","hub",
    "cloud","internal","intranet","extranet","corp","corporate","private","secure",
    "ssl","tls","auth","oauth","sso","login","logout","account","accounts","profile",
    "user","users","customer","customers","payment","pay","billing","invoice","order",
    "orders","search","analytics","tracking","metrics","log","logs","error","proxy",
    "gateway","lb","balancer","office","mail2","email","smtp2","relay","mx3","mx4",
    "webdav","caldav","exchange","autodiscover","autoconfig","cpanel","whm","plesk",
    "wp","wordpress","joomla","drupal","magento","staging2","dev2","test2","uat","qa",
    "preprod","api2","apiv2","v2","v1","v3","old","new","legacy","archive","backup2",
    "monitoring","alert","alerts","nagios","zabbix","smtp3","pop4","imap4","webmail2",
    "s3","bucket","cdn2","download2","upload2","files2","assets2","media2","static2",
    "en","fr","de","es","pt","ru","zh","ja","ko","ar","it","nl","pl","tr","sv",
    "vpn2","jump","bastion","server","server1","server2","web1","web2","web3","app1",
    "app2","db1","db2","cache","redis2","memcache","queue","rabbit","kafka","elastic",
    "solr","nginx","apache","iis","tomcat","node","php","python","ruby","java",
]


def _resolve(hostname: str) -> list:
    try:
        return sorted({r[4][0] for r in socket.getaddrinfo(hostname, None)})
    except Exception:
        return []


def _http_probe(hostname: str, timeout: float = 5.0) -> dict:
    info = {"status": None, "title": None, "server": None, "redirect_url": None}
    try:
        import requests as _req
        for scheme in ("https", "http"):
            try:
                r = _req.get(
                    f"{scheme}://{hostname}", timeout=timeout, verify=False,
                    allow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0 (SubdomainScanner/1.0)"},
                )
                info["status"] = r.status_code
                info["redirect_url"] = r.url if r.url != f"{scheme}://{hostname}" else None
                info["server"] = r.headers.get("Server", "").split("/")[0][:40]
                m = re.search(r"<title[^>]*>([^<]{1,200})</title>", r.text, re.I)
                info["title"] = m.group(1).strip()[:100] if m else ""
                break
            except Exception:
                continue
    except ImportError:
        pass
    return info


def _crtsh(domain: str, timeout: float = 20.0) -> set:
    results = set()
    try:
        import requests as _req
        r = _req.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        if r.ok:
            for entry in r.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lower().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        results.add(name)
    except Exception as exc:
        logger.warning("crt.sh error for %s: %s", domain, exc)
    return results


def run(
    domain: str,
    probe_http: bool = True,
    bruteforce: bool = False,
    wordlist: list = None,
    concurrency: int = 40,
    http_timeout: float = 6.0,
) -> dict:
    """Full subdomain enumeration. Returns structured result dict."""
    warnings.filterwarnings("ignore")
    t0 = time.time()
    domain = domain.strip().lower().lstrip("*. ")
    all_subs: dict = {}

    # 1. Certificate Transparency
    for fqdn in _crtsh(domain):
        all_subs[fqdn] = {"subdomain": fqdn, "ips": [], "source": "crt.sh", "live": False}

    # 2. DNS bruteforce
    if bruteforce:
        wl = wordlist or _WORDLIST
        found_lock = threading.Lock()

        def _check_word(word):
            fqdn = f"{word}.{domain}"
            ips = _resolve(fqdn)
            if ips:
                with found_lock:
                    if fqdn not in all_subs:
                        all_subs[fqdn] = {"subdomain": fqdn, "ips": ips, "source": "bruteforce", "live": True}
                    else:
                        all_subs[fqdn]["ips"] = ips
                        all_subs[fqdn]["live"] = True
                        all_subs[fqdn]["source"] += "+bf"

        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            ex.map(_check_word, wl)

    # 3. Resolve all unresolved
    def _do_resolve(entry):
        if not entry["ips"]:
            entry["ips"] = _resolve(entry["subdomain"])
        entry["live"] = bool(entry["ips"])

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        list(ex.map(_do_resolve, all_subs.values()))

    # 4. HTTP probe (live only)
    if probe_http:
        live = [e for e in all_subs.values() if e["live"]]
        def _do_probe(entry):
            entry.update(_http_probe(entry["subdomain"], http_timeout))
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(concurrency, max(len(live), 1))) as ex:
            list(ex.map(_do_probe, live))

    subdomains = sorted(all_subs.values(), key=lambda x: x["subdomain"])
    return {
        "domain": domain,
        "subdomains": subdomains,
        "total": len(subdomains),
        "live": sum(1 for s in subdomains if s.get("live")),
        "elapsed_s": round(time.time() - t0, 2),
    }
