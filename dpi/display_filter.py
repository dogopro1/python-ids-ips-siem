"""
Wireshark-style display filter engine.

Supported syntax:
  ip.addr == 192.168.1.1        ip.src, ip.dst
  ip.src == 10.0.0.0/24         CIDR notation
  tcp.port == 80                tcp.srcport, tcp.dstport
  tcp.flags.syn == 1            tcp.flags.ack, .fin, .rst, .psh, .urg
  udp.port == 53                udp.srcport, udp.dstport
  dns.qry.name contains "google"
  http.request.method == "GET"
  http.response.code == 200
  arp.opcode == 1
  frame.len > 1000
  ttl < 64
  protocol == "TCP"
  not <expr>
  <expr> and <expr>
  <expr> or <expr>
  (<expr>)

All field lookups operate on dissected packet dicts (from dpi.packet_dissector.dissect).
"""
import re
import ipaddress
import logging

logger = logging.getLogger("ids_ips")

# ── Tokenizer ─────────────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(
    r'(?P<lparen>\()'
    r'|(?P<rparen>\))'
    r'|(?P<not>not\b)'
    r'|(?P<and>and\b)'
    r'|(?P<or>or\b)'
    r'|(?P<op>==|!=|>=|<=|>|<|contains\b|matches\b|startswith\b)'
    r'|(?P<field>[a-zA-Z][a-zA-Z0-9_.]*)'
    r'|(?P<net>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2})'
    r'|(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
    r'|(?P<num>-?\d+(?:\.\d+)?)'
    r'|(?P<str>"[^"]*"|\'[^\']*\')',
    re.IGNORECASE,
)


def _tokenize(expr: str) -> list:
    tokens = []
    for m in _TOKEN_RE.finditer(expr):
        kind = m.lastgroup
        val = m.group()
        if kind == "str":
            val = val[1:-1]  # strip quotes
        elif kind == "num":
            val = float(val) if "." in val else int(val)
        elif kind == "ip":
            kind = "str"   # treat bare IPs as strings
        tokens.append((kind, val))
    return tokens


# ── Field extractor ───────────────────────────────────────────────────────────

def _get_field(pkt: dict, field: str):
    """Extract field value from packet dict. Returns None if not present."""
    f = field.lower()

    # ip.*
    if f == "ip.addr":
        return [pkt.get("src_ip"), pkt.get("dst_ip")]
    if f == "ip.src":
        return pkt.get("src_ip") or pkt.get("ip", {}).get("src")
    if f == "ip.dst":
        return pkt.get("dst_ip") or pkt.get("ip", {}).get("dst")
    if f == "ttl":
        return pkt.get("ttl") or pkt.get("ip", {}).get("ttl")

    # tcp.*
    if f == "tcp.port":
        return [pkt.get("src_port"), pkt.get("dst_port")]
    if f in ("tcp.srcport", "tcp.sport"):
        return pkt.get("tcp", {}).get("src_port") or pkt.get("src_port")
    if f in ("tcp.dstport", "tcp.dport"):
        return pkt.get("tcp", {}).get("dst_port") or pkt.get("dst_port")
    if f == "tcp.flags":
        return pkt.get("tcp", {}).get("flags", "")
    if f == "tcp.window":
        return pkt.get("tcp", {}).get("window")
    if f.startswith("tcp.flags."):
        flag_name = f.split(".", 2)[2].upper()
        _flag_map = {"SYN": "S", "ACK": "A", "FIN": "F", "RST": "R",
                     "PSH": "P", "URG": "U", "ECE": "E", "CWR": "C"}
        flag_char = _flag_map.get(flag_name, flag_name[0])
        flags = pkt.get("tcp", {}).get("flags", "")
        return 1 if flag_char in str(flags) else 0

    # udp.*
    if f == "udp.port":
        return [pkt.get("src_port"), pkt.get("dst_port")]
    if f in ("udp.srcport", "udp.sport"):
        return pkt.get("udp", {}).get("src_port") or pkt.get("src_port")
    if f in ("udp.dstport", "udp.dport"):
        return pkt.get("udp", {}).get("dst_port") or pkt.get("dst_port")

    # icmp.*
    if f == "icmp.type":
        return pkt.get("icmp", {}).get("type")
    if f == "icmp.code":
        return pkt.get("icmp", {}).get("code")

    # dns.*
    if f == "dns.qry.name":
        questions = pkt.get("dns", {}).get("questions", [])
        return questions[0] if questions else None
    if f == "dns.a":
        for ans in pkt.get("dns", {}).get("answers", []):
            if ans.get("type") == 1:
                return ans.get("rdata")
    if f == "dns.id":
        return pkt.get("dns", {}).get("id")

    # http.*
    if f == "http.request.method":
        return pkt.get("http", {}).get("method")
    if f == "http.response.code":
        status = pkt.get("http", {}).get("status", "")
        try:
            return int(str(status).split()[1]) if status else None
        except Exception:
            return None
    if f == "http.host":
        return pkt.get("http", {}).get("headers", {}).get("host")

    # arp.*
    if f == "arp.opcode":
        ops = {"who-has": 1, "is-at": 2}
        op_str = pkt.get("arp", {}).get("op", "")
        return ops.get(op_str, pkt.get("arp", {}).get("op"))
    if f == "arp.src.hw_mac":
        return pkt.get("arp", {}).get("sender_mac")
    if f == "arp.dst.hw_mac":
        return pkt.get("arp", {}).get("target_mac")

    # tls.*
    if f == "tls.record.content_type":
        return pkt.get("tls", {}).get("content_type")

    # frame.*
    if f == "frame.len":
        return pkt.get("ip", {}).get("len") or pkt.get("size")
    if f == "frame.time_relative":
        return pkt.get("timestamp")

    # protocol
    if f == "protocol":
        return pkt.get("protocol", "").upper()

    return None


# ── Evaluator ─────────────────────────────────────────────────────────────────

def _match_value(field_val, op: str, cmp_val) -> bool:
    """Compare field_val to cmp_val using op."""
    # Handle list (e.g. ip.addr, tcp.port)
    if isinstance(field_val, list):
        return any(_match_single(v, op, cmp_val) for v in field_val if v is not None)
    return _match_single(field_val, op, cmp_val)


def _match_single(field_val, op: str, cmp_val) -> bool:
    if field_val is None:
        return False

    # CIDR match for ip fields
    if isinstance(cmp_val, str) and "/" in cmp_val:
        try:
            net = ipaddress.ip_network(cmp_val, strict=False)
            addr = ipaddress.ip_address(str(field_val))
            result = addr in net
            return result if op == "==" else not result
        except Exception:
            pass

    op = op.lower()
    if op in ("==", "="):
        return str(field_val).lower() == str(cmp_val).lower()
    if op == "!=":
        return str(field_val).lower() != str(cmp_val).lower()
    if op == "contains":
        return str(cmp_val).lower() in str(field_val).lower()
    if op == "matches":
        try:
            return bool(re.search(str(cmp_val), str(field_val), re.IGNORECASE))
        except Exception:
            return False
    if op == "startswith":
        return str(field_val).lower().startswith(str(cmp_val).lower())
    try:
        fv = float(field_val)
        cv = float(cmp_val)
        if op == ">":
            return fv > cv
        if op == "<":
            return fv < cv
        if op == ">=":
            return fv >= cv
        if op == "<=":
            return fv <= cv
    except (ValueError, TypeError):
        pass
    return False


# ── Recursive parser ──────────────────────────────────────────────────────────

class _Parser:
    def __init__(self, tokens: list):
        self._tokens = tokens
        self._pos = 0

    def _peek(self):
        return self._tokens[self._pos] if self._pos < len(self._tokens) else (None, None)

    def _consume(self, kind=None):
        tok = self._tokens[self._pos]
        if kind and tok[0] != kind:
            raise ValueError(f"Expected {kind}, got {tok}")
        self._pos += 1
        return tok

    def parse(self):
        node = self._parse_or()
        return node

    def _parse_or(self):
        left = self._parse_and()
        while self._peek()[0] == "or":
            self._consume("or")
            right = self._parse_and()
            left = ("or", left, right)
        return left

    def _parse_and(self):
        left = self._parse_not()
        while self._peek()[0] == "and":
            self._consume("and")
            right = self._parse_not()
            left = ("and", left, right)
        return left

    def _parse_not(self):
        if self._peek()[0] == "not":
            self._consume("not")
            expr = self._parse_primary()
            return ("not", expr)
        return self._parse_primary()

    def _parse_primary(self):
        kind, val = self._peek()
        if kind == "lparen":
            self._consume("lparen")
            node = self._parse_or()
            self._consume("rparen")
            return node
        if kind == "field":
            self._consume("field")
            field_name = val
            op_tok = self._peek()
            if op_tok[0] == "op":
                self._consume("op")
                op = op_tok[1]
                cmp_tok = self._peek()
                if cmp_tok[0] in ("num", "str", "field", "net"):
                    self._consume()
                    cmp_val = cmp_tok[1]
                else:
                    cmp_val = ""
                return ("cmp", field_name, op, cmp_val)
            # Bare field — test for truthiness
            return ("exists", field_name)
        raise ValueError(f"Unexpected token: {kind!r} {val!r}")


def _eval_node(node, pkt: dict) -> bool:
    if node is None:
        return True
    op = node[0]
    if op == "cmp":
        _, field, comp_op, cmp_val = node
        fval = _get_field(pkt, field)
        return _match_value(fval, comp_op, cmp_val)
    if op == "exists":
        _, field = node
        return _get_field(pkt, field) is not None
    if op == "not":
        return not _eval_node(node[1], pkt)
    if op == "and":
        return _eval_node(node[1], pkt) and _eval_node(node[2], pkt)
    if op == "or":
        return _eval_node(node[1], pkt) or _eval_node(node[2], pkt)
    return False


# ── Public API ────────────────────────────────────────────────────────────────

def compile_filter(expr: str):
    """Compile a filter expression. Returns compiled object or raises ValueError."""
    tokens = _tokenize(expr.strip())
    if not tokens:
        return None
    parser = _Parser(tokens)
    return parser.parse()


def apply_filter(compiled, pkt: dict) -> bool:
    """Apply a compiled filter to a packet dict. Returns True if packet matches."""
    if compiled is None:
        return True
    try:
        return _eval_node(compiled, pkt)
    except Exception:
        return False


def filter_packets(packets: list, expr: str) -> list:
    """Filter a list of packet dicts using expression. Returns matching packets."""
    if not expr or not expr.strip():
        return packets
    try:
        compiled = compile_filter(expr)
        return [p for p in packets if apply_filter(compiled, p)]
    except ValueError as e:
        raise ValueError(f"Filter error: {e}")
