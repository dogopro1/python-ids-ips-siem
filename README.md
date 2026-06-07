# IDS/IPS Security Console

Kompletna platforma bezpieczeństwa sieciowego uruchamiana lokalnie.  
Zastępuje: **BurpSuite** (proxy + vuln scanner) · **Wireshark** (DPI, PCAP) · **Nmap** (scanner) · **WHOIS/RDAP** · **Threat Intelligence** · **Domowy IDS/IPS**.

---

## Szybki start

```bash
# Wymagania: Python 3.10+, pip
cd ids_ips_system
pip install -r requirements.txt

# Windows — uruchom jako Administrator (wymagane do packet capture i IPS)
python main.py

# Linux / macOS
sudo python main.py
```

Dashboard dostępny pod: **http://127.0.0.1:5000**  
Proxy HTTP/HTTPS: **127.0.0.1:8080**

---

## Architektura

```
ids_ips_system/
├── main.py                    # Entry point — startuje wszystkie komponenty
├── config/config.yaml         # Jedyne źródło konfiguracji
├── core/                      # Silnik IDS/IPS
│   ├── ids.py                 # Worker thread — analiza pakietów
│   ├── ips.py                 # Blokowanie IP (netsh/iptables/pfctl)
│   ├── rules.py               # 6 reguł detekcji (sliding window)
│   ├── connection_tracker.py  # Śledzenie aktywnych połączeń
│   └── traffic_series.py      # Szeregi czasowe ruchu (wykresy)
├── sniffer/packet_sniffer.py  # Scapy sniffer (graceful degradation)
├── db/database.py             # SQLite singleton (WAL, batch writes)
├── web/
│   ├── app.py                 # Flask API (70+ endpointów)
│   └── templates/dashboard.html  # 15-zakładkowy dashboard
├── proxy/                     # MODUŁ 1: Intercepting Proxy
├── dpi/                       # MODUŁ 2: Deep Packet Inspection
├── intel/                     # MODUŁ 3: Threat Intelligence
├── network/                   # MODUŁ 5: Home Network Monitor
├── vuln/                      # MODUŁ 6: Vulnerability Scanner
└── utils/                     # Narzędzia (net_tools, scanner, dns...)
```

---

## Moduły

### Moduł 1 — Intercepting HTTP/HTTPS Proxy *(zastępuje BurpSuite)*

**Co robi:**  
Przechwytuje cały ruch HTTP i HTTPS w czasie rzeczywistym. Dla HTTPS generuje certyfikaty SSL podpisane własnym CA i wykonuje SSL MITM (Man-in-the-Middle), więc widzisz odszyfrowany ruch.

**Jak używać:**

1. Uruchom system: `python main.py`
2. Przejdź do zakładki **HTTP Proxy** w dashboardzie
3. Kliknij **Start Proxy** — proxy nasłuchuje na `127.0.0.1:8080`
4. Pobierz certyfikat CA: kliknij **Download CA.crt**
5. Zaimportuj CA do przeglądarki:
   - **Chrome/Edge:** Ustawienia → Prywatność → Certyfikaty → Importuj (zaufane CA)
   - **Firefox:** Opcje → Prywatność → Certyfikaty → Importuj
6. W przeglądarce ustaw proxy HTTP na `127.0.0.1:8080`
7. Przeglądaj sieć — wszystkie requesty pojawiają się w tabeli

**Funkcje:**
- Historia requestów i response (host, metoda, status, body)
- **Repeater**: kliknij "Replay" przy dowolnym requeście — modyfikuj i wyślij ponownie
- Filtrowanie po hoście i metodzie HTTP
- Przycisk "Detail" — pełny podgląd nagłówków i body request/response

**Konfiguracja** (config.yaml):
```yaml
proxy_enabled: true
proxy_host: "127.0.0.1"
proxy_port: 8080
proxy_ca_dir: "data/proxy"    # tutaj zapisywane są certyfikaty
```

---

### Moduł 2 — Deep Packet Inspection + Wireshark-like *(zastępuje Wireshark)*

**Co robi:**  
Analizuje pakiety sieciowe na poziomie protokołów: Ethernet, IP, TCP, UDP, ICMP, HTTP, DNS, TLS, ARP, DHCP. Rekonstruuje strumienie TCP (Follow Stream). Eksportuje/importuje pliki PCAP kompatybilne z Wiresharkiem.

**Zakładka: DPI Inspector**

**PCAP Export:**
1. Wpisz liczbę pakietów do wyeksportowania (np. 1000)
2. Opcjonalnie podaj nazwę pliku (`mojapcap.pcap`)
3. Kliknij **Export PCAP** — plik zapisuje się w `data/pcap/`
4. Otwórz plik w Wireshark — wszystkie pakiety są widoczne

**PCAP Import:**
1. Wpisz pełną ścieżkę do pliku `.pcap`
2. Kliknij **Import PCAP** — pakiety trafiają do bazy danych

**Follow TCP Stream:**
- Tabela "TCP Stream Reassembly" pokazuje aktywne strumienie TCP
- Kliknij w wiersz aby zobaczyć pełną komunikację client↔server
- Kolorystyka: zielony = client→server, niebieski = server→client

**Protokoły analizowane automatycznie:**
- `HTTP` — metoda, ścieżka, nagłówki, body
- `DNS` — zapytania, odpowiedzi, typy rekordów
- `TLS` — typ handshake (ClientHello, ServerHello, Certificate)
- `ARP` — who-has, is-at, wykrywanie gratuitous ARP

---

### Moduł 3 — Threat Intelligence + RDAP/BGP *(rozszerzony WHOIS)*

**Co robi:**  
Sprawdza reputację IP, domeny lub hasha pliku w zewnętrznych bazach zagrożeń. Używa RDAP (nowoczesne REST API zastępujące WHOIS). Sprawdza informacje BGP/ASN z RIPE NCC.

**Zakładka: Threat Intel**

**Konfiguracja API (wymagana dla pełnej funkcjonalności):**
```yaml
# config.yaml
virustotal_api_key: "twój_klucz"    # virustotal.com — darmowe konto
abuseipdb_api_key: "twój_klucz"     # abuseipdb.com — darmowe konto
shodan_api_key: "twój_klucz"        # shodan.io — darmowe konto
```

**Jak używać:**
1. W zakładce **Threat Intel** wpisz IP, domenę lub hash pliku
2. Wybierz typ zapytania:
   - **IP Address** → sprawdza VirusTotal + AbuseIPDB + Shodan jednocześnie
   - **Domain** → sprawdza VirusTotal (reputacja, kategorie, malicious count)
   - **File Hash** → MD5/SHA1/SHA256, wyniki skanowania w 70+ silnikach AV
   - **RDAP Lookup** → pełne dane rejestracyjne (IP lub domena) — bez klucza
   - **BGP/ASN Lookup** → prefix BGP, holder AS, trasy — bez klucza
3. Kliknij **Query All Sources**

**Wyniki:**
- VirusTotal: liczba silników wykrywających malicious/suspicious/harmless
- AbuseIPDB: procent confidence (>80% = bardzo podejrzane), liczba zgłoszeń
- Shodan: otwarte porty, CVE, banery usług, lokalizacja
- RDAP: registrar, daty rejestracji, nameservery, kontakty
- BGP: ASN, holder, prefiks IP

**Wyniki są cache'owane** (domyślnie 1h) w SQLite — kolejne zapytania o ten sam cel są natychmiastowe.

---

### Moduł 4 — Nmap-like Scanner *(zastępuje Nmap)*

**Co robi:**  
Skanowanie portów TCP i UDP z banner grabbing (identyfikacja usług i wersji), OS fingerprinting (TTL + TCP window), ARP scan sieci lokalnej. Timing presets jak w Nmap (-T1 do -T5).

**Zakładka: Net Tools** (rozszerzona)

**Port Scanner TCP:**
```
Host: 192.168.1.1
Ports: 1-1024  (lub: 22,80,443,8080)
Timing: T3 Normal (domyślnie)
Banner: ✓ (czyta pierwsze 512 bajtów z otwartego portu)
OS Detect: □ (TTL + TCP window fingerprinting)
```

**Banner Grab:**
- Wpisz host + port + opcjonalnie SSL
- Zwraca pierwsze bajty odpowiedzi usługi
- Automatycznie parsuje wersję (SSH-2.0-OpenSSH_9.2, nginx/1.24, Apache/2.4...)

**OS Fingerprint:**
- Wysyła ping i mierzy TTL:
  - TTL ≤ 64 → Linux/Android/macOS
  - TTL ≤ 128 → Windows
  - TTL ≤ 255 → Cisco/urządzenie sieciowe
- Sprawdza TCP window size dla pewniejszego wyniku

**UDP Scan:**
```
Host: 192.168.1.1
Ports: 53,67,123,161,500,1900
```
Wysyła specyficzne proby dla każdego protokołu (DNS query, NTP request, SNMP, SSDP).

**ARP Scan (tylko sieć lokalna):**
```
Subnet: 192.168.1.0/24  (auto-detect jeśli puste)
```
Wykrywa wszystkie żywe hosty w podsieci, zwraca IP + MAC + vendor.

**Timing presets:**
| Preset | connect_timeout | Wątki | Zastosowanie |
|--------|----------------|-------|--------------|
| T1 Sneaky | 2.0s | 20 | IDS evasion |
| T2 Polite | 1.5s | 50 | Delikatny |
| T3 Normal | 0.5s | 150 | Domyślny |
| T4 Aggressive | 0.3s | 300 | Szybki |
| T5 Insane | 0.1s | 500 | Maksymalny |

---

### Moduł 5 — Home Network Monitor *(lokalny IDS/IPS sieci domowej)*

**Co robi:**  
Monitoruje sieć domową: wykrywa ARP spoofing, mapuje urządzenia, śledzi zużycie pasma per device, identyfikuje producenta urządzenia po MAC OUI.

**Zakładka: Home Network**

**Network Devices:**
- Kliknij **Scan Network** — uruchamia ARP scan całej podsieci
- Tabela pokazuje: IP, MAC, vendor (TP-Link, Raspberry Pi, Apple...), hostname (PTR DNS), status
- Kliknij IP urządzenia → automatycznie przełącza do Threat Intel z tym IP

**ARP Spoof Detection:**
- Działa w tle od startu systemu (wymaga uprawnień root/admin)
- Monitoruje wszystkie pakiety ARP
- Alert gdy:
  - Znane IP zmienia MAC address → podejrzenie ARP poisoning
  - Wykryto gratuitous ARP (ARP reply bez zapytania) → typowa technika ataku MITM
- Alerty w tabeli "ARP Spoof Events" i w logach systemowych

**Bandwidth Monitor:**
- Tabela "Top Talkers" — kto zużywa najwięcej pasma
- Kolumny: IP, prędkość (KB/s), łączny transfer (MB), liczba pakietów

**Konfiguracja:**
```yaml
home_network: "auto"              # lub np. "192.168.0.0/24"
arp_monitor_enabled: true
network_map_interval: 300         # rescan co 5 minut
bandwidth_monitor_enabled: true
```

---

### Moduł 6 — Web Vulnerability Scanner *(zastępuje BurpSuite Scanner)*

**Co robi:**  
Automatyczny skaner podatności webowych. Testuje parametry GET i POST na SQL injection, XSS, LFI, open redirect. Sprawdza security headers, flagi cookie, tokeny CSRF. Wykonuje directory bruteforce na 200 popularnych ścieżkach.

**Zakładka: Vuln Scanner**

**Jak używać:**
1. Wpisz URL celu (np. `https://testphp.vulnweb.com`)
2. Zaznacz które testy chcesz przeprowadzić
3. Kliknij **Full Scan**
4. Poczekaj 30-90 sekund

**Testy:**

| Check | Co testuje |
|-------|-----------|
| Security Headers | Brakujące HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy |
| SQL Injection | 15 payloadów w parametrach GET; wykrywa odpowiedzi z błędami SQL |
| XSS Reflected | 10 payloadów XSS; sprawdza czy payload pojawia się w response |
| LFI / Path Traversal | 13 payloadów `../etc/passwd`, `..\\win.ini`; szuka sygnatur pliku |
| Open Redirect | Parametry redirect/url/next/goto testowane payloadami `//evil.com` |
| CSRF | Szuka formularzy POST bez tokenów CSRF |
| Dir Bruteforce | 200 popularnych ścieżek: admin, .env, .git, phpinfo.php, wp-admin, actuator... |

**Risk Score:**
- CRITICAL: 40 pkt / znalezisko
- HIGH: 20 pkt / znalezisko  
- MEDIUM: 8 pkt / znalezisko
- LOW: 2 pkt / znalezisko

**Historia skanów** zachowywana w bazie SQLite.

> ⚠️ **WAŻNE:** Używaj wyłącznie na systemach, do których masz autoryzację.

---

## Zakładki dashboardu

| # | Zakładka | Opis |
|---|----------|------|
| 1 | Overview | Podgląd real-time: pakiety, alerty, połączenia, wykresy |
| 2 | Packets | Tabela pakietów z filtrami protokołu/IP/portu |
| 3 | Alerts | Alerty IDS z filtrowaniem i eksportem CSV |
| 4 | Connections | Aktywne połączenia TCP/UDP, top talkers |
| 5 | IP Analysis | Kliknij dowolne IP → geo, DNS, historia, blokowanie |
| 6 | Domain Scan | TLS/cert, security headers, tech fingerprint, crawler |
| 7 | Statistics | Wykresy, top ports/sources, timeline 24h |
| 8 | Firewall | Blokowanie/odblokowanie IP, whitelist, blacklist |
| 9 | Net Tools | Ping, traceroute, DNS, WHOIS, port scan, UDP scan, banner, OS detect, ARP scan |
| 10 | Logs | Podgląd logów z filtrowaniem |
| 11 | **HTTP Proxy** | Intercepting proxy, historia requestów, Repeater |
| 12 | **DPI Inspector** | TCP streams (Follow Stream), PCAP export/import |
| 13 | **Threat Intel** | VirusTotal, AbuseIPDB, Shodan, RDAP, BGP |
| 14 | **Vuln Scanner** | SQLi, XSS, LFI, CSRF, Dir Bruteforce, Headers audit |
| 15 | **Home Network** | Devices map, ARP spoof detector, bandwidth monitor |

---

## Reguły detekcji IDS (6 reguł)

| Reguła | Opis | Severity |
|--------|------|----------|
| BLACKLIST | Pakiet z IP na czarnej liście | HIGH |
| DOS_FLOOD | >100 pakietów/10s z jednego IP | HIGH |
| PORT_SCAN | >20 unikalnych portów/10s z jednego IP | MEDIUM |
| SYN_FLOOD | >80 pakietów SYN bez ACK/10s | HIGH |
| ICMP_FLOOD | >50 pakietów ICMP/10s | MEDIUM |
| SUSPICIOUS_PORT | Połączenie na port 4444/5555/31337/12345 | LOW |

Wszystkie reguły używają **sliding window** (nie bucket) — nie pomijają ataków na granicy okna czasowego.  
**Rate limiter:** max 1 alert/30s dla tej samej pary (IP, typ reguły) — zapobiega flooding alertami.

---

## IPS — Automatyczne blokowanie

Gdy IDS wykryje alert HIGH lub MEDIUM, IPS automatycznie blokuje źródłowe IP:
- **Windows:** `netsh advfirewall firewall add rule`
- **Linux:** `iptables -A INPUT -s {IP} -j DROP`
- **macOS:** pfctl anchor

IP z **whitelist** nigdy nie jest blokowane.  
Domyślnie blokada zdejmowana po 600 sekundach (konfigurowalne, 0 = permanentne).

---

## Konfiguracja API Keys

Edytuj `config/config.yaml`:

```yaml
# Threat Intelligence (darmowe klucze)
virustotal_api_key: ""    # https://www.virustotal.com/gui/join-us
abuseipdb_api_key: ""     # https://www.abuseipdb.com/register
shodan_api_key: ""        # https://account.shodan.io/register

# Proxy
proxy_enabled: true
proxy_port: 8080

# IDS/IPS
dos_threshold: 100
portscan_threshold: 20
block_timeout: 600        # 0 = permanentne blokowanie

# Sieć domowa
home_network: "auto"      # lub np. "192.168.1.0/24"
arp_monitor_enabled: true
```

---

## Wymagania

- Python 3.10+
- Windows: uruchom jako **Administrator** (packet capture + netsh)
- Linux/macOS: uruchom jako **root** (packet capture + iptables/pfctl)
- Biblioteki: `flask`, `scapy`, `pyyaml`, `dnspython`, `cryptography`, `requests`

---

## Baza danych

SQLite (`data/ids.db`) — 13 tabel:

| Tabela | Zawiera |
|--------|---------|
| packets | Przechwycone pakiety (max 100k) |
| alerts | Alerty IDS |
| blocked_ips | Historia blokowania |
| whitelist | IP nigdy nie blokowane |
| blacklist_manual | Ręczna czarna lista |
| domain_scans | Historia skanów domen |
| dns_cache | Cache reverse DNS |
| ip_analysis_cache | Cache geo/ASN |
| **proxy_requests** | Historia HTTP proxy |
| **intel_cache** | Cache TI (VT/AbuseIPDB/Shodan) |
| **arp_events** | Eventy ARP spoof |
| **network_devices** | Mapa urządzeń sieciowych |
| **vuln_scans** | Historia skanów podatności |

---

## Eksport danych

- `/api/export/packets.csv` — wszystkie pakiety
- `/api/export/alerts.csv` — wszystkie alerty
- PCAP export w zakładce DPI Inspector (kompatybilny z Wireshark)
