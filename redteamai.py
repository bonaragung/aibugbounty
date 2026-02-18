#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║     AI-Augmented Bug Bounty Scanner — Demo untuk Presentasi ║
║     "Mencari Celah di Era AI: Bug Bounty + Kecerdasan Buatan"║
╚══════════════════════════════════════════════════════════════╝

Filosofi tool ini:
  AI bukan autopilot — AI adalah partner analisis.
  Human tetap yang memvalidasi, membuktikan, dan melaporkan.

Alur kerja:
  [RECON] → [SCAN] → [AI TRIAGE] → [HUMAN VERIFY] → [REPORT]
"""

import os
import re
import subprocess
import requests
import datetime
import psutil
import json
from pathlib import Path
import sys
import time

# ══════════════════════════════════════════════
# KONFIGURASI
# ══════════════════════════════════════════════

OLLAMA_API     = "http://localhost:11434/api/generate"
MODEL          = "llama3:latest"          # Meta-Llama-3-8B-Instruct

REPORT_DIR     = Path("./reports")
REPORT_DIR.mkdir(exist_ok=True)

WORDLIST       = "/Users/macbookair/Documents/SecLists/Discovery/Web-Content/common.txt"

# Token dinaikkan: 8B Instruct di 16GB RAM mampu 2048 tanpa swap
MAX_OUTPUT_TOKENS = 2048
REQUEST_TIMEOUT   = 300    # 5 menit — cukup untuk output panjang
RETRY_COUNT       = 3

# ══════════════════════════════════════════════
# UTILITIES
# ══════════════════════════════════════════════

def banner():
    print("""
\033[38;5;208m
 █████╗ ██╗    ██████╗ ██╗   ██╗ ██████╗     ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██║    ██╔══██╗██║   ██║██╔════╝     ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
███████║██║    ██████╔╝██║   ██║██║  ███╗    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝ 
██╔══██║██║    ██╔══██╗██║   ██║██║   ██║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝  
██║  ██║██║    ██████╔╝╚██████╔╝╚██████╔╝    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║   
╚═╝  ╚═╝╚═╝    ╚═════╝  ╚═════╝  ╚═════╝     ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝   
          
[ AI-Augmented Bug Bounty Scanner | Model: Llama3 8B-Instruct ]\033[0m
""")

def run_command(command, timeout=120):
    """Jalankan command shell dengan timeout dan error handling yang baik."""
    try:
        result = subprocess.run(
            command, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout.strip() or result.stderr.strip()
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] Perintah '{command[:40]}...' melebihi {timeout}s"
    except Exception as e:
        return f"[ERROR] {e}"

def system_monitor():
    cpu  = psutil.cpu_percent(interval=0.5)
    ram  = psutil.virtual_memory()
    used = ram.used  // (1024**2)
    total= ram.total // (1024**2)
    bar  = "█" * int(ram.percent / 10) + "░" * (10 - int(ram.percent / 10))
    return f"CPU: {cpu:>5.1f}% | RAM: [{bar}] {ram.percent:.1f}% ({used}MB/{total}MB)"

def log(level, msg):
    """Logger berwarna untuk output yang lebih mudah dibaca."""
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
              "CRIT": "\033[91m", "SYS": "\033[90m", "AI": "\033[95m"}
    icons  = {"INFO": "◉", "OK": "✓", "WARN": "⚠", "CRIT": "✗", "SYS": "⚙", "AI": "🤖"}
    color  = colors.get(level, "\033[0m")
    icon   = icons.get(level, "•")
    ts     = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"\033[90m[{ts}]\033[0m {color}[{icon} {level}]\033[0m {msg}")

# ══════════════════════════════════════════════
# PHASE 1: RECON & SCANNING
# ══════════════════════════════════════════════

def phase_recon(target):
    """
    FASE RECON — Kumpulkan data sebanyak mungkin.
    Output mentah, belum dianalisis.
    """
    log("INFO", f"Fase Recon dimulai → target: {target}")
    results = {}

    # Nmap: service version detection
    log("INFO", "Nmap sV scan...")
    results["nmap"] = run_command(
        f"nmap -sV --version-intensity 5 -T4 --open {target}", timeout=180
    )

    # Nikto: web vulnerability scanner
    log("INFO", "Nikto web scan...")
    results["nikto"] = run_command(
        f"nikto -h http://{target} -maxtime 90 -nointeractive", timeout=120
    )

    # Gobuster: directory brute force
    log("INFO", "Gobuster directory scan...")
    if os.path.exists(WORDLIST):
        results["gobuster"] = run_command(
            f"gobuster dir -u http://{target} -w {WORDLIST} -q --timeout 8s",
            timeout=150
        )
    else:
        results["gobuster"] = "Wordlist tidak ditemukan. Install: apt install dirb"

    return results

# ══════════════════════════════════════════════
# PHASE 2: INTELLIGENT PARSING
# ══════════════════════════════════════════════

def extract_services(nmap_output):
    """Ekstrak service yang terbuka dari output nmap."""
    services = []
    for line in nmap_output.splitlines():
        if "/tcp" in line and "open" in line:
            services.append(line.strip())
    return services[:25]

def extract_versions(nmap_output):
    """
    Ekstrak fingerprint versi software dari nmap.
    Diperluas: 20+ teknologi umum yang sering jadi target bug bounty.
    """
    keywords = [
        # Web servers
        "Apache", "Nginx", "nginx", "IIS", "Lighttpd",
        # Languages/runtimes
        "PHP", "Python", "Ruby", "Node", "Perl",
        # SSH/FTP
        "OpenSSH", "vsftpd", "ProFTPD",
        # Database
        "MySQL", "MariaDB", "PostgreSQL", "MongoDB",
        # App servers
        "Tomcat", "JBoss", "WebLogic", "GlassFish",
        # Mail
        "Postfix", "Exim", "Dovecot",
        # Other
        "Samba", "OpenVPN", "Jenkins", "Gitlab"
    ]
    versions = []
    for line in nmap_output.splitlines():
        if any(kw.lower() in line.lower() for kw in keywords):
            versions.append(line.strip())
    # Deduplicate sambil pertahankan urutan
    seen = set()
    unique = []
    for v in versions:
        if v not in seen:
            seen.add(v)
            unique.append(v)
    return unique[:15]

def extract_cves(text):
    """Ekstrak semua CVE ID yang muncul di output scan."""
    return sorted(set(re.findall(r"CVE-\d{4}-\d+", text)))

def filter_nikto_noise(nikto_raw):
    """
    Filter output Nikto.
    Nikto menghasilkan banyak noise (header info, dll).
    Kita ambil hanya temuan yang benar-benar relevan.
    """
    # Keyword yang menandakan temuan penting
    high_value = [
        "CVE", "OSVDB", "inject", "XSS", "SQLi", "RCE",
        "traversal", "upload", "backup", "config", "phpinfo",
        "admin", "shell", "passwd", "credential", "token",
        "vuln", "danger", "outdated", "exposed", "disclosure",
        "bypass", "overflow", "execute", "arbitrary"
    ]
    # Keyword noise yang bisa diabaikan
    noise = [
        "Retrieved x-powered", "Cookie", "Allowed HTTP Methods",
        "X-Frame-Options", "X-XSS-Protection", "X-Content-Type",
        "Uncommon header", "No CGI", "Server leaks"
    ]

    high_value_lines = []
    info_lines = []

    for line in nikto_raw.splitlines():
        line = line.strip()
        if not line or len(line) < 15:
            continue
        if any(n in line for n in noise):
            continue
        if any(h in line for h in high_value):
            high_value_lines.append(f"🔴 {line}")
        elif line.startswith("+"):
            info_lines.append(f"🔵 {line}")

    combined = high_value_lines + info_lines[:10]
    return "\n".join(combined[:50]) if combined else "Tidak ada temuan signifikan dari Nikto."

def parse_searchsploit(json_str):
    """Parse output JSON dari searchsploit menjadi format yang readable."""
    try:
        data = json.loads(json_str)
        exploits = data.get("RESULTS_EXPLOIT", [])
        if not exploits:
            return None
        results = []
        for exp in exploits[:5]:  # Ambil max 5 exploit per software
            results.append(
                f"  [EDB-{exp.get('EDB-ID','?')}] {exp.get('Title','Unknown')} "
                f"({exp.get('Type','?')})"
            )
        return "\n".join(results)
    except (json.JSONDecodeError, KeyError):
        return None

# ══════════════════════════════════════════════
# PHASE 3: AI TRIAGE ENGINE
# ══════════════════════════════════════════════

def build_system_prompt():
    """
    System prompt untuk Llama3 8B-Instruct.
    Pisahkan dari user prompt — ini penting untuk Instruct model!
    System prompt mendefinisikan PERSONA dan CONSTRAINT.
    """
    return """You are an elite offensive security researcher and bug bounty hunter with 10+ years of experience.

Your expertise:
- Web application security (OWASP Top 10, business logic flaws)
- Network infrastructure attacks
- CVE analysis and exploit chain construction
- Writing high-quality bug bounty reports

Your analysis principles:
1. EVIDENCE-BASED: Only analyze what's confirmed in scan data. Never assume.
2. SPECIFIC: Name exact CVEs, versions, endpoints. No generic advice.
3. ACTIONABLE: Every finding maps to a concrete attack vector.
4. SEVERITY: Use CVSS v3 scoring (Critical 9-10, High 7-8.9, Medium 4-6.9, Low 0-3.9).
5. HONEST: If version is unconfirmed, say "Version unconfirmed — confidence: LOW".

You NEVER fabricate CVEs or exploit details not supported by the evidence."""

def build_user_prompt(target, summary, cves_found):
    """
    User prompt terstruktur untuk Llama3 8B-Instruct.
    Gunakan heading yang jelas — model Instruct sangat responsif terhadap struktur.
    """
    cve_list = ", ".join(cves_found) if cves_found else "Tidak ada CVE terdeteksi di scan output"

    return f"""Analyze the following penetration test reconnaissance data for a bug bounty assessment.

TARGET: {target}

=== SCAN DATA ===
{summary}

=== CVEs DETECTED ===
{cve_list}

=== ANALYSIS REQUIRED ===
Provide a structured security assessment in EXACTLY this format:

## 1. EXECUTIVE SUMMARY
[2-3 kalimat: overall risk posture, most critical finding, potential business impact jika dieksploitasi]

## 2. ATTACK SURFACE MAP
[List setiap service/port yang terbuka dengan:]
| Service | Version | Status | Risk Level | Notes |
(gunakan format tabel)

## 3. HIGH-PRIORITY FINDINGS
[Untuk setiap temuan bernilai tinggi:]
**Finding:** [nama]
**Component:** [spesifik]
**CVE:** [ID atau "No CVE — custom finding"]
**CVSS Score:** [angka] | **Severity:** [Critical/High/Medium/Low]
**Attack Vector:** [deskripsi teknis cara eksploitasi]
**Evidence:** [data dari scan yang mendukung]
**Confidence:** [High/Medium/Low]

## 4. REALISTIC ATTACK CHAIN
[Skenario serangan yang paling mungkin dari recon → exploit → impact:]
Initial Access → Privilege Escalation → Lateral Movement → Data Exfiltration

## 5. BUG BOUNTY POTENTIAL
[Perkiraan findings yang layak dilaporkan ke program bug bounty:]
- P1 (Critical): [list]
- P2 (High): [list]
- P3 (Medium): [list]

## 6. NEXT STEPS FOR MANUAL VERIFICATION
[Apa yang harus diverifikasi manual oleh pentester sebelum submit laporan]

Begin analysis:"""

def send_to_ollama(system_prompt, user_prompt):
    """
    Kirim ke Ollama dengan parameter yang dioptimalkan untuk Llama3 8B-Instruct.
    """
    payload = {
        "model":   MODEL,
        "system":  system_prompt,   # Field 'system' khusus untuk Instruct model
        "prompt":  user_prompt,
        "stream":  False,
        "options": {
            "num_predict":    MAX_OUTPUT_TOKENS,
            "temperature":    0.15,   # Rendah = lebih faktual dan deterministik
            "top_p":          0.90,   # Nucleus sampling — variasi terkontrol
            "repeat_penalty": 1.15,   # Cegah repetisi kalimat
            "num_ctx":        4096,   # Context window penuh Llama3
        }
    }

    for attempt in range(RETRY_COUNT):
        try:
            log("AI", f"Mengirim ke Ollama (attempt {attempt+1}/{RETRY_COUNT})...")
            r = requests.post(OLLAMA_API, json=payload, timeout=REQUEST_TIMEOUT)
            r.raise_for_status()
            response = r.json().get("response", "").strip()

            if response and len(response) > 200:
                log("OK", f"AI response diterima ({len(response)} chars)")
                return response
            else:
                log("WARN", "Response terlalu pendek, mencoba lagi...")

        except requests.exceptions.Timeout:
            log("WARN", f"Timeout setelah {REQUEST_TIMEOUT}s — model mungkin overload")
        except requests.exceptions.ConnectionError:
            log("CRIT", "Tidak bisa terhubung ke Ollama — pastikan service berjalan")
        except requests.exceptions.RequestException as e:
            log("WARN", f"Request error: {e}")

        if attempt < RETRY_COUNT - 1:
            log("INFO", "Menunggu 5 detik sebelum retry...")
            time.sleep(5)

    return "[ERROR] Ollama tidak merespons setelah semua retry. Cek: ollama serve"

# ══════════════════════════════════════════════
# PHASE 4: REPORT GENERATION
# ══════════════════════════════════════════════

def generate_report(target, summary, ai_analysis, cves_found, scan_duration):
    """
    Buat laporan TXT dan HTML yang profesional.
    HTML menggunakan dark theme ala terminal — sesuai konteks security.
    """
    timestamp   = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = re.sub(r"[^\w\-]", "_", target)

    txt_file  = REPORT_DIR / f"{safe_target}_report_{timestamp}.txt"
    html_file = REPORT_DIR / f"{safe_target}_report_{timestamp}.html"

    # ── TXT Report ──
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write("=" * 65 + "\n")
        f.write("     AI-AUGMENTED BUG BOUNTY RECONNAISSANCE REPORT\n")
        f.write("=" * 65 + "\n")
        f.write(f"Target         : {target}\n")
        f.write(f"Generated      : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Scan Duration  : {scan_duration:.1f} detik\n")
        f.write(f"CVEs Detected  : {', '.join(cves_found) if cves_found else 'None'}\n")
        f.write(f"AI Model       : {MODEL} (Llama3 8B-Instruct)\n")
        f.write("=" * 65 + "\n\n")
        f.write("DISCLAIMER: Laporan ini hanya valid untuk target yang\n")
        f.write("telah mendapat izin eksplisit (bug bounty scope atau pentest legal).\n\n")
        f.write("── TECHNICAL SUMMARY ──\n\n")
        f.write(summary)
        f.write("\n\n── AI TRIAGE ANALYSIS ──\n\n")
        f.write(ai_analysis)
        f.write("\n\n── CATATAN PENTESTER ──\n")
        f.write("[ ] Verifikasi manual setiap temuan sebelum submit\n")
        f.write("[ ] Buat PoC (Proof of Concept) yang jelas\n")
        f.write("[ ] Screenshot request/response sebagai evidence\n")
        f.write("[ ] Tulis impact statement yang konkret\n")

    # ── HTML Report ──
    cve_badges = "".join(
        f'<span class="cve-badge">{c}</span>' for c in cves_found
    ) if cves_found else '<span class="no-cve">None detected</span>'

    html_content = f"""<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Bug Bounty Report — {target}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
        header {{ background: linear-gradient(135deg, #161b22, #1f2937); padding: 30px 40px; border-bottom: 2px solid #e94560; }}
        h1 {{ font-size: 1.8rem; color: #e94560; margin-bottom: 8px; }}
        .subtitle {{ color: #8b949e; font-size: 0.9rem; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 40px; }}
        .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin: 20px 0 30px; }}
        .meta-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 14px 18px; }}
        .meta-card .label {{ font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }}
        .meta-card .value {{ font-size: 0.95rem; color: #e6edf3; font-weight: 500; }}
        .section {{ margin-bottom: 28px; }}
        h2 {{ font-size: 1.1rem; color: #58a6ff; background: #161b22; padding: 10px 16px; border-left: 3px solid #e94560; border-radius: 0 6px 6px 0; margin-bottom: 14px; }}
        pre {{ background: #010409; color: #39d353; padding: 20px; border-radius: 8px; overflow-x: auto; font-size: 0.82rem; line-height: 1.7; white-space: pre-wrap; border: 1px solid #30363d; }}
        .cve-badge {{ background: #da3633; color: white; padding: 3px 10px; border-radius: 20px; font-size: 0.75rem; font-weight: 600; margin-right: 6px; display: inline-block; margin-bottom: 4px; }}
        .no-cve {{ color: #8b949e; font-size: 0.85rem; }}
        .disclaimer {{ background: #161b22; border: 1px solid #f0883e; border-radius: 8px; padding: 14px 18px; margin-bottom: 24px; font-size: 0.85rem; color: #f0883e; }}
        .checklist {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 20px; }}
        .checklist h3 {{ color: #7ee787; margin-bottom: 10px; font-size: 0.95rem; }}
        .checklist-item {{ display: flex; align-items: center; gap: 10px; margin: 8px 0; color: #c9d1d9; font-size: 0.85rem; }}
        .checkbox {{ width: 16px; height: 16px; border: 2px solid #30363d; border-radius: 3px; flex-shrink: 0; }}
        footer {{ text-align: center; padding: 20px; color: #8b949e; font-size: 0.8rem; border-top: 1px solid #30363d; margin-top: 30px; }}
        .ai-note {{ display: inline-block; background: #1f2937; border: 1px solid #58a6ff; border-radius: 6px; padding: 4px 10px; font-size: 0.78rem; color: #58a6ff; margin-bottom: 10px; }}
    </style>
</head>
<body>
    <header>
        <h1>🛡️ AI-Augmented Bug Bounty Report</h1>
        <div class="subtitle">Reconnaissance & Triage Analysis — Powered by {MODEL}</div>
    </header>
    <div class="container">
        <div class="disclaimer">
            ⚠️ <strong>Legal Notice:</strong> Laporan ini hanya untuk target dengan izin eksplisit 
            (authorized bug bounty program atau penetration test legal). 
            Penggunaan tanpa izin adalah ilegal.
        </div>
        <div class="meta-grid">
            <div class="meta-card"><div class="label">Target</div><div class="value">{target}</div></div>
            <div class="meta-card"><div class="label">Generated</div><div class="value">{datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</div></div>
            <div class="meta-card"><div class="label">Scan Duration</div><div class="value">{scan_duration:.1f} detik</div></div>
            <div class="meta-card"><div class="label">AI Model</div><div class="value">{MODEL}</div></div>
        </div>
        <div class="section">
            <h2>🔍 CVEs Detected</h2>
            {cve_badges}
        </div>
        <div class="section">
            <h2>📊 Technical Summary</h2>
            <pre>{summary}</pre>
        </div>
        <div class="section">
            <h2>🤖 AI Triage Analysis</h2>
            <div class="ai-note">⚡ Generated by {MODEL} — MUST be verified manually before any action</div>
            <pre>{ai_analysis}</pre>
        </div>
        <div class="checklist">
            <h3>✅ Pre-Submission Checklist</h3>
            <div class="checklist-item"><div class="checkbox"></div>Verifikasi setiap temuan secara manual</div>
            <div class="checklist-item"><div class="checkbox"></div>Buat Proof of Concept (PoC) yang bisa direproduksi</div>
            <div class="checklist-item"><div class="checkbox"></div>Screenshot HTTP request & response sebagai evidence</div>
            <div class="checklist-item"><div class="checkbox"></div>Tulis business impact statement yang konkret</div>
            <div class="checklist-item"><div class="checkbox"></div>Pastikan target dalam scope program bug bounty</div>
            <div class="checklist-item"><div class="checkbox"></div>Baca disclosure policy program sebelum submit</div>
        </div>
    </div>
    <footer>
        AI-Augmented Bug Bounty Scanner | AI assists, Humans decide | For authorized use only
    </footer>
</body>
</html>"""

    with open(html_file, "w", encoding="utf-8") as f:
        f.write(html_content)

    log("OK", f"TXT  → {txt_file}")
    log("OK", f"HTML → {html_file}")
    return html_file

# ══════════════════════════════════════════════
# MAIN ORCHESTRATOR
# ══════════════════════════════════════════════

def main(target):
    banner()
    start_time = time.time()

    log("SYS", f"Target: {target}")
    log("SYS", system_monitor())
    print()

    # ── Phase 1: Recon ──
    print("\033[93m▶ PHASE 1: RECONNAISSANCE\033[0m")
    raw_data = phase_recon(target)

    # ── Phase 2: Parse & Enrich ──
    print("\n\033[93m▶ PHASE 2: INTELLIGENT PARSING\033[0m")

    services = extract_services(raw_data["nmap"])
    versions = extract_versions(raw_data["nmap"])
    log("OK", f"Services: {len(services)} terbuka | Versions: {len(versions)} terdeteksi")

    # Searchsploit per versi terdeteksi
    exploit_results = ""
    if versions:
        log("INFO", "Mapping exploits via Searchsploit...")
        for v in versions[:5]:
            raw_exploit = run_command(f"searchsploit --json '{v}'", timeout=30)
            parsed = parse_searchsploit(raw_exploit)
            if parsed:
                exploit_results += f"\n[{v}]\n{parsed}\n"

    nikto_filtered = filter_nikto_noise(raw_data["nikto"])

    # Kompilasi summary yang bersih
    summary = f"""SERVICES DETECTED ({len(services)} open ports):
{'─' * 40}
{chr(10).join(services) if services else 'Tidak ada service terdeteksi'}

VERSION FINGERPRINTS:
{'─' * 40}
{chr(10).join(versions) if versions else 'Tidak ada version info'}

NIKTO WEB FINDINGS (filtered):
{'─' * 40}
{nikto_filtered}

GOBUSTER DIRECTORY SCAN:
{'─' * 40}
{raw_data['gobuster'][:1200] if raw_data['gobuster'] else 'Tidak ada path ditemukan'}

SEARCHSPLOIT EXPLOIT MAP:
{'─' * 40}
{exploit_results[:1500] if exploit_results else 'Tidak ada exploit yang termap'}"""

    # Ekstrak semua CVE dari output
    all_output = " ".join(raw_data.values()) + exploit_results
    cves_found = extract_cves(all_output)
    if cves_found:
        log("CRIT", f"CVEs ditemukan: {', '.join(cves_found)}")
    else:
        log("INFO", "Tidak ada CVE eksplisit terdeteksi dari scan output")

    # ── Phase 3: AI Triage ──
    print("\n\033[93m▶ PHASE 3: AI TRIAGE\033[0m")
    log("SYS", system_monitor())
    log("AI", f"Mengirim data ke Llama3 8B-Instruct... (estimasi: 60-120 detik)")

    system_prompt = build_system_prompt()
    user_prompt   = build_user_prompt(target, summary, cves_found)

    ai_analysis   = send_to_ollama(system_prompt, user_prompt)
    log("SYS", system_monitor())

    # ── Phase 4: Report ──
    print("\n\033[93m▶ PHASE 4: REPORT GENERATION\033[0m")
    scan_duration = time.time() - start_time
    report_path   = generate_report(target, summary, ai_analysis, cves_found, scan_duration)

    # ── Summary ──
    print(f"""
\033[92m{'═' * 50}
  SCAN SELESAI
{'═' * 50}\033[0m
  Target       : {target}
  Durasi       : {scan_duration:.1f} detik
  CVEs         : {len(cves_found)} ditemukan
  Report       : ./reports/

\033[93m  ⚠ REMINDER:\033[0m
  AI hanya membantu triage — SEMUA temuan WAJIB
  diverifikasi manual sebelum submit ke program
  bug bounty. AI tidak bisa gantikan human judgment.
""")

# ══════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"\nUsage  : python3 {sys.argv[0]} <target>")
        print(f"Example: python3 {sys.argv[0]} 192.168.1.100")
        print(f"Example: python3 {sys.argv[0]} testphp.vulnweb.com\n")
        sys.exit(1)

    target = sys.argv[1].strip().rstrip("/")
    main(target)
