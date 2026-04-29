import time
import json
import os
import sys
from datetime import datetime
from typing import Optional

try:
    from main_scoring import get_threat_analysis
except ImportError:
    print("❌ Error Fatal: File 'main_scoring.py' tidak ditemukan!")
    print("  Pastikan kedua file ada di folder yang sama.")
    sys.exit(1)

LOG_FILE = "/var/ossec/logs/alerts/alerts.json"

# ─── IGNORE LIST ────────────────────────────────────────────────────────────
IGNORE_EXT   = ('.part', '.tmp', '.crdownload', '.swp', '.temp')
IGNORE_PROTO = ('dns', 'dhcp', 'ntp', 'mdns', 'ssdp', 'arp')  # layer-2/discovery noise

def follow_log(filepath):
    """Generator: tail -f behaviour."""
    if not os.path.exists(filepath):
        print(f"❌ File log tidak ditemukan: {filepath}")
        return
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            f.seek(0, 2)
            print(f"[*] Watchdog Aktif! Memantau: {filepath}")
            print("[*] Menunggu trigger (FIM / Suricata fileinfo)...")
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                yield line
    except PermissionError:
        print("❌ Error: Permission Denied! Jalankan pakai 'sudo'.")
        sys.exit(1)


# ─── CORRELATION GATE ────────────────────────────────────────────────────────
def correlate_event(log: dict) -> Optional[dict]:

    data_block = log.get('data', {})
    syscheck   = log.get('syscheck', {})

    # ── JALUR FIM ──────────────────────────────────────────────────────────
    sha256_fim = syscheck.get('sha256_after')
    if sha256_fim:
        file_path = syscheck.get('path', 'Unknown')
        filename  = os.path.basename(file_path)

        # Filter ekstensi temporer
        if filename.lower().endswith(IGNORE_EXT):
            return None

        return {
            "source"   : "fim",
            "file_hash": sha256_fim,
            "file_path": file_path,
            "src_ip"   : "127.0.0.1",   # FIM lokal, tidak ada src_ip jaringan
            "dest_ip"  : "127.0.0.1",
        }

    # ── JALUR SURICATA fileinfo ────────────────────────────────────────────
    # Wazuh meletakkan payload Suricata di bawah log['data']
    event_type = data_block.get('event_type', '')
    app_proto  = data_block.get('app_proto', '').lower()
    fileinfo   = data_block.get('fileinfo', {})
    sha256_sur = fileinfo.get('sha256')

    if event_type == 'fileinfo' and sha256_sur:
        # Abaikan protokol discovery/noise
        if app_proto in IGNORE_PROTO:
            return None

        file_path = fileinfo.get('filename', 'Unknown')
        filename  = os.path.basename(file_path)

        if filename.lower().endswith(IGNORE_EXT):
            return None

        src_ip  = data_block.get('src_ip', '127.0.0.1')
        dest_ip = data_block.get('dest_ip', '127.0.0.1')

        return {
            "source"   : "suricata",
            "file_hash": sha256_sur,    # disimpan untuk referensi, bukan dianalisis
            "file_path": file_path,
            "src_ip"   : src_ip,
            "dest_ip"  : dest_ip,
        }

    # Semua event lain (port scan, DNS, HTTP tanpa file, dll) → NOISE
    return None


# ─── PROCESS ALERT ──────────────────────────────────────────────────────────
def process_alert(json_line: str):
    try:
        log = json.loads(json_line)
    except json.JSONDecodeError:
        return None

    # 1. Korelasi & filter noise
    ctx = correlate_event(log)
    if ctx is None:
        return None

    source    = ctx['source']
    file_hash = ctx['file_hash']
    file_path = ctx['file_path']
    src_ip    = ctx['src_ip']
    dest_ip   = ctx['dest_ip']
    filename  = os.path.basename(file_path)

    print(f"\n[!] Trigger [{source.upper()}] → {filename}")
    if source == "fim":
        print(f"    Hash : {file_hash}")
    else:
        print(f"    File : {filename}  |  Src IP: {src_ip}")

    try:
        return get_threat_analysis(
            file_hash=file_hash,
            src_ip=src_ip,
            dest_ip=dest_ip,
            file_path=file_path,
            source=source,
        )
    except Exception as e:
        print(f"⚠️  Warning: Gagal analisis. Error: {e}")
        return None


# ─── MAIN ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        for new_line in follow_log(LOG_FILE):
            analysis_data = process_alert(new_line)

            if analysis_data:
                target  = analysis_data.get('target', {})
                scores  = analysis_data.get('scores', {})
                details = analysis_data.get('details', {})

                final_json = {
                    "timestamp": datetime.now().isoformat(),
                    "target": {
                        "file_hash": target.get('file_hash'),
                        "filename" : target.get('filename', 'unknown'),
                        "path"     : target.get('path'),
                        "src_ip"   : target.get('src_ip', '127.0.0.1'),
                        "dst_ip"   : target.get('dst_ip', '127.0.0.1'),
                    },
                    "scores": {
                        "final_score": scores.get('final_score', 0.0),
                        "status"     : scores.get('status', 'NORMAL'),
                        "severity"   : scores.get('severity', 'low'),
                    },
                    "details": details,
                }

                print(json.dumps(final_json, indent=2))

                try:
                    with open("/var/log/cti_decision_results.log", "a") as f:
                        f.write(json.dumps(final_json) + "\n")
                except PermissionError:
                    print("❌ Error: Jalankan dengan 'sudo' untuk menulis log.")

    except KeyboardInterrupt:
        print("\n🛑 Watchdog dimatikan manual.")
