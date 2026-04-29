import os
import re
import json
from datetime import datetime, timedelta
from dotenv import load_dotenv

try:
    from checkers.virustotal import check_virustotal
    from checkers.ctx import check_ctx
    from checkers.otx import check_otx
    from checkers.abuseipdb import check_abuseipdb
except ImportError as e:
    print(json.dumps({"error": "Module import failed", "details": str(e)}))
    exit()

load_dotenv()

CACHE_FILE = "cti_cache.json"
CACHE_EXPIRY_HOURS = 24

def load_cache():
    if not os.path.exists(CACHE_FILE): return {}
    try:
        with open(CACHE_FILE, 'r') as f: return json.load(f)
    except: return {}

def save_cache(cache_data):
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache_data, f, indent=4)
    except: pass

# --- FUNGSI NORMALISASI ---
def normalize_vt(raw):
    if not raw or any(x in str(raw) for x in ["Error", "Not Found"]): return 0.0
    match = re.search(r'(\d+)/(\d+)', str(raw))
    return int(match.group(1))/int(match.group(2)) if match else 0.0

def normalize_ctx(raw):
    safe = ["Not Found", "Error", "None", "normal"]
    return 0.0 if not raw or any(s in str(raw).lower() for s in safe) else 1.0

def normalize_otx(raw):
    if not raw or "none" in str(raw).lower(): return 0.0
    match = re.search(r'(\d+) pulses', str(raw))
    return min(int(match.group(1)) / 50.0, 1.0) if match else 0.0

def normalize_abuseipdb(raw):
    if not raw or "Error" in str(raw): return 0.0
    match = re.search(r'(\d+)', str(raw))
    return min(int(match.group(1)) / 100.0, 1.0) if match else 0.0

def extract_ctx_name(raw):
    if not raw:
        return None
    raw_str = str(raw).strip()
    if any(x in raw_str.lower() for x in ["not found", "error", "none", "normal"]):
        return None
    return raw_str

# --- CORE ENGINE ---
def get_threat_analysis(file_hash, src_ip, dest_ip, file_path, source):
    cache_key = f"{source}_{file_hash}_{src_ip}"
    cache_data = load_cache()

    # 1. CEK CACHE
    if cache_key in cache_data:
        entry = cache_data[cache_key]
        status = entry['data']['scores']['status']
        if status in ["MALICIOUS", "SUSPICIOUS"]:
            entry['data']['timestamp'] = datetime.now().isoformat()
            return entry['data']
        else:
            cached_time = datetime.fromisoformat(entry['cache_timestamp'])
            if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
                entry['data']['timestamp'] = datetime.now().isoformat()
                return entry['data']


    ctx_name = None

    if source == "fim":
        # --- PATH: FIM → Hash-based scoring ---
        raw_h_vt  = check_virustotal(file_hash, "hash")
        raw_h_ctx = check_ctx(file_hash, "hash")
        ctx_name  = extract_ctx_name(raw_h_ctx)

        s_h_vt  = normalize_vt(raw_h_vt)
        s_h_ctx = normalize_ctx(raw_h_ctx)

        W_VT  = 0.2671
        W_CTX = 0.2571
        W_TOTAL = W_VT + W_CTX 

        hash_score  = (s_h_vt * W_VT + s_h_ctx * W_CTX) / W_TOTAL
        final_score = hash_score

        score_details = {
            "source"  : "fim",
            "vt_norm" : round(s_h_vt, 4),
            "ctx_norm": round(s_h_ctx, 4),
            "ctx_name": ctx_name,
            "hash_score": round(hash_score, 4)
        }

    else:
        # --- PATH: Suricata → IP-based scoring ---
        raw_i_abuse = check_abuseipdb(src_ip, "ip")
        raw_i_vt    = check_virustotal(src_ip, "ip")
        raw_i_ctx   = check_ctx(src_ip, "ip")
        raw_i_otx   = check_otx(src_ip, "ip")

        s_i_abuse = normalize_abuseipdb(raw_i_abuse)
        s_i_vt    = normalize_vt(raw_i_vt)
        s_i_ctx   = normalize_ctx(raw_i_ctx)
        s_i_otx   = normalize_otx(raw_i_otx)

        # Total bobot = 1.0, tidak perlu normalisasi ulang
        ip_score = (
            s_i_vt    * 0.2671 +
            s_i_ctx   * 0.2571 +
            s_i_otx   * 0.2320 +
            s_i_abuse * 0.2437
        )
        final_score = ip_score

        score_details = {
            "source"      : "suricata",
            "analyzed"    : "src_ip",
            "vt_norm"     : round(s_i_vt, 4),
            "ctx_norm"    : round(s_i_ctx, 4),
            "otx_norm"    : round(s_i_otx, 4),
            "abuseipdb_norm": round(s_i_abuse, 4),
            "ip_score"    : round(ip_score, 4)
        }

    # 3. PENENTUAN STATUS
    status   = "MALICIOUS" if final_score >= 0.6 else "SUSPICIOUS" if final_score >= 0.2 else "NORMAL"
    severity = "high" if status == "MALICIOUS" else "medium" if status == "SUSPICIOUS" else "low"

    # 4. OUTPUT & CACHING
    result = {
        "timestamp": datetime.now().isoformat(),
        "target": {
            "file_hash": file_hash,
            "filename" : os.path.basename(file_path) if file_path else "unknown",
            "path"     : file_path,
            "src_ip"   : src_ip,
            "dst_ip"   : dest_ip
        },
        "scores": {
            "final_score": round(final_score, 4),
            "status"     : status,
            "severity"   : severity
        },
        "details": score_details
    }

    cache_data[cache_key] = {"cache_timestamp": datetime.now().isoformat(), "data": result}
    save_cache(cache_data)

    return result

if __name__ == "__main__":
    pass
