"""
IOC Dashboard SOC — app.py
Pipeline : upload .txt → vt_tools.py → CSV IP → MISP → dashboard
Source de vérité : MISP uniquement (jamais les CSV directement)
"""

import os
import re
import csv
import glob
import subprocess
import logging
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute

# ─────────────────────────────────────────────
# LOGGING — visible dans le terminal Docker
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.DEBUG,
    format="[%(levelname)s] %(message)s"
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────
# BLOC A — Configuration & connexion MISP
# ─────────────────────────────────────────────

_vt_tool_dir = os.environ.get("VT_TOOL_DIR", os.path.expanduser("~/p/vt_tool"))
_env_path = os.path.join(_vt_tool_dir, ".env")
log.info(f"Loading .env from : {_env_path}")
load_dotenv(dotenv_path=_env_path)

app = Flask(__name__)
app.secret_key = os.urandom(24)

MISPURL       = os.environ.get("MISPURL", "https://localhost")
MISPKEY       = os.environ.get("MISPKEY", "")
MISPSSLVERIFY = os.environ.get("MISPSSLVERIFY", "False").lower() not in ("true", "1")
VT_TOOL_DIR   = os.path.expanduser(os.environ.get("VT_TOOL_DIR", "~/p/vt_tool"))
RESULTS_DIR   = os.path.join(VT_TOOL_DIR, "Results")
UPLOAD_DIR    = os.path.join(VT_TOOL_DIR, "Up")


log.info(f"VT_TOOL_DIR   : {VT_TOOL_DIR}")
log.info(f"RESULTS_DIR   : {RESULTS_DIR}")
log.info(f"MISPURL       : {MISPURL}")
log.info(f"MISPKEY       : {'SET (' + MISPKEY[:6] + '...)' if MISPKEY else '⚠ NOT SET'}")
log.info(f"MISPSSLVERIFY : {MISPSSLVERIFY}")


def get_misp():
    """Instancie PyMISP. Retourne None si MISP indisponible ou clé absente."""
    if not MISPKEY:
        log.error("get_misp() → MISPKEY is empty — check your .env file")
        return None
    try:
        log.debug(f"get_misp() → connecting to {MISPURL} (ssl={not MISPSSLVERIFY})")
        misp = PyMISP(MISPURL, MISPKEY, ssl=not MISPSSLVERIFY)
        log.info("get_misp() → connection OK")
        return misp
    except Exception as e:
        log.error(f"get_misp() → connection FAILED : {type(e).__name__}: {e}")
        return None


# ─────────────────────────────────────────────
# BLOC B — Parsing du CSV IP (fichier le plus récent)
# ─────────────────────────────────────────────

def parse_ip_csv():
    pattern = os.path.join(RESULTS_DIR, "*_IP_Analysis_*.csv")
    files = glob.glob(pattern)
    log.debug(f"parse_ip_csv() → looking for: {pattern}")
    log.debug(f"parse_ip_csv() → found {len(files)} file(s): {files}")

    if not files:
        log.warning("parse_ip_csv() → no IP CSV found in Results/")
        return []

    latest = max(files, key=os.path.getmtime)
    log.info(f"parse_ip_csv() → reading: {latest}")

    seen = set()
    iocs = []

    try:
        with open(latest, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get("ip", "").strip()
                if not ip or ip in seen:
                    continue
                seen.add(ip)

                raw_score   = row.get("malicious_score", "").strip()
                total_scans = row.get("total_scans", "").strip()
                tags_val    = row.get("tags", "").strip()
                link        = row.get("link", "").strip()

                if raw_score.lower() in ("not found", "") and tags_val.lstrip("-").isdigit():
                    log.debug(f"parse_ip_csv() → {ip}: score in 'tags' column = {tags_val}")
                    raw_score = tags_val

                score_is_num = raw_score.lstrip("-").isdigit()
                total_is_num = total_scans.lstrip("-").isdigit()

                if not score_is_num:
                    formatted_score = "Not found"
                elif total_is_num and int(total_scans) > 0:
                    formatted_score = f"{int(raw_score)}/{int(total_scans)}"
                else:
                    formatted_score = f"{int(raw_score)}/94"

                log.debug(f"parse_ip_csv() → {ip} : score={formatted_score}")
                iocs.append({
                    "value":           ip,
                    "misp_type":       "ip-dst",
                    "malicious_score": formatted_score,
                    "total_scans":     total_scans,
                    "link":            link,
                })
    except (OSError, csv.Error) as e:
        log.error(f"parse_ip_csv() → failed to read CSV: {type(e).__name__}: {e}")
        return []

    log.info(f"parse_ip_csv() → extracted {len(iocs)} unique IPs")
    return iocs


# ─────────────────────────────────────────────
# BLOC C — Création Event MISP
# ─────────────────────────────────────────────

def create_misp_event(iocs, filename):
    misp = get_misp()
    if misp is None:
        log.error("create_misp_event() → get_misp() returned None, aborting")
        return None

    try:
        log.info(f"create_misp_event() → creating event for '{filename}' with {len(iocs)} IoCs")
        event = MISPEvent()
        event.info            = f"SOC Analysis — {filename}"
        event.distribution    = 0
        event.threat_level_id = 2
        event.analysis        = 0

        for ioc in iocs:
            event.add_attribute(
                type    = "ip-dst",
                value   = ioc["value"],
                comment = ioc["malicious_score"],
                to_ids  = False,
            )

        result = misp.add_event(event)
        log.debug(f"create_misp_event() → raw result type: {type(result)}, value: {result}")

        if hasattr(result, "id"):
            log.info(f"create_misp_event() → Event created, ID={result.id}")
            return int(result.id)
        if isinstance(result, dict):
            eid = int(result.get("Event", {}).get("id", 0)) or None
            log.info(f"create_misp_event() → Event created (dict), ID={eid}")
            return eid

        log.error(f"create_misp_event() → unexpected result format: {result}")
        return None

    except Exception as e:
        log.error(f"create_misp_event() → FAILED: {type(e).__name__}: {e}")
        return None


# ─────────────────────────────────────────────
# BLOC D — Lecture MISP (source de vérité)
# ─────────────────────────────────────────────

def get_score_status(score_str):
    if not score_str or score_str.strip().lower() == "not found":
        return {"malicious": None, "total": None, "status": "UNKNOWN", "badge": "badge-unknown"}

    match = re.match(r"(\d+)/(\d+)", score_str.strip())
    if not match:
        return {"malicious": None, "total": None, "status": "UNKNOWN", "badge": "badge-unknown"}

    malicious = int(match.group(1))
    total     = int(match.group(2))

    if malicious > 5:
        return {"malicious": malicious, "total": total, "status": "MALICIOUS", "badge": "badge-malicious"}
    elif malicious > 0:
        return {"malicious": malicious, "total": total, "status": "SUSPECT",   "badge": "badge-suspect"}
    else:
        return {"malicious": malicious, "total": total, "status": "CLEAN",     "badge": "badge-clean"}


def read_misp_event(event_id):
    misp = get_misp()
    if misp is None:
        log.error(f"read_misp_event({event_id}) → get_misp() returned None")
        return []

    try:
        log.info(f"read_misp_event() → fetching event ID={event_id}")
        event = misp.get_event(event_id, pythonify=True)
        results = []
        for attr in event.attributes:
            if attr.type != "ip-dst":
                continue
            score_str = attr.comment or "Not found"
            info      = get_score_status(score_str)
            results.append({
                "value":           attr.value,
                "malicious_score": score_str,
                "status":          info["status"],
                "badge":           info["badge"],
                "link":            f"https://www.virustotal.com/gui/ip-address/{attr.value}",
            })
        log.info(f"read_misp_event() → got {len(results)} attributes from MISP")
        return results
    except Exception as e:
        log.error(f"read_misp_event({event_id}) → FAILED: {type(e).__name__}: {e}")
        return []


def list_misp_events():
    misp = get_misp()
    if misp is None:
        log.warning("list_misp_events() → MISP unavailable")
        return []
    try:
        events = misp.search(controller="events", pythonify=True)
        result = []
        for e in events:
            result.append({
                "id":            e.id,
                "info":          e.info,
                "date":          str(e.date),
                "nb_attributes": len(e.attributes),
                "misp_link":     f"{MISPURL}/events/view/{e.id}",
            })
        result.sort(key=lambda x: int(x["id"]), reverse=True)
        log.info(f"list_misp_events() → {len(result)} events found")
        return result
    except Exception as e:
        log.error(f"list_misp_events() → FAILED: {type(e).__name__}: {e}")
        return []


# ─────────────────────────────────────────────
# BLOC E — Routes Flask
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("report")
    if not uploaded or uploaded.filename == "":
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("index"))
    if not uploaded.filename.endswith(".txt"):
        flash("Format invalide : seuls les fichiers .txt sont acceptés.", "error")
        return redirect(url_for("index"))

    filename    = uploaded.filename
    report_path = os.path.join(VT_TOOL_DIR, filename)

    log.info(f"analyze() → saving uploaded file to: {report_path}")
    os.makedirs(VT_TOOL_DIR, exist_ok=True)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    uploaded.save(report_path)
    log.info(f"analyze() → file saved OK")

    venv_python = os.path.join(VT_TOOL_DIR, ".venv", "bin", "python")
    if not os.path.exists(venv_python):
        log.warning(f"analyze() → venv python not found at {venv_python}, falling back to python3")
        venv_python = "python3"
    vt_script = os.path.join(VT_TOOL_DIR, "vt_tools.py")
    log.info(f"analyze() → running: {venv_python} {vt_script} -n -f {report_path}")

    env = os.environ.copy()
    try:
        proc = subprocess.run(
            [venv_python, vt_script, "-n", "-f", report_path],
            cwd=VT_TOOL_DIR, env=env, check=True, timeout=120, capture_output=True,
        )
        log.info(f"analyze() → vt_tools.py stdout: {proc.stdout.decode()[:500]}")
    except subprocess.TimeoutExpired:
        log.error("analyze() → vt_tools.py TIMEOUT after 120s")
        flash("vt_tools.py a dépassé le délai (120s). Vérifiez votre connexion.", "error")
        return redirect(url_for("index"))
    except subprocess.CalledProcessError as exc:
        log.error(f"analyze() → vt_tools.py FAILED (code {exc.returncode})")
        log.error(f"analyze() → stderr: {exc.stderr.decode()[:500]}")
        log.error(f"analyze() → stdout: {exc.stdout.decode()[:500]}")
        flash(f"Erreur vt_tools.py (code {exc.returncode}). Vérifiez votre clé VirusTotal.", "error")
        return redirect(url_for("index"))

    iocs = parse_ip_csv()
    if not iocs:
        log.error("analyze() → parse_ip_csv() returned empty list")
        flash("Aucune adresse IP extraite. Vérifiez le contenu du fichier.", "error")
        return redirect(url_for("index"))

    event_id = create_misp_event(iocs, filename)
    if event_id is None:
        log.error("analyze() → create_misp_event() returned None — check MISP logs above")
        flash("Impossible de créer l'événement MISP. Vérifiez que MISP tourne et que la clé API est correcte.", "error")
        return redirect(url_for("index"))

    results = read_misp_event(event_id)
    if not results:
        log.error(f"analyze() → read_misp_event({event_id}) returned empty — check MISP logs above")
        flash("Event MISP créé (ID %d) mais impossible de relire les données." % event_id, "error")
        return redirect(url_for("index"))

    summary = {"total": len(results), "malicious": 0, "suspect": 0, "clean": 0, "unknown": 0}
    for r in results:
        summary[r["status"].lower()] += 1

    event_info = {"id": event_id, "info": f"SOC Analysis — {filename}"}

    return render_template(
        "results.html",
        results    = results,
        summary    = summary,
        filename   = filename,
        event_info = event_info,
        misp_url   = MISPURL,
        get_score  = get_score_status,
    )


@app.route("/history")
def history():
    events = list_misp_events()
    return render_template(
        "history.html",
        events   = events,
        misp_url = MISPURL,
    )


if __name__ == "__main__":
    log.info("=" * 50)
    log.info("IOC Dashboard starting...")
    log.info(f"VT_TOOL_DIR : {VT_TOOL_DIR}")
    log.info(f"MISP URL    : {MISPURL}")
    log.info(f"MISP KEY    : {'OK (' + MISPKEY[:6] + '...)' if MISPKEY else '⚠ NOT SET'}")
    log.info("=" * 50)
    app.run(host="0.0.0.0", port=5000, debug=True)
