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
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, url_for, flash
from pymisp import PyMISP, MISPEvent, MISPAttribute

# ─────────────────────────────────────────────
# BLOC A — Configuration & connexion MISP
# ─────────────────────────────────────────────

load_dotenv(dotenv_path='../vt_tool/.env')

app = Flask(__name__)
app.secret_key = os.urandom(24)

MISPURL       = os.environ.get("MISPURL", "https://localhost")
MISPKEY       = os.environ.get("MISPKEY", "")
MISPSSLVERIFY = os.environ.get("MISPSSLVERIFY", "False").lower() not in ("true", "1")
VT_TOOL_DIR   = os.path.expanduser(os.environ.get("VT_TOOL_DIR", "~/p/vt_tool"))
RESULTS_DIR   = os.path.join(VT_TOOL_DIR, "Results")


def get_misp():
    """Instancie PyMISP. Retourne None si MISP indisponible ou clé absente."""
    if not MISPKEY:
        return None
    try:
        return PyMISP(MISPURL, MISPKEY, ssl=not MISPSSLVERIFY)
    except Exception:
        return None


# ─────────────────────────────────────────────
# BLOC B — Parsing du CSV IP (fichier le plus récent)
# ─────────────────────────────────────────────

def parse_ip_csv():
    """
    Trouve *_IP_Analysis_*.csv le plus récent dans Results/.
    Retourne une liste de dicts : { value, misp_type, malicious_score, total_scans, link }
    Gère : CSV absent, vide, score 'Not found', doublons.
    """
    pattern = os.path.join(RESULTS_DIR, "*_IP_Analysis_*.csv")
    files = glob.glob(pattern)
    if not files:
        return []

    latest = max(files, key=os.path.getmtime)
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

                # Fallback : versions récentes de vt_tools mettent le score dans 'tags'
                # quand malicious_score vaut "Not found"
                if raw_score.lower() in ("not found", "") and tags_val.lstrip("-").isdigit():
                    raw_score = tags_val

                score_is_num   = raw_score.lstrip("-").isdigit()
                total_is_num   = total_scans.lstrip("-").isdigit()

                if not score_is_num:
                    formatted_score = "Not found"
                elif total_is_num and int(total_scans) > 0:
                    formatted_score = f"{int(raw_score)}/{int(total_scans)}"
                else:
                    # total_scans absent dans ce format CSV — défaut VT = 94 moteurs
                    formatted_score = f"{int(raw_score)}/94"
                

                iocs.append({
                    "value":           ip,
                    "misp_type":       "ip-dst",
                    "malicious_score": formatted_score,
                    "total_scans":     total_scans,
                    "link":            link,
                })
    except (OSError, csv.Error):
        return []

    return iocs


# ─────────────────────────────────────────────
# BLOC C — Création Event MISP
# ─────────────────────────────────────────────

def create_misp_event(iocs, filename):
    """
    Crée un MISPEvent. Chaque IP → Attribute ip-dst, score dans Comment.
    Retourne event_id (int) ou None.
    """
    misp = get_misp()
    if misp is None:
        return None

    try:
        event = MISPEvent()
        event.info            = f"SOC Analysis — {filename}"
        event.distribution    = 0
        event.threat_level_id = 2
        event.analysis        = 0

        for ioc in iocs:
            event.add_attribute(
                type     = "ip-dst",
                value    = ioc["value"],
                comment  = ioc["malicious_score"],
                to_ids   = False,
            )

        result = misp.add_event(event)

        if hasattr(result, "id"):
            return int(result.id)
        if isinstance(result, dict):
            return int(result.get("Event", {}).get("id", 0)) or None
        return None
    except Exception:
        return None


# ─────────────────────────────────────────────
# BLOC D — Lecture MISP (source de vérité)
# ─────────────────────────────────────────────

def get_score_status(score_str):
    """
    Grille de scoring TP :
      malicious > 5       → MALICIOUS (rouge)
      0 < malicious ≤ 5  → SUSPECT   (orange)
      malicious = 0       → CLEAN     (vert)
      Not found / absent  → UNKNOWN   (gris)
    """
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
    """
    Relit un Event MISP par son ID — source de vérité, pas le CSV.
    Retourne une liste de dicts : { value, malicious_score, status, badge, link }
    """
    misp = get_misp()
    if misp is None:
        return []

    try:
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
        return results
    except Exception:
        return []


def list_misp_events():
    """Liste tous les Events MISP pour /history, triés par ID décroissant."""
    misp = get_misp()
    if misp is None:
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
        return result
    except Exception:
        return []


# ─────────────────────────────────────────────
# BLOC E — Routes Flask
# ─────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    # Validation
    uploaded = request.files.get("report")
    if not uploaded or uploaded.filename == "":
        flash("Aucun fichier sélectionné.", "error")
        return redirect(url_for("index"))
    if not uploaded.filename.endswith(".txt"):
        flash("Format invalide : seuls les fichiers .txt sont acceptés.", "error")
        return redirect(url_for("index"))

    filename    = uploaded.filename
    report_path = os.path.join(VT_TOOL_DIR, filename)
    uploaded.save(report_path)

    # Lancer vt_tools.py en mode non-interactif
    venv_python = os.path.join(VT_TOOL_DIR, ".venv", "bin", "python")
    if not os.path.exists(venv_python):
        venv_python = "python3"
    vt_script = os.path.join(VT_TOOL_DIR, "vt_tools.py")
    env = os.environ.copy()

    try:
        subprocess.run(
            [venv_python, vt_script, "-n", "-f", report_path],
            cwd=VT_TOOL_DIR, env=env, check=True, timeout=120, capture_output=True,
        )
    except subprocess.TimeoutExpired:
        flash("vt_tools.py a dépassé le délai (120s). Vérifiez votre connexion.", "error")
        return redirect(url_for("index"))
    except subprocess.CalledProcessError as exc:
        flash(f"Erreur vt_tools.py (code {exc.returncode}). Vérifiez votre clé VirusTotal.", "error")
        return redirect(url_for("index"))

    # Parse CSV
    iocs = parse_ip_csv()
    if not iocs:
        flash("Aucune adresse IP extraite. Vérifiez le contenu du fichier.", "error")
        return redirect(url_for("index"))

    # Créer Event MISP
    event_id = create_misp_event(iocs, filename)
    if event_id is None:
        flash("Impossible de créer l'événement MISP. Vérifiez que MISP tourne et que la clé API est correcte.", "error")
        return redirect(url_for("index"))

    # Relire MISP — source de vérité
    results = read_misp_event(event_id)
    if not results:
        flash("Event MISP créé (ID %d) mais impossible de relire les données." % event_id, "error")
        return redirect(url_for("index"))

    # KPI
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
    print(f"[IOC Dashboard] VT_TOOL_DIR : {VT_TOOL_DIR}")
    print(f"[IOC Dashboard] MISP URL    : {MISPURL}")
    print(f"[IOC Dashboard] MISP KEY    : {'OK' if MISPKEY else '⚠ MANQUANTE'}")
    app.run(host="0.0.0.0", port=5000, debug=True)
