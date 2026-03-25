import os
import sys
import subprocess
import glob
import csv
from pathlib import Path
from datetime import datetime
from dotenv import load_dotenv

from flask import Flask, render_template, request, flash, redirect, url_for
from werkzeug.utils import secure_filename
from pymisp import PyMISP, MISPEvent

def _vt_tool_dir() -> Path:
    # Retourne le dossier frère "vt_tool"
    return (Path(__file__).resolve().parent.parent / "vt_tool").expanduser().resolve()

# Chargement du .env exclusif depuis vt_tool
env_path = _vt_tool_dir() / ".env"
if env_path.is_file():
    load_dotenv(dotenv_path=env_path)

# Configuration App
app = Flask(__name__)
app.config['SECRET_KEY'] = "cti-soc-windows-2026"
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 Mo max

# MISP Client Lazy Init
_misp_client = None

def get_misp_client() -> PyMISP | None:
    global _misp_client
    if _misp_client is not None:
        return _misp_client
        
    misp_url = os.environ.get("MISPURL")
    misp_key = os.environ.get("MISPKEY")
    misp_ssl_str = os.environ.get("MISPSSLVERIFY", "False")
    misp_ssl = misp_ssl_str.lower() in ('true', '1', 't')
    
    proxy = os.environ.get("PROXY")
    proxies = {}
    if proxy:
        proxies = {'http': f"http://{proxy}", 'https': f"http://{proxy}"}
    
    if not misp_url or not misp_key:
        print("MISP mapping missing URL (MISPURL) or KEY (MISPKEY)")
        return None
        
    try:
        if proxies:
            _misp_client = PyMISP(misp_url, misp_key, misp_ssl, debug=False, proxies=proxies)
        else:
            _misp_client = PyMISP(misp_url, misp_key, misp_ssl, debug=False)
        return _misp_client
    except Exception as e:
        print(f"Failed to connect to MISP: {e}")
        return None

# Outils VT
def run_vt_tools(filepath: str) -> bool:
    vt_dir = _vt_tool_dir()
    script = vt_dir / "vt_tools.py"
    
    cmd = [sys.executable, str(script), "-n", str(Path(filepath).resolve())]
    try:
        res = subprocess.run(cmd, cwd=str(vt_dir), capture_output=True, text=True, timeout=600)
        if res.returncode == 0:
            return True
        else:
            print(f"vt_tools error: {res.stderr}")
            return False
    except Exception as e:
        print(f"Exception running vt_tools: {e}")
        return False

# CSV Parsing
def parse_latest_ip_csv() -> list[dict]:
    vt_dir = _vt_tool_dir()
    results_dir = vt_dir / "Results"
    
    if not results_dir.exists():
        return []
        
    csv_files = glob.glob(str(results_dir / "*_IP_Analysis_*.csv"))
    if not csv_files:
        return []
        
    latest_csv = max(csv_files, key=os.path.getmtime)
    
    results = []
    seen_ips = set()
    
    try:
        with open(latest_csv, 'r', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = row.get('ip', '').strip()
                if not ip or ip in seen_ips:
                    continue
                
                seen_ips.add(ip)
                
                try:
                    score = int(row.get('malicious_score', -1))
                except ValueError:
                    score = -1
                    
                try:
                    total = int(row.get('total_scans', 0))
                except ValueError:
                    total = 0
                    
                results.append({
                    'ip': ip,
                    'malicious_score': score,
                    'total_scans': total,
                    'tags': row.get('tags', ''),
                    'link': row.get('link', '')
                })
        return results
    except Exception as e:
        print(f"Error parsing CSV: {e}")
        return []

def compute_score_label(ioc) -> str:
    score = ioc.get('malicious_score', -1)
    total = ioc.get('total_scans', 0)
    
    if score == -1 or total == 0:
        return "0/0"
    return f"{score}/{total}"

def _compute_status(ioc) -> str:
    score = ioc.get('malicious_score', -1)
    
    if score == -1:
        return ('UNKNOWN', 'grey')
    if score > 5:
        return ('MALICIOUS', 'red')
    if score > 0 and score <= 5:
        return ('SUSPECT', 'orange')
    return ('CLEAN', 'green')

# MISP Functions
def create_misp_event(iocs, filename) -> str:
    misp = get_misp_client()
    if not misp:
        return "N/A"
        
    try:
        stem = Path(filename).stem
        date_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        info = f"SOC Report — {stem} — {date_utc}"
        
        event = MISPEvent()
        event.info = info
        event.threat_level_id = 2  # Medium
        event.distribution = 0     # Your organization only
        event.analysis = 1         # Ongoing
        
        for ioc in iocs:
            score_label = compute_score_label(ioc)
            event.add_attribute('ip-dst', ioc['ip'], comment=score_label, to_ids=False)
            
        added_event = misp.add_event(event, pythonify=True)
        return str(added_event.id)
    except Exception as e:
        print(f"Error creating MISP event: {e}")
        return "N/A"

def read_misp_event(event_id) -> list[dict]:
    misp = get_misp_client()
    if not misp:
        return []
        
    try:
        event = misp.get_event(event_id, pythonify=True)
        results = []
        
        import re
        score_pattern = re.compile(r'^(\d+)/(\d+)$')
        
        for attr in event.attributes:
            if attr.type == 'ip-dst':
                ip = attr.value
                comment = attr.comment or ""
                
                score = -1
                total = 0
                match = score_pattern.match(comment)
                if match:
                    score = int(match.group(1))
                    total = int(match.group(2))
                    
                ioc_dict = {
                    'ip': ip,
                    'malicious_score': score,
                    'total_scans': total,
                    'link': f"https://www.virustotal.com/gui/ip-address/{ip}"
                }
                
                status, badge = _compute_status(ioc_dict)
                ioc_dict['score'] = comment if match else "0/0"
                ioc_dict['status'] = status
                ioc_dict['badge'] = badge
                
                results.append(ioc_dict)
                
        return results
    except Exception as e:
        print(f"Error reading MISP event: {e}")
        return []

def get_misp_history(limit=20) -> list[dict]:
    misp = get_misp_client()
    if not misp:
        return []
        
    try:
        events = misp.search(controller='events', limit=limit, pythonify=True)
        events.sort(key=lambda x: int(x.id), reverse=True)
        
        misp_url_base = os.environ.get("MISPURL", "").rstrip('/')
        
        history = []
        for e in events:
            history.append({
                'id': e.id,
                'info': e.info,
                'date': e.date,
                'nb_attributes': getattr(e, 'attribute_count', len(e.attributes) if hasattr(e, 'attributes') else 0),
                'lien_misp': f"{misp_url_base}/events/view/{e.id}"
            })
        return history
    except Exception as e:
        print(f"Error retrieving MISP history: {e}")
        return []

def delete_misp_event(event_id) -> bool:
    misp = get_misp_client()
    if not misp:
        return False
        
    try:
        res = misp.delete_event(event_id)
        print(f"Event {event_id} deleted from MISP.")
        return True
    except Exception as e:
        print(f"Error deleting MISP event {event_id}: {e}")
        return False

# KPI Calculator
def compute_kpi(results) -> dict:
    kpis = {
        'total': len(results),
        'malicious': 0,
        'suspect': 0,
        'clean': 0,
        'unknown': 0
    }
    for r in results:
        status = r.get('status')
        if status == 'MALICIOUS': kpis['malicious'] += 1
        elif status == 'SUSPECT': kpis['suspect'] += 1
        elif status == 'CLEAN': kpis['clean'] += 1
        elif status == 'UNKNOWN': kpis['unknown'] += 1
    return kpis

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        flash("Aucun fichier envoyé", "error")
        return redirect(url_for('index'))
        
    file = request.files['file']
    if file.filename == '':
        flash("Aucun fichier sélectionné", "error")
        return redirect(url_for('index'))
        
    if not file.filename.endswith('.txt'):
        flash("Seuls les fichiers .txt sont acceptés", "error")
        return redirect(url_for('index'))
        
    filename = secure_filename(file.filename)
    vt_dir = _vt_tool_dir()
    os.makedirs(vt_dir, exist_ok=True)
    
    filepath = vt_dir / filename
    try:
        file.save(str(filepath))
    except Exception as e:
        flash(f"Erreur lors de la sauvegarde: {e}", "error")
        return redirect(url_for('index'))
        
    if not run_vt_tools(str(filepath)):
        flash("L'analyse VirusTotal a échoué. Vérifiez vos clés et votre connexion.", "error")
        return redirect(url_for('index'))
        
    csv_data = parse_latest_ip_csv()
    if not csv_data:
        flash("Aucun IoC trouvé ou erreur de lecture du CSV", "warning")
        return redirect(url_for('index'))
        
    send_to_misp = request.form.get('send_to_misp') == 'on'
    
    results = []
    event_info = {'url': None}
    
    if send_to_misp:
        event_id = create_misp_event(csv_data, filename)
        if event_id != "N/A":
            results = read_misp_event(event_id)
            misp_url_base = os.environ.get("MISPURL", "").rstrip('/')
            event_info['url'] = f"{misp_url_base}/events/view/{event_id}"
        else:
            flash("Échec de la connexion ou création dans MISP. Analyse ignorée.", "error")
            return redirect(url_for('index'))
    else:
        for row in csv_data:
            score_lbl = compute_score_label(row)
            status, badge = _compute_status(row)
            results.append({
                'ip': row['ip'],
                'score': score_lbl,
                'status': status,
                'badge': badge,
                'link': row.get('link', '')
            })
            
    kpis = compute_kpi(results)
    
    return render_template(
        'results.html',
        results=results,
        summary=kpis,
        filename=filename,
        event_info=event_info,
        misp_mode=send_to_misp
    )

@app.route('/history')
def history():
    history_events = get_misp_history()
    return render_template('history.html', history=history_events)

@app.route('/delete/<event_id>', methods=['POST'])
def delete_event(event_id):
    if delete_misp_event(event_id):
        flash(f"Événement #{event_id} supprimé avec succès.", "success")
    else:
        flash(f"Erreur lors de la suppression de l'événement #{event_id}.", "error")
    return redirect(url_for('history'))

@app.errorhandler(413)
def request_entity_too_large(error):
    flash("Fichier trop volumineux (max 5 Mo)", "error")
    return redirect(url_for('index'))

@app.errorhandler(404)
def page_not_found(error):
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)
