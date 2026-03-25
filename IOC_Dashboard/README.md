# IOC Dashboard SOC

Dashboard Flask d'analyse IoC : upload rapport → VirusTotal → MISP → dashboard.

## Lancement

```bash
# 1. Activer le venv de vt_tool
cd ~/vt_tool
source .venv/bin/activate

# 2. Charger les variables d'environnement
export $(grep -v '^#' .env | xargs)

# 3. Ajouter la variable VT_TOOL_DIR
export VT_TOOL_DIR=~/vt_tool

# 4. Installer les dépendances si besoin
pip install flask pymisp

# 5. Lancer le dashboard
cd ~/ioc_dashboard
python app.py
```

Ouvrir : http://localhost:5000

## Stack

- `app.py` — Flask backend (orchestration pipeline)
- `templates/` — Jinja2 (index, results, history)
- `static/style.css` — Dark theme SOC
- MISP source de vérité (jamais les CSV directement)
