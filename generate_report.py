#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script de génération de rapport HTML enrichi pour l'audit de sécurité Windows
Inclut des recommandations de remédiation détaillées
"""

import json
import sys
import os
from datetime import datetime
from pathlib import Path

# Configuration de l'encodage pour Windows
if sys.platform == 'win32':
    os.system('')  # Active le support ANSI dans Windows
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')


def load_audit_data(json_file):
    """Charge les données d'audit depuis le fichier JSON"""
    with open(json_file, 'r', encoding='utf-8') as f:
        return json.load(f)


def load_remediation_recommendations():
    """Charge les recommandations de remédiation"""
    remediation_file = Path(__file__).parent / 'remediation_recommendations.json'
    if remediation_file.exists():
        with open(remediation_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}


def get_severity_color(severity):
    """Retourne la couleur associée à un niveau de sévérité"""
    colors = {
        'CRITICAL': '#8b0000',
        'HIGH': '#dc3545',
        'MEDIUM': '#ffc107',
        'LOW': '#17a2b8',
        'INFO': '#6c757d'
    }
    return colors.get(severity, '#6c757d')


def generate_html_report(audit_data, remediation_data, output_file):
    """Génère un rapport HTML enrichi à partir des données d'audit"""
    
    total_tasks = 0
    pass_count = 0
    fail_count = 0
    warning_count = 0
    info_count = 0
    critical_issues = []
    high_issues = []
    
    for host_data in audit_data:
        hostname = host_data.get('host', 'Unknown')
        for task in host_data.get('tasks', []):
            total_tasks += 1
            status = task.get('audit_status', 'INFO')
            task_name = task.get('task', '')
            severity = task.get('severity', '')
            
            if status == 'PASS':
                pass_count += 1
            elif status == 'FAIL':
                fail_count += 1
                if not severity:
                    if task_name in remediation_data:
                        severity = remediation_data[task_name].get('severity', 'MEDIUM')
                
                issue_info = {
                    'host': hostname,
                    'task': task_name,
                    'msg': task.get('msg', ''),
                    'severity': severity
                }
                if severity == 'CRITICAL':
                    critical_issues.append(issue_info)
                elif severity == 'HIGH':
                    high_issues.append(issue_info)
            elif status == 'WARNING':
                warning_count += 1
            else:
                info_count += 1
    
    # Calcul du score de sécurité
    if (pass_count + fail_count) > 0:
        security_score = int((pass_count / (pass_count + fail_count)) * 100)
    else:
        security_score = 0
    
    # Génération du HTML
    html_content = f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rapport d'Audit de Sécurité Windows - Détaillé</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }}
        
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }}
        
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid;
        }}
        
        .summary-card.score {{ border-color: #667eea; }}
        .summary-card.pass {{ border-color: #28a745; }}
        .summary-card.fail {{ border-color: #dc3545; }}
        .summary-card.warning {{ border-color: #ffc107; }}
        .summary-card.info {{ border-color: #17a2b8; }}
        
        .summary-card h3 {{
            font-size: 0.9em;
            color: #6c757d;
            text-transform: uppercase;
            margin-bottom: 10px;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .summary-card.score .value {{ color: #667eea; }}
        .summary-card.pass .value {{ color: #28a745; }}
        .summary-card.fail .value {{ color: #dc3545; }}
        .summary-card.warning .value {{ color: #ffc107; }}
        .summary-card.info .value {{ color: #17a2b8; }}
        
        .critical-alerts {{
            margin: 30px;
            padding: 20px;
            background: #fff5f5;
            border-left: 5px solid #8b0000;
            border-radius: 8px;
        }}
        
        .critical-alerts h2 {{
            color: #8b0000;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .high-alerts {{
            margin: 30px;
            padding: 20px;
            background: #fff8f0;
            border-left: 5px solid #dc3545;
            border-radius: 8px;
        }}
        
        .high-alerts h2 {{
            color: #dc3545;
            margin-bottom: 15px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .alert-item {{
            background: white;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }}
        
        .alert-item strong {{
            color: #343a40;
        }}
        
        .host-section {{
            padding: 30px;
        }}
        
        .host-header {{
            background: #667eea;
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .host-header h2 {{
            font-size: 1.5em;
        }}
        
        .tasks-table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .tasks-table thead {{
            background: #343a40;
            color: white;
        }}
        
        .tasks-table th {{
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }}
        
        .tasks-table td {{
            padding: 12px 15px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .tasks-table tbody tr:hover {{
            background: #f8f9fa;
        }}
        
        .tasks-table tbody tr.expandable {{
            cursor: pointer;
        }}
        
        .tasks-table tbody tr.expandable:hover {{
            background: #e9ecef;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        
        .status-badge.pass {{ background: #d4edda; color: #155724; }}
        .status-badge.fail {{ background: #f8d7da; color: #721c24; }}
        .status-badge.warning {{ background: #fff3cd; color: #856404; }}
        .status-badge.info {{ background: #d1ecf1; color: #0c5460; }}
        
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 3px;
            font-size: 0.75em;
            font-weight: bold;
            text-transform: uppercase;
            color: white;
        }}
        
        .remediation-section {{
            display: none;
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-left: 3px solid #667eea;
            border-radius: 5px;
        }}
        
        .remediation-section.show {{
            display: block;
        }}
        
        .remediation-section h4 {{
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .remediation-section p {{
            margin: 10px 0;
            line-height: 1.6;
        }}
        
        .remediation-section pre {{
            background: #343a40;
            color: #f8f9fa;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            margin: 10px 0;
        }}
        
        .remediation-section code {{
            font-family: 'Courier New', monospace;
        }}
        
        .references {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid #dee2e6;
        }}
        
        .references a {{
            color: #667eea;
            text-decoration: none;
        }}
        
        .references a:hover {{
            text-decoration: underline;
        }}
        
        footer {{
            background: #343a40;
            color: white;
            text-align: center;
            padding: 20px;
            font-size: 0.9em;
        }}
        
        .toggle-icon {{
            float: right;
            color: #667eea;
            font-weight: bold;
        }}
        
        .export-button {{
            position: fixed;
            bottom: 30px;
            right: 30px;
            background: #667eea;
            color: white;
            padding: 15px 25px;
            border-radius: 50px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.3);
            cursor: pointer;
            font-weight: bold;
            border: none;
            font-size: 1em;
            z-index: 1000;
            transition: all 0.3s ease;
        }}
        
        .export-button:hover {{
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(0,0,0,0.4);
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
            .remediation-section {{
                display: block !important;
            }}
            .export-button {{
                display: none;
            }}
        }}
    </style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔒 Rapport d'Audit de Sécurité Windows</h1>
            <p>Rapport détaillé avec recommandations de remédiation</p>
            <p>Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M:%S')}</p>
        </header>
        
        <div class="summary">
            <div class="summary-card score">
                <h3>Score de Sécurité</h3>
                <div class="value">{security_score}%</div>
                <p>{pass_count} / {pass_count + fail_count} conformes</p>
            </div>
            
            <div class="summary-card fail">
                <h3>Problèmes Critiques</h3>
                <div class="value">{len(critical_issues)}</div>
                <p>Action immédiate</p>
            </div>
            
            <div class="summary-card fail">
                <h3>Problèmes Élevés</h3>
                <div class="value">{len(high_issues)}</div>
                <p>Haute priorité</p>
            </div>
            
            <div class="summary-card pass">
                <h3>Réussis</h3>
                <div class="value">{pass_count}</div>
                <p>Conformes</p>
            </div>
            
            <div class="summary-card warning">
                <h3>Avertissements</h3>
                <div class="value">{warning_count}</div>
                <p>À surveiller</p>
            </div>
        </div>
"""
    
    # Section des alertes critiques
    if critical_issues:
        html_content += """
        <div class="critical-alerts">
            <h2>🚨 Problèmes Critiques - Action Immédiate Requise</h2>
"""
        for issue in critical_issues:
            html_content += f"""
            <div class="alert-item">
                <strong>{issue['host']}</strong> - {issue['task']}: {issue['msg']}
            </div>
"""
        html_content += """
        </div>
"""
    
    # Section des alertes haute priorité
    if high_issues:
        html_content += """
        <div class="high-alerts">
            <h2>⚠️ Problèmes de Haute Priorité</h2>
"""
        for issue in high_issues:
            html_content += f"""
            <div class="alert-item">
                <strong>{issue['host']}</strong> - {issue['task']}: {issue['msg']}
            </div>
"""
        html_content += """
        </div>
"""
    
    # Génération des sections pour chaque hôte
    for host_data in audit_data:
        hostname = host_data.get('host', 'Unknown')
        tasks = host_data.get('tasks', [])
        
        html_content += f"""
        <div class="host-section">
            <div class="host-header">
                <h2>🖥️ {hostname}</h2>
            </div>
            
            <table class="tasks-table">
                <thead>
                    <tr>
                        <th style="width: 30%;">Vérification</th>
                        <th style="width: 30%;">Résultat</th>
                        <th style="width: 15%;">Statut</th>
                        <th style="width: 15%;">Sévérité</th>
                        <th style="width: 10%;">Action</th>
                    </tr>
                </thead>
                <tbody>
"""
        
        task_id = 0
        for task in tasks:
            task_name = task.get('task', 'N/A')
            msg = task.get('msg', 'N/A')
            status = task.get('audit_status', 'INFO').lower()
            
            severity = task.get('severity', '')
            mitigation_advice = task.get('mitigation_advice', '')
            mitigation_cmd = task.get('mitigation_cmd', '')
            
            if not severity and task_name in remediation_data:
                remediation_info = remediation_data[task_name]
                severity = remediation_info.get('severity', '')
                if not mitigation_advice:
                    mitigation_advice = remediation_info.get('description', '')
                if not mitigation_cmd:
                    mitigation_cmd = '\n'.join(remediation_info.get('commands', []))
            
            has_remediation = bool(mitigation_advice or mitigation_cmd)
            
            severity_badge = ''
            if severity:
                severity_color = get_severity_color(severity)
                severity_badge = f'<span class="severity-badge" style="background-color: {severity_color};">{severity}</span>'
            
            expand_icon = '📋' if has_remediation else ''
            row_class = 'expandable' if has_remediation else ''
            onclick = f"onclick=\"toggleRemediation('remediation-{task_id}')\"" if has_remediation else ''
            
            html_content += f"""
                    <tr class="{row_class}" {onclick}>
                        <td><strong>{task_name}</strong></td>
                        <td>{msg}</td>
                        <td><span class="status-badge {status}">{status.upper()}</span></td>
                        <td>{severity_badge}</td>
                        <td style="text-align: center;">{expand_icon}</td>
                    </tr>
"""
            
            if has_remediation:
                html_content += f"""
                    <tr>
                        <td colspan="5" style="padding: 0;">
                            <div class="remediation-section" id="remediation-{task_id}">
                                <h4>🛠️ Recommandations de Remédiation</h4>
                                <p><strong>Conseil :</strong> {mitigation_advice}</p>
"""
                
                if mitigation_cmd:
                    html_content += f"""
                                <p><strong>Commandes PowerShell :</strong></p>
                                <pre><code>{mitigation_cmd}</code></pre>
"""
                
                html_content += """
                            </div>
                        </td>
                    </tr>
"""
            
            task_id += 1
        
        html_content += """
                </tbody>
            </table>
        </div>
"""
    
    # Footer et JavaScript
    html_content += f"""
        <footer>
            <p>Rapport généré automatiquement par le système d'audit Ansible</p>
            <p>Machines auditées: {len(audit_data)} | Total vérifications: {total_tasks}</p>
        </footer>
    </div>
    
    <button class="export-button" onclick="exportToPDF()">📄 Exporter en PDF</button>
    
    <script>
        function toggleRemediation(id) {{
            const element = document.getElementById(id);
            if (element) {{
                element.classList.toggle('show');
            }}
        }}
        
        function exportToPDF() {{
            const button = document.querySelector('.export-button');
            button.style.display = 'none';
            
            const opt = {{
                margin: 10,
                filename: 'rapport-audit-securite-{datetime.now().strftime('%Y-%m-%d')}.pdf',
                image: {{ type: 'jpeg', quality: 0.98 }},
                html2canvas: {{ scale: 2 }},
                jsPDF: {{ unit: 'mm', format: 'a4', orientation: 'portrait' }}
            }};
            
            const remediations = document.querySelectorAll('.remediation-section');
            remediations.forEach(r => r.classList.add('show'));
            
            html2pdf().set(opt).from(document.querySelector('.container')).save().then(() => {{
                remediations.forEach(r => r.classList.remove('show'));
                button.style.display = 'block';
            }});
        }}
    </script>
</body>
</html>
"""
    
    # Écriture du fichier HTML
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[OK] Rapport HTML enrichi genere avec succes : {output_file}")
    print(f"[SCORE] Score de securite : {security_score}%")
    print(f"[CRITICAL] Problemes CRITIQUES : {len(critical_issues)}")
    print(f"[HIGH] Problemes ELEVES : {len(high_issues)}")
    print(f"[STATS] PASS: {pass_count} | FAIL: {fail_count} | WARNING: {warning_count}")


def main():
    """Point d'entrée principal du script"""
    
    # Vérifier les arguments
    if len(sys.argv) < 2:
        # Chercher le dernier fichier JSON dans exports/
        exports_dir = Path('exports')
        if not exports_dir.exists():
            print("[ERREUR] Le dossier 'exports' n'existe pas")
            print("Usage: python generate_report_enhanced.py [fichier_json]")
            sys.exit(1)
        
        json_files = list(exports_dir.glob('audit-*.json'))
        if not json_files:
            print("[ERREUR] Aucun fichier JSON trouve dans 'exports/'")
            print("Usage: python generate_report_enhanced.py [fichier_json]")
            sys.exit(1)
        
        # Prendre le fichier le plus récent
        json_file = max(json_files, key=lambda p: p.stat().st_mtime)
        print(f"[INFO] Utilisation du fichier : {json_file}")
    else:
        json_file = Path(sys.argv[1])
        if not json_file.exists():
            print(f"[ERREUR] Le fichier {json_file} n'existe pas")
            sys.exit(1)
    
    # Générer le nom du fichier de sortie
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_file = Path('exports') / f'rapport-audit-detaille-{timestamp}.html'
    
    # Charger les données et générer le rapport
    try:
        audit_data = load_audit_data(json_file)
        remediation_data = load_remediation_recommendations()
        generate_html_report(audit_data, remediation_data, output_file)
        print(f"\n[SUCCES] Rapport genere : {output_file}")
        print(f"[INFO] Ouvrez le fichier dans votre navigateur")
        print(f"[ASTUCE] Cliquez sur les lignes avec l'icone pour voir les recommandations detaillees")
    except Exception as e:
        print(f"[ERREUR] Erreur lors de la generation du rapport : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
