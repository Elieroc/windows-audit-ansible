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


def get_enhanced_section(task_name, task_data):
    """Retourne un contenu HTML enrichi pour certaines tâches"""
    enhanced = {}
    
    # Section WinRM enrichie
    if 'WinRM' in task_name:
        enhanced['title'] = '🔐 Configuration WinRM - Authentification et Chiffrement'
        enhanced['details'] = '''
        <div style="background: #f0f9ff; padding: 12px; border-radius: 4px; margin: 8px 0;">
            <strong>Modes d'authentification disponibles :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li><code>Basic</code> - ❌ À éviter (identifiants en clair)</li>
                <li><code>Certificate</code> - ✓ Recommandé</li>
                <li><code>Negotiate (NTLM et Kerberos)</code> - ✓ Recommandé</li>
                <li><code>Kerberos</code> - ✓ Recommandé</li>
                <li><code>CredSSP</code> - ⚠️ À configurer avec prudence</li>
            </ul>
            <strong>Clés de registre critiques :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li><code>HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowBasic</code> = 0</li>
                <li><code>HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Service\\AllowUnencryptedTraffic</code> = 0</li>
                <li><code>HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowBasic</code> = 0</li>
                <li><code>HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\WinRM\\Client\\AllowUnencryptedTraffic</code> = 0</li>
            </ul>
        </div>'''
    
    # Section SMB enrichie
    elif 'SMB' in task_name and ('signing' in task_name.lower() or 'client' in task_name.lower()):
        enhanced['title'] = '🔒 Configuration SMB - Signatures et Sécurité'
        enhanced['details'] = '''
        <div style="background: #fef3c7; padding: 12px; border-radius: 4px; margin: 8px 0;">
            <strong>Paramètres de signature SMB (Serveur) :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li><code>HKLM:\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters</code>
                    <ul><li><code>RequireSecuritySignature = 1</code> ✓ (Signature obligatoire)</li>
                        <li><code>EnableSecuritySignature = 1</code> ✓ (Signature activée)</li></ul>
                </li>
            </ul>
            <strong>Paramètres de signature SMB (Client) :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li><code>HKLM:\\System\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters</code>
                    <ul><li><code>RequireSecuritySignature = 1</code> ✓ (Signature obligatoire)</li>
                        <li><code>EnableSecuritySignature = 1</code> ✓ (Signature activée)</li></ul>
                </li>
            </ul>
            <strong>Paramètres NTLM (Relais NTLM) :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li><code>HKLM:\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RestrictNullSessAccess = 1</code></li>
                <li><code>HKLM:\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\NullSessionPipes</code> = (vide)</li>
            </ul>
        </div>'''
    
    # Section BIOS enrichie
    elif 'BIOS' in task_name or 'UEFI' in task_name:
        enhanced['title'] = '🖥️ Sécurité Physique - Protection BIOS/UEFI'
        enhanced['details'] = '''
        <div style="background: #fee2e2; padding: 12px; border-radius: 4px; margin: 8px 0;">
            <strong>Points de contrôle BIOS/UEFI :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li>✓ <strong>Mot de passe administrateur BIOS</strong> - Activé et complexe</li>
                <li>✓ <strong>Mot de passe utilisateur BIOS</strong> - Activé (optionnel mais recommandé)</li>
                <li>✓ <strong>Secure Boot</strong> - Activé (UEFI)</li>
                <li>✓ <strong>TPM (Trusted Platform Module)</strong> - Activé et initialisé</li>
                <li>✓ <strong>Virtualization / VT-x / AMD-V</strong> - Activé si utilisé (Hyper-V, etc.)</li>
                <li>✓ <strong>Ordre de démarrage</strong> - Correctement configuré (disque dur en premier)</li>
                <li>⚠️ <strong>USB Boot</strong> - Désactiver si non utilisé</li>
                <li>⚠️ <strong>Legacy Boot / CSM</strong> - Désactiver si UEFI supporté</li>
            </ul>
            <strong>Vérification manuelle requise :</strong>
            <ul style="margin: 8px 0; padding-left: 20px;">
                <li>Redémarrer et entrer au BIOS (Delete, F2, F12 selon le fabricant)</li>
                <li>Vérifier que le mot de passe administrateur est bien défini</li>
                <li>Confirmer les paramètres de sécurité (Secure Boot, TPM, VT-x)</li>
            </ul>
        </div>'''
    
    return enhanced


def categorize_task(task_name):
    """Catégorise les tâches d'audit par domaine de sécurité"""
    categories = {
        'Comptes et identités': ['Administrator account', 'Guest account', 'LAPS', 'Local Admin', 'Local Admin Group'],
        'Politiques de mots de passe': ['Password minimum length', 'LMHASH', 'NoLMHash'],
        'Contrôle d\'accès': ['UAC', 'RDP SecurityLayer', 'RDP NLA', 'RDP Encryption Level'],
        'SMB et protocoles réseau': ['SMBv1', 'SMB signing', 'SMB Client Signing', 'NetBIOS', 'LLMNR', 'IPv6', 'SMB Share', 'NTFS Permissions'],
        'Administration à distance': ['WinRM Hardening'],
        'Protection mémoire': ['LSASS RunAsPPL', 'WDigest'],
        'Protection antimalware': ['Defender RealTime Protection', 'AppLocker Rules', 'ASR Rules', 'Controlled Folder Access', 'Antivirus', 'EDR'],
        'Sécurité physique': ['USB AutoRun', 'BitLocker', 'BIOS', 'UEFI'],
        'Journalisation et audit': ['Audit logon/logoff', 'Security log size', 'Sysmon service', 'PowerShell Script Block Logging', 'Windows Event Forwarding', 'WEF'],
        'Services et pare-feu': ['Service', 'Firewall profile', 'dangerous services', 'Service Registry', 'Permissions', 'Startup Services'],
        'Authentification avancée': ['Windows Hello', 'Windows Hello for Business', 'MFA', 'Just Enough Administration', 'JEA'],
        'Contrôle des scripts': ['PowerShell Language Mode'],
        'Gestion des sessions': ['Cached Logons Count'],
        'Mise à jour et sécurité': ['WSUS', 'Virtualization Based Security', 'Device Guard', 'Credential Guard', 'VBS', 'Smart App Control', 'Windows Update'],
        'Gestion des applications': ['Installed Software', 'Software Inventory', 'vulnerable', 'Running Processes', 'Processus', 'Applications détaillées'],
        'Sysmon et monitoring': ['Sysmon']
    }
    
    for category, keywords in categories.items():
        for keyword in keywords:
            if keyword.lower() in task_name.lower():
                return category
    return 'Autres vérifications'


def generate_html_report(audit_data, remediation_data, output_file):
    """Génère un rapport HTML enrichi à partir des données d'audit"""
    
    total_tasks = 0
    pass_count = 0
    fail_count = 0
    warning_count = 0
    info_count = 0
    critical_issues = []
    high_issues = []
    categorized_tasks = {}
    
    for host_data in audit_data:
        hostname = host_data.get('host', 'Unknown')
        for task in host_data.get('tasks', []):
            total_tasks += 1
            status = task.get('audit_status', 'INFO')
            task_name = task.get('task', '')
            severity = task.get('severity', '')
            category = categorize_task(task_name)
            
            if category not in categorized_tasks:
                categorized_tasks[category] = {'pass': 0, 'fail': 0, 'warning': 0, 'info': 0}
            
            if status == 'PASS':
                pass_count += 1
                categorized_tasks[category]['pass'] += 1
            elif status == 'FAIL':
                fail_count += 1
                categorized_tasks[category]['fail'] += 1
                if not severity:
                    if task_name in remediation_data:
                        severity = remediation_data[task_name].get('severity', 'MEDIUM')
                
                issue_info = {
                    'host': hostname,
                    'task': task_name,
                    'msg': task.get('msg', ''),
                    'severity': severity,
                    'category': category
                }
                if severity == 'CRITICAL':
                    critical_issues.append(issue_info)
                elif severity == 'HIGH':
                    high_issues.append(issue_info)
            elif status == 'WARNING':
                warning_count += 1
                categorized_tasks[category]['warning'] += 1
            else:
                info_count += 1
                categorized_tasks[category]['info'] += 1
    
    # Calcul du score de sécurité
    if (pass_count + fail_count) > 0:
        security_score = int((pass_count / (pass_count + fail_count)) * 100)
    else:
        security_score = 0
    
    # Génération du CSS
    css_styles = """
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap');
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: #f5f7fa;
            padding: 20px;
            min-height: 100vh;
            color: #2c3e50;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.08);
        }
        
        header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 50px 40px;
            position: relative;
            overflow: hidden;
        }
        
        header::before {
            content: '';
            position: absolute;
            top: -50%;
            right: -10%;
            width: 500px;
            height: 500px;
            background: rgba(255,255,255,0.05);
            border-radius: 50%;
        }
        
        .header-content {
            position: relative;
            z-index: 1;
            display: flex;
            align-items: center;
            gap: 30px;
            justify-content: space-between;
        }
        
        .logo {
            display: none;
        }
        
        .logo img {
            display: none;
        }
        
        .btn-export-pdf {
            background: #10b981;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 1em;
            cursor: pointer;
            font-weight: 600;
            transition: all 0.3s;
        }
        
        .btn-export-pdf:hover {
            background: #059669;
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(16,185,129,0.3);
        }
        
        .header-text h1 {
            font-size: 2.2em;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        
        .header-text p {
            font-size: 1em;
            opacity: 0.95;
            font-weight: 300;
        }
        
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8fafc;
            border-bottom: 1px solid #e2e8f0;
        }
        
        .summary-card {
            background: white;
            padding: 24px;
            border-radius: 12px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            text-align: center;
            border-left: 4px solid;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        
        .summary-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0,0,0,0.12);
        }
        
        .summary-card.score { border-color: #3b82f6; }
        .summary-card.pass { border-color: #10b981; }
        .summary-card.fail { border-color: #ef4444; }
        .summary-card.warning { border-color: #f59e0b; }
        .summary-card.info { border-color: #6366f1; }
        
        .summary-card h3 {
            font-size: 0.75em;
            color: #64748b;
            text-transform: uppercase;
            margin-bottom: 12px;
            font-weight: 600;
            letter-spacing: 0.5px;
        }
        
        .summary-card .value {
            font-size: 2.5em;
            font-weight: 700;
            margin-bottom: 4px;
            line-height: 1;
        }
        
        .summary-card.score .value { color: #3b82f6; }
        .summary-card.pass .value { color: #10b981; }
        .summary-card.fail .value { color: #ef4444; }
        .summary-card.warning .value { color: #f59e0b; }
        .summary-card.info .value { color: #6366f1; }
        
        .critical-alerts {
            margin: 30px 40px;
            padding: 24px;
            background: #fef2f2;
            border-left: 4px solid #dc2626;
            border-radius: 8px;
        }
        
        .critical-alerts h2 {
            color: #dc2626;
            margin-bottom: 16px;
            font-size: 1.3em;
            font-weight: 600;
        }
        
        .high-alerts {
            margin: 30px 40px;
            padding: 24px;
            background: #fff7ed;
            border-left: 4px solid #f97316;
            border-radius: 8px;
        }
        
        .high-alerts h2 {
            color: #f97316;
            margin-bottom: 16px;
            font-size: 1.3em;
            font-weight: 600;
        }
        
        .alert-item {
            background: white;
            padding: 16px;
            margin: 12px 0;
            border-radius: 6px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
            font-size: 0.95em;
        }
        
        .alert-item strong {
            color: #1e293b;
            font-weight: 600;
        }
        
        .host-section {
            padding: 40px;
        }
        
        .host-header {
            background: linear-gradient(135deg, #1e3a8a 0%, #3b82f6 100%);
            color: white;
            padding: 20px 28px;
            border-radius: 8px;
            margin-bottom: 24px;
        }
        
        .host-header h2 {
            font-size: 1.4em;
            font-weight: 600;
        }
        
        .category-section {
            margin-bottom: 30px;
            padding: 20px;
            background: #f8fafc;
            border-left: 4px solid #10b981;
            border-radius: 6px;
        }
        
        .category-section h3 {
            color: #1e293b;
            margin-bottom: 12px;
            font-size: 1.2em;
        }
        
        .task-item {
            margin-bottom: 16px;
            padding: 12px;
            background: white;
            border-left: 4px solid #10b981;
            border-radius: 4px;
        }
        
        .task-item.fail {
            border-left-color: #ef4444;
        }
        
        .task-item.warning {
            border-left-color: #f59e0b;
        }
        
        .severity-badge {
            padding: 6px 14px;
            border-radius: 6px;
            font-size: 0.7em;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            white-space: nowrap;
            display: inline-block;
            margin-top: 8px;
        }
        
        .severity-critical { background: #7f1d1d; color: white; }
        .severity-high { background: #c2410c; color: white; }
        .severity-medium { background: #f59e0b; color: white; }
        .severity-low { background: #65a30d; color: white; }
        .severity-info { background: #3b82f6; color: white; }
        
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.85em;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            display: inline-block;
            margin-left: 10px;
            border: 1px solid;
        }
        
        .status-pass { background: #d1fae5; color: #065f46; border-color: #10b981; }
        .status-fail { background: #fee2e2; color: #991b1b; border-color: #ef4444; }
        .status-warning { background: #fed7aa; color: #92400e; border-color: #f59e0b; }
        .status-info { background: #dbeafe; color: #1e40af; border-color: #3b82f6; }
        
        .remediation-info {
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #e2e8f0;
            background: #f0f9ff;
            padding: 12px;
            border-radius: 4px;
            color: #0c4a6e;
            font-size: 0.9em;
        }
        
        .command-block {
            background: #0c4a6e;
            color: #e0f2fe;
            padding: 12px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            overflow-x: auto;
            margin-top: 8px;
            margin-bottom: 8px;
        }
        
        .summary-dashboard {
            padding: 40px;
            background: #f8fafc;
        }
        
        .dashboard-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 20px;
        }
        
        .dashboard-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid;
            box-shadow: 0 1px 3px rgba(0,0,0,0.08);
        }
        
        .dashboard-card h3 {
            color: #1e293b;
            margin-bottom: 12px;
            font-size: 1.1em;
        }
        
        .dashboard-card .stats {
            display: flex;
            justify-content: space-between;
            margin-bottom: 12px;
            font-size: 0.9em;
        }
        
        .dashboard-card .stats span {
            font-weight: 600;
        }
        
        .progress-bar {
            background: #f1f5f9;
            border-radius: 4px;
            overflow: hidden;
            height: 8px;
        }
        
        .progress-fill {
            background: #10b981;
            height: 100%;
        }
        
        @media print {
            body { background: white; padding: 0; margin: 0; }
            .container { box-shadow: none; }
            .btn-export-pdf { display: none; }
        }
    """
    
    # En-tête HTML
    html_content = '<!DOCTYPE html>\n<html lang="fr">\n<head>\n'
    html_content += '<meta charset="UTF-8">\n'
    html_content += '<meta name="viewport" content="width=device-width, initial-scale=1.0">\n'
    html_content += '<title>Rapport d\'Audit de Sécurité Windows</title>\n'
    html_content += '<style>' + css_styles + '</style>\n'
    html_content += '<script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>\n'
    html_content += '</head>\n<body>\n'
    html_content += '<div class="container">\n'
    
    # Header
    timestamp = datetime.now().strftime('%d/%m/%Y à %H:%M:%S')
    html_content += '<header>\n<div class="header-content">\n'
    html_content += '<div class="header-text">\n'
    html_content += '<h1>Rapport d\'Audit de Sécurité Windows</h1>\n'
    html_content += '<p>Analyse détaillée de la conformité et des vulnérabilités - ' + timestamp + '</p>\n'
    html_content += '</div>\n'
    html_content += '<button class="btn-export-pdf" onclick="exportPDF()">📄 Rapport PDF</button>\n'
    html_content += '</div>\n</header>\n'
    
    # Summary cards
    html_content += '<div class="summary">\n'
    html_content += '<div class="summary-card score">\n<h3>Score de Sécurité</h3>\n'
    html_content += '<div class="value">' + str(security_score) + '%</div>\n'
    html_content += '<p>' + str(pass_count) + ' / ' + str(pass_count + fail_count) + ' conformes</p>\n</div>\n'
    
    html_content += '<div class="summary-card fail">\n<h3>Problèmes Critiques</h3>\n'
    html_content += '<div class="value">' + str(len(critical_issues)) + '</div>\n'
    html_content += '<p>Action immédiate</p>\n</div>\n'
    
    html_content += '<div class="summary-card fail">\n<h3>Problèmes Élevés</h3>\n'
    html_content += '<div class="value">' + str(len(high_issues)) + '</div>\n'
    html_content += '<p>Haute priorité</p>\n</div>\n'
    
    html_content += '<div class="summary-card pass">\n<h3>Réussis</h3>\n'
    html_content += '<div class="value">' + str(pass_count) + '</div>\n'
    html_content += '<p>Conformes</p>\n</div>\n'
    
    html_content += '<div class="summary-card warning">\n<h3>Avertissements</h3>\n'
    html_content += '<div class="value">' + str(warning_count) + '</div>\n'
    html_content += '<p>À surveiller</p>\n</div>\n'
    html_content += '</div>\n'
    
    # Alertes critiques
    if critical_issues:
        html_content += '<div class="critical-alerts">\n'
        html_content += '<h2>🚨 Problèmes Critiques - Action Immédiate Requise</h2>\n'
        for issue in critical_issues:
            html_content += '<div class="alert-item"><strong>' + issue['host'] + '</strong> - ' + issue['task'] + ': ' + issue['msg'] + '</div>\n'
        html_content += '</div>\n'
    
    # Alertes haute priorité
    if high_issues:
        html_content += '<div class="high-alerts">\n'
        html_content += '<h2>⚠️ Problèmes de Haute Priorité</h2>\n'
        for issue in high_issues:
            html_content += '<div class="alert-item"><strong>' + issue['host'] + '</strong> - ' + issue['task'] + ': ' + issue['msg'] + '</div>\n'
        html_content += '</div>\n'
    
    # Dashboard par catégorie
    html_content += '<div class="summary-dashboard">\n'
    html_content += '<h2 style="margin-bottom: 30px; color: #1e293b;">📊 Résumé par Domaine de Sécurité</h2>\n'
    html_content += '<div class="dashboard-grid">\n'
    
    sorted_categories = sorted(categorized_tasks.items(), key=lambda x: (x[1]['fail'], -x[1]['pass']), reverse=True)
    
    for category, stats in sorted_categories:
        total_cat = stats['pass'] + stats['fail'] + stats['warning'] + stats['info']
        pass_pct = int((stats['pass'] / total_cat * 100)) if total_cat > 0 else 0
        
        if stats['fail'] > 0:
            border_color = '#ef4444'
        elif stats['warning'] > 0:
            border_color = '#f59e0b'
        else:
            border_color = '#10b981'
        
        html_content += '<div class="dashboard-card" style="border-left-color: ' + border_color + ';">\n'
        html_content += '<h3>' + category + '</h3>\n'
        html_content += '<div class="stats">\n'
        html_content += '<span style="color: #10b981;">✓ ' + str(stats['pass']) + ' réussi(s)</span>\n'
        html_content += '<span style="color: #ef4444;">✗ ' + str(stats['fail']) + ' échoué(s)</span>\n'
        html_content += '</div>\n'
        html_content += '<div class="progress-bar">\n'
        html_content += '<div class="progress-fill" style="width: ' + str(pass_pct) + '%;"></div>\n'
        html_content += '</div>\n'
        html_content += '<p style="margin-top: 10px; color: #64748b; font-size: 0.85em;">' + str(pass_pct) + '% conforme</p>\n'
        html_content += '</div>\n'
    
    html_content += '</div>\n</div>\n'
    
    # Sections par hôte
    for host_data in audit_data:
        hostname = host_data.get('host', 'Unknown')
        tasks = host_data.get('tasks', [])
        
        html_content += '<div class="host-section">\n'
        html_content += '<div class="host-header"><h2>💻 ' + hostname + '</h2></div>\n'
        
        # Grouper par catégorie
        tasks_by_category = {}
        for task in tasks:
            task_name = task.get('task', 'N/A')
            category = categorize_task(task_name)
            if category not in tasks_by_category:
                tasks_by_category[category] = []
            tasks_by_category[category].append(task)
        
        # Afficher chaque catégorie
        for category in sorted(tasks_by_category.keys()):
            category_tasks = tasks_by_category[category]
            failed = sum(1 for t in category_tasks if t.get('audit_status', '').lower() == 'fail')
            passed = sum(1 for t in category_tasks if t.get('audit_status', '').lower() == 'pass')
            warned = sum(1 for t in category_tasks if t.get('audit_status', '').lower() == 'warning')
            
            cat_color = '#10b981' if failed == 0 else '#ef4444'
            status_icon = '✓' if failed == 0 else '✗'
            status_text = status_icon + ' ' + str(passed) + ' réussi(s) | ' + str(failed) + ' échoué(s) | ' + str(warned) + ' avertissement(s)'
            
            html_content += '<div class="category-section" style="border-left-color: ' + cat_color + ';">\n'
            html_content += '<h3>📁 ' + category + '</h3>\n'
            html_content += '<div style="color: #64748b; margin-bottom: 16px; font-size: 0.95em;">' + status_text + '</div>\n'
            
            for task in category_tasks:
                task_name = task.get('task', 'N/A')
                msg = task.get('msg', 'N/A')
                status = task.get('audit_status', 'INFO').lower()
                severity = task.get('severity', '')
                mitigation_advice = task.get('mitigation_advice', '')
                mitigation_cmd = task.get('mitigation_cmd', '')
                
                skip_tasks = ['Record dangerous services', 'Record firewall profiles']
                if task_name not in skip_tasks:
                    remediation_info = remediation_data.get(task_name, {})
                    
                    if not severity and remediation_info:
                        severity = remediation_info.get('severity', '')
                    
                    if not mitigation_advice and remediation_info:
                        mitigation_advice = remediation_info.get('description', '')
                        if not mitigation_advice:
                            mitigation_advice = remediation_info.get('remediation', '')
                    
                    if not mitigation_cmd and remediation_info:
                        commands = remediation_info.get('commands', [])
                        if commands:
                            mitigation_cmd = '\n'.join(commands)
                
                # Couleur du statut
                if status == 'pass':
                    task_color = '#10b981'
                    status_class = 'status-pass'
                    status_label = 'CONFORME'
                elif status == 'fail':
                    task_color = '#ef4444'
                    status_class = 'status-fail'
                    status_label = 'NON-CONFORME'
                elif status == 'warning':
                    task_color = '#f59e0b'
                    status_class = 'status-warning'
                    status_label = 'ATTENTION'
                else:
                    task_color = '#6366f1'
                    status_class = 'status-info'
                    status_label = 'INFO'
                
                html_content += '<div class="task-item" style="border-left-color: ' + task_color + ';">\n'
                html_content += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">\n'
                html_content += '<span style="color: #1e293b; font-weight: 600;">' + task_name + '</span>\n'
                html_content += '<span class="' + status_class + '">' + status_label + '</span>\n'
                html_content += '</div>\n'
                
                if severity:
                    sev_lower = severity.lower()
                    html_content += '<span class="severity-badge severity-' + sev_lower + '">' + severity + '</span>\n'
                
                if msg and msg != 'N/A':
                    html_content += '<div style="color: #64748b; font-size: 0.9em; margin: 8px 0;"><strong>Détail :</strong> ' + msg + '</div>\n'
                
                # Ajouter les sections enrichies
                enhanced = get_enhanced_section(task_name, task)
                if enhanced:
                    html_content += '<div style="margin: 12px 0; padding: 12px; background: #f8fafc; border-radius: 4px;">\n'
                    if 'title' in enhanced:
                        html_content += '<strong style="color: #1e293b;">' + enhanced['title'] + '</strong>\n'
                    if 'details' in enhanced:
                        html_content += enhanced['details']
                    html_content += '</div>\n'
                
                if mitigation_advice or mitigation_cmd:
                    html_content += '<div class="remediation-info">\n'
                    
                    if mitigation_advice:
                        html_content += '<div style="margin-bottom: 12px;"><strong>📋 Recommandation :</strong><br>' + mitigation_advice + '</div>\n'
                    
                    if mitigation_cmd:
                        html_content += '<div class="command-block"><strong>💻 Commande :</strong><br>' + mitigation_cmd.replace('<', '&lt;').replace('>', '&gt;') + '</div>\n'
                    
                    html_content += '</div>\n'
                
                html_content += '</div>\n'
            
            html_content += '</div>\n'
        
        html_content += '</div>\n'
    
    # Footer
    html_content += '</div>\n'
    html_content += '<script>\n'
    html_content += 'function exportPDF() {\n'
    html_content += '    const element = document.querySelector(".container");\n'
    html_content += '    const opt = {\n'
    html_content += '        margin: 10,\n'
    html_content += '        filename: "rapport-audit-' + datetime.now().strftime('%Y-%m-%d') + '.pdf",\n'
    html_content += '        image: { type: "jpeg", quality: 0.98 },\n'
    html_content += '        html2canvas: { scale: 2 },\n'
    html_content += '        jsPDF: { orientation: "portrait", unit: "mm", format: "a4" }\n'
    html_content += '    };\n'
    html_content += '    if (typeof html2pdf !== "undefined") {\n'
    html_content += '        html2pdf().set(opt).from(element).save();\n'
    html_content += '    } else {\n'
    html_content += '        alert("Utilisez Ctrl+P pour imprimer en PDF");\n'
    html_content += '    }\n'
    html_content += '}\n'
    html_content += '</script>\n'
    html_content += '</body>\n</html>\n'
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    print(f"[OK] Rapport HTML genere avec succes : {output_file}")
    print(f"[SCORE] Score de securite : {security_score}%")
    print(f"[CRITICAL] Problemes CRITIQUES : {len(critical_issues)}")
    print(f"[HIGH] Problemes ELEVES : {len(high_issues)}")
    print(f"[STATS] PASS: {pass_count} | FAIL: {fail_count} | WARNING: {warning_count}")


def main():
    """Point d'entrée principal du script"""
    
    if len(sys.argv) < 2:
        exports_dir = Path('exports')
        if not exports_dir.exists():
            print("[ERREUR] Le dossier 'exports' n'existe pas")
            print("Usage: python generate_report.py [fichier_json]")
            sys.exit(1)
        
        json_files = list(exports_dir.glob('audit-*.json'))
        if not json_files:
            print("[ERREUR] Aucun fichier JSON trouve dans 'exports/'")
            print("Usage: python generate_report.py [fichier_json]")
            sys.exit(1)
        
        json_file = max(json_files, key=lambda p: p.stat().st_mtime)
        print(f"[INFO] Utilisation du fichier : {json_file}")
    else:
        json_file = Path(sys.argv[1])
        if not json_file.exists():
            print(f"[ERREUR] Le fichier {json_file} n'existe pas")
            sys.exit(1)
    
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
    output_file = Path('exports') / f'rapport-audit-detaille-{timestamp}.html'
    
    try:
        audit_data = load_audit_data(json_file)
        remediation_data = load_remediation_recommendations()
        generate_html_report(audit_data, remediation_data, output_file)
        print(f"\n[SUCCES] Rapport genere : {output_file}")
        print(f"[INFO] Ouvrez le fichier dans votre navigateur")
    except Exception as e:
        print(f"[ERREUR] Erreur lors de la generation du rapport : {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
