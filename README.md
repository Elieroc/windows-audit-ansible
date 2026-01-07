# 🛡️ Audit de Sécurité Windows avec Ansible

Système automatisé d'audit de sécurité pour serveurs Windows, générant des rapports HTML détaillés avec recommandations de remédiation.

## 📋 Prérequis

### Sur la machine de contrôle (Linux)
- Ansible 2.9+
- Python 3.6+
- WinRM configuré pour la communication avec Windows

### Sur les serveurs Windows cibles
- Windows Server 2012 R2+ ou Windows 10+
- WinRM activé et configuré
- Accès administrateur

## 🚀 Installation

1. **Cloner ou copier le projet**
```bash
cd ~/
git clone <repository> windows-audit-ansible-main
cd windows-audit-ansible-main
```

2. **Configurer l'inventaire**
Modifier `inventory.ini` avec vos informations :
```ini
[windows]
ESGI5-server ansible_host=192.168.8.63

[windows:vars]
ansible_user=Administrator
ansible_password=
ansible_connection=winrm
ansible_port=5985
ansible_winrm_transport=ntlm
ansible_winrm_server_cert_validation=ignore
```

3. **Rendre le wrapper exécutable**
```bash
chmod +x wrapper.sh connect.sh
```

## 💻 Utilisation

### Audit complet (recommandé)
```bash
./wrapper.sh
```

Cette commande :
- ✅ Exécute l'audit Ansible complet
- ✅ Génère le rapport HTML détaillé
- ✅ Copie les résultats dans `resultats_audit/`

### Audit en mode verbose (debug)
```bash
./wrapper.sh -v
```

Affiche toutes les tâches Ansible en cours d'exécution (utile pour le troubleshooting).

### Connexion interactive à Windows
```bash
./connect.sh
```

Lance evil-winrm pour une connexion PowerShell interactive.

## 📊 Résultats

Tous les résultats sont générés dans le dossier `resultats_audit/` :

- **`audit-YYYY-MM-DD_HH-MM-SS.json`** : Données brutes de l'audit
- **`rapport-audit-detaille-YYYY-MM-DD_HH-MM-SS.html`** : Rapport HTML complet
- **`audit-YYYY-MM-DD_HH-MM-SS.log`** : Logs d'exécution

### Ouvrir le rapport HTML
```bash
firefox resultats_audit/rapport-audit-detaille-*.html
```

Ou depuis Windows :
```powershell
scp bibi@192.168.8.57:~/windows-audit-ansible-main/resultats_audit/rapport-*.html .
```

## 🔍 Contrôles de Sécurité

Le playbook vérifie plus de 90 paramètres de sécurité répartis en catégories :

### 🔐 Gestion des Comptes
- Statut des comptes Administrator et Guest
- Politique de mots de passe (longueur, complexité, historique, âge)
- Verrouillage de compte
- Membres du groupe Administrateurs local
- Installation et configuration LAPS

### 🌐 Réseau
- Configuration des pare-feu Windows (Domain, Private, Public)
- Services réseau (SMBv1, LLMNR, NetBIOS)
- Partages réseau et permissions
- Protocoles chiffrés (SSL/TLS)

### 🛡️ Sécurité Système
- Windows Update et WSUS
- Windows Defender et antivirus
- User Account Control (UAC)
- BitLocker et chiffrement
- Virtualization Based Security (VBS)
- Credential Guard
- Secure Boot et TPM

### 🔒 Durcissement
- Services inutiles ou dangereux
- Bureau à distance (RDP)
- Autorun et exécution automatique
- Audit de session et logs
- AppLocker / Windows Defender Application Control

### 📦 Inventaire
- Applications installées (avec versions, éditeurs, dates)
- Processus en cours d'exécution
- Services Windows

### 🖥️ Configuration Matérielle
- Protection BIOS/UEFI
- Informations système (OS, CPU, RAM)

## 🎨 Format du Rapport HTML

Le rapport généré contient :
- **Tableau de bord** : Statistiques globales avec graphiques
- **Navigation rapide** : Liens vers chaque section
- **Détails par tâche** : Résultats colorés (✓ Réussi, ✗ Échoué, ⚠ Avertissement)
- **Recommandations** : Conseils de remédiation contextuels
- **Commandes PowerShell** : Scripts prêts à l'emploi pour corriger les problèmes
- **Tableaux interactifs** : Pour les inventaires d'applications

## 📁 Structure du Projet

```
windows-audit-ansible-main/
├── audit.yml                          # Playbook principal
├── inventory.ini                      # Configuration des hôtes
├── wrapper.sh                         # Script d'orchestration
├── generate_report.py                 # Générateur de rapport HTML
├── remediation_recommendations.json   # Base de recommandations
├── ansible.cfg                        # Configuration Ansible
├── connect.sh                         # Connexion interactive evil-winrm
├── callback_plugins/
│   └── concise_json.py               # Plugin Ansible pour export JSON
├── exports/                           # Fichiers JSON générés (temporaires)
└── resultats_audit/                   # Résultats finaux (JSON + HTML + logs)
```

## 🔧 Configuration Avancée

### Désactiver les warnings
Les warnings sont déjà filtrés via `ansible.cfg` et le wrapper.

### Modifier les seuils d'alerte
Éditer `audit.yml` et ajuster les conditions dans les tâches.

### Ajouter de nouvelles vérifications
1. Ajouter une tâche dans `audit.yml`
2. Ajouter la recommandation dans `remediation_recommendations.json`
3. Si nécessaire, modifier `generate_report.py` pour le formatage

## 🐛 Troubleshooting

### L'audit échoue immédiatement
- Vérifier que WinRM est actif sur Windows : `winrm quickconfig`
- Tester la connexion : `./connect.sh`
- Vérifier les credentials dans `inventory.ini`

### Certaines tâches échouent
- Lancer en mode verbose : `./wrapper.sh -v`
- Les tâches avec `ignore_errors: yes` peuvent échouer sans bloquer l'audit

### Le rapport ne s'affiche pas correctement
- Vérifier que Python 3 est installé
- Les données sont dans `resultats_audit/*.json`
- Régénérer le rapport : `python3 generate_report.py`

### Les applications ne sont pas listées
- Vérifier l'accès au registre Windows
- Certaines applications n'utilisent pas Windows Installer

## 📝 Notes Importantes

- **Sécurité** : Les credentials sont en clair dans `inventory.ini`. Protéger ce fichier.
- **Performance** : L'audit complet prend 2-5 minutes selon la machine.
- **Versions** : Testé sur Windows Server 2019/2022 et Windows 10/11.
- **WinRM** : L'audit utilise HTTP (port 5985). Pour HTTPS, modifier `inventory.ini`.

---

**Version** : 1.0  
**Dernière mise à jour** : Janvier 2026


Après exécution, les fichiers suivants sont générés :

- **exports/audit-YYYY-MM-DD_HH-MM-SS.json** : Données brutes de l'audit
- **exports/rapport-audit-detaille-YYYY-MM-DD_HH-MM-SS.html** : Rapport HTML enrichi avec recommandations
- **logs/audit-YYYY-MM-DD_HH-MM-SS.log** : Logs d'exécution détaillés
- **regroupement/** : Copie de tous les fichiers pertinents (si run-full-audit.sh utilisé)

## ToDo
- ✅ Script de génération de rapport HTML enrichi
- ✅ Script d'orchestration complet avec regroupement
- ⏳ Ajouter le reste des tasks d'audit
- ⏳ Créer le playbook de remédiation automatique
