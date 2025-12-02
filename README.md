# Windows Audit Configuration Ansible

## Introduction
Le projet a pour objectif d'automatiser l'audit de configuration de machine Windows en utilisant Ansible pour qu'il puisse facilement etre deploye a grande echelle.
Pour communiquer avec la machine cible, Ansible utilise WinRM.

## Arborescence du projet
```
.
|-- audit.yml : Playbook d'audit Ansible
|-- callback_plugins
|   `-- concise_json.py : Plugin Ansible custom pour generer un export JSON concis
|-- connect.sh : Connexion a la machine windows avec evil-winrm pour tester la connectivite et tester des commandes pour debug
|-- exports
|   `-- audit-2025-12-02_11-25-11.json : Export JSON genere par le plugin custom Ansible
|-- inventory.ini : Inventaire des machines cibles avec les identifiants de connexion
`-- wrapper.sh : Wrapper pour definir des variables et executer ansible-playbook 
```

