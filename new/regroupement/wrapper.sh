#!/bin/bash

# Wrapper complet : Audit Ansible + Génération Rapport HTML + Regroupement
# Ce script lance tout le processus d'audit en une seule commande

TIMESTAMP=$(date +%Y-%m-%d_%H-%M-%S)

# Déterminer le répertoire du projet
# Si on exécute depuis windows-audit-ansible-main/, PROJECT_DIR est le répertoire courant
# Si on exécute le script dans regroupement/, PROJECT_DIR est le parent
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Si le script est dans regroupement/, alors PROJECT_DIR est le parent
# Sinon, PROJECT_DIR est le répertoire courant
if [[ "$SCRIPT_DIR" == */regroupement ]]; then
    PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
else
    PROJECT_DIR="$SCRIPT_DIR"
fi

REGROUPEMENT_DIR="${PROJECT_DIR}/resultats_audit"
LOG_FILE="${REGROUPEMENT_DIR}/audit-${TIMESTAMP}.log"

mkdir -p "${REGROUPEMENT_DIR}"

echo "=========================================="
echo "  Audit de Sécurité Windows - Complet"
echo "=========================================="
echo "Date: $(date)"
echo "Répertoire du projet: $PROJECT_DIR"
echo "Log: $LOG_FILE"
echo ""

cd "$PROJECT_DIR" || exit 1

# Étape 1 : Audit Ansible
echo "[1/3] Exécution de l'audit Ansible..."
ANSIBLE_CALLBACK_PLUGINS="$PROJECT_DIR/callback_plugins" \
ANSIBLE_STDOUT_CALLBACK=concise_json \
ansible-playbook -i inventory.ini audit.yml "$@" 2>&1 | tee -a "$LOG_FILE"

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "✗ Erreur lors de l'audit Ansible"
    exit 1
fi
echo "✓ Audit terminé"
echo ""

# Étape 2 : Génération du rapport HTML
echo "[2/3] Génération du rapport HTML..."
python3 generate_report.py 2>&1 | tee -a "$LOG_FILE"

if [ ${PIPESTATUS[0]} -ne 0 ]; then
    echo "✗ Erreur lors de la génération du rapport"
    exit 1
fi
echo "✓ Rapport généré"
echo ""

# Étape 3 : Copie dans regroupement
echo "[3/3] Regroupement des résultats..."
LATEST_JSON=$(ls -t exports/audit-*.json 2>/dev/null | head -n1)
LATEST_HTML=$(ls -t exports/rapport-audit-detaille-*.html 2>/dev/null | head -n1)

if [ -n "$LATEST_JSON" ]; then
    cp "$LATEST_JSON" "$REGROUPEMENT_DIR/"
    echo "  Copié: $(basename "$LATEST_JSON")"
fi

if [ -n "$LATEST_HTML" ]; then
    cp "$LATEST_HTML" "$REGROUPEMENT_DIR/"
    echo "  Copié: $(basename "$LATEST_HTML")"
fi

echo ""
echo "=========================================="
echo "  ✓ Audit terminé avec succès !"
echo "=========================================="
echo ""
echo "Résultats disponibles dans : resultats_audit/"

exit 0
