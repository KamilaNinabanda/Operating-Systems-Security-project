#!/usr/bin/env bash
# UNINSTALL FORM Ubuntu, Debian y Kali Linux.
# HOW TO:
# chmod +x uninstall_sentinel_falco.sh
#sudo ./uninstall_sentinel_falco.sh
#-------------------------
#   sudo bash uninstall_sentinel_falco.sh
#   sudo bash uninstall_sentinel_falco.sh --purge-data
#   sudo bash uninstall_sentinel_falco.sh --remove-falco
#   sudo bash uninstall_sentinel_falco.sh --purge-data --remove-falco

set -Eeuo pipefail
umask 077

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

INSTALL_DIR="/opt/Sentinel_Falco"
DATA_DIR="/var/lib/Sentinel_Falco"
ENV_FILE="/etc/falco-guard.env"
GUARD_SERVICE="/etc/systemd/system/falco-guard.service"
FALCO_CONFIG="/etc/falco/config.d/configfalco.yaml"
FALCO_RULES="/etc/falco/rules.d/rules_detection_falco.yaml"
FALCO_REPO="/etc/apt/sources.list.d/falcosecurity.list"
FALCO_KEY="/etc/apt/keyrings/verify_repo_install.gpg"

PURGE_DATA=false
REMOVE_FALCO=false

usage() {
  cat <<'EOF'
Desinstalador de Sentinel_Falco

Opciones:
  --purge-data     Elimina también /var/lib/Sentinel_Falco (alertas, estado y evidencias AUDIT).
                   Sin esta opción, los datos se conservan.
  --remove-falco   Desinstala el paquete Falco y elimina el repositorio y la clave
                   agregados por el instalador de Sentinel_Falco.
  -h, --help       Muestra esta ayuda.

Docker NO se desinstala.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --purge-data) PURGE_DATA=true ;;
    --remove-falco) REMOVE_FALCO=true ;;
    -h|--help) usage; exit 0 ;;
    *) echo -e "${RED}Opción desconocida: $1${NC}" >&2; usage; exit 1 ;;
  esac
  shift
done

if [[ "$EUID" -ne 0 ]]; then
  echo -e "${RED}Ejecuta el desinstalador con sudo.${NC}" >&2
  echo "Ejemplo: sudo bash uninstall_sentinel_falco.sh"
  exit 1
fi

echo -e "${BLUE}Desinstalador de Sentinel_Falco${NC}"
echo
echo "Se eliminarán los componentes de Sentinel_Falco:"
echo " - Servicio falco-guard y su archivo de servicio"
echo " - Programa y configuración en /opt/Sentinel_Falco"
echo " - Configuración específica y reglas instaladas en /etc/falco"
echo " - Variables y token en /etc/falco-guard.env"
if $PURGE_DATA; then
  echo -e "${RED} - También se eliminarán los datos y evidencias de $DATA_DIR${NC}"
else
  echo -e "${GREEN} - Los datos y evidencias de $DATA_DIR se conservarán${NC}"
fi
if $REMOVE_FALCO; then
  echo -e "${YELLOW} - También se desinstalará el paquete Falco y se quitará su repositorio${NC}"
else
  echo " - Falco se conservará instalado"
fi
echo " - Docker se conservará instalado"
echo

read -r -p "¿Deseas continuar? Escribe SI para confirmar: " answer
if [[ "$answer" != "SI" ]]; then
  echo "Desinstalación cancelada."
  exit 0
fi

echo
echo "[1/6] Deteniendo y deshabilitando servicios..."
for service in falco-guard.service falco-modern-bpf.service falco-kmod.service falco-bpf.service; do
  if systemctl list-unit-files "$service" --no-legend 2>/dev/null | grep -q .; then
    systemctl disable --now "$service" 2>/dev/null || true
  else
    systemctl stop "$service" 2>/dev/null || true
  fi
done

echo "[2/6] Eliminando el servicio de Sentinel_Falco..."
rm -f "$GUARD_SERVICE"
systemctl daemon-reload
systemctl reset-failed falco-guard.service 2>/dev/null || true

echo "[3/6] Eliminando el programa y sus configuraciones..."
rm -rf "$INSTALL_DIR"
rm -f "$FALCO_CONFIG" "$FALCO_RULES" "$ENV_FILE"

# Eliminar directorios solo si quedaron vacíos; no borrar configuraciones ajenas.
rmdir /etc/falco/config.d 2>/dev/null || true
rmdir /etc/falco/rules.d 2>/dev/null || true

echo "[4/6] Gestionando datos y evidencias..."
if $PURGE_DATA; then
  rm -rf "$DATA_DIR"
  echo "Datos y evidencias eliminados."
else
  echo "Datos conservados en: $DATA_DIR"
fi

echo "[5/6] Gestionando Falco..."
if $REMOVE_FALCO; then
  if command -v apt-get >/dev/null 2>&1; then
    apt-get remove -y falco || {
      echo -e "${YELLOW}No se pudo desinstalar Falco automáticamente. Revisa el gestor de paquetes.${NC}"
    }
    rm -f "$FALCO_REPO" "$FALCO_KEY"
    apt-get update
  fi
else
  echo "Falco se mantiene instalado."
fi

echo "[6/6] Verificación..."
if systemctl is-active --quiet falco-guard.service 2>/dev/null; then
  echo -e "${RED}Advertencia: falco-guard todavía aparece activo.${NC}"
else
  echo -e "${GREEN}Servicio falco-guard detenido.${NC}"
fi

echo
echo -e "${GREEN}Desinstalación de Sentinel_Falco finalizada.${NC}"
echo "Docker no fue modificado."
if ! $PURGE_DATA && [[ -d "$DATA_DIR" ]]; then
  echo "Recuerda que los datos y evidencias siguen en: $DATA_DIR"
fi
if ! $REMOVE_FALCO; then
  echo "Falco permanece instalado. Para quitarlo posteriormente:"
  echo "  sudo apt-get remove falco"
fi
