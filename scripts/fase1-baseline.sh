#!/usr/bin/env bash
#
# fase1-baseline.sh — Línea de partida
#
# No endurece nada. Solo mide el sistema tal como está, antes de tocarlo.
#
# POR QUÉ ESTA FASE EXISTE
#   Sin una medición previa no se puede demostrar ninguna mejora, y sobre todo
#   no se puede distinguir entre "esto ya estaba bien" y "esto lo arreglé yo".
#   La línea de partida es lo que convierte el bastionado en algo verificable
#   en vez de en una lista de comandos ejecutados.
#
# LA VERSIÓN DE LYNIS IMPORTA
#   Los criterios de puntuación cambian entre versiones de Lynis. Comparar un
#   informe de la 3.0.9 con otro de la 3.1.x no mide el trabajo hecho: mide la
#   diferencia entre dos baremos. Por eso se instala desde el repositorio de la
#   distribución (versión fija y reproducible) y la fase 7 aborta la comparación
#   si detecta versiones distintas.
#
set -euo pipefail

DIR=/opt/hardening-lab/reports
BASE="$DIR/baseline-report.dat"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$DIR"

echo "=========================================="
echo " FASE 1 — Línea de partida"
echo " $(date)"
echo "=========================================="

if [[ -s "$BASE" ]]; then
  echo
  echo "ATENCIÓN: ya existe una línea de partida en $BASE"
  echo "Si la sobrescribes pierdes la referencia con la que comparar."
  echo "Para rehacerla a propósito, bórrala antes a mano."
  exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "[1/4] Instalando Lynis desde el repositorio de la distribución"
# ---------------------------------------------------------------------------
apt-get update -qq
apt-get install -y -qq lynis
echo "  $(lynis --version 2>/dev/null | head -1)"

# ---------------------------------------------------------------------------
echo
echo "[2/4] Inventario del sistema ANTES de tocar nada"
# ---------------------------------------------------------------------------
# Este inventario vale tanto como el informe de Lynis: documenta el punto de
# partida en lenguaje llano, y sirve para detectar cambios que Lynis no mira.
{
  echo "# Inventario previo al bastionado — $(date)"
  echo
  echo "## Sistema"
  echo "$(lsb_release -ds 2>/dev/null || cat /etc/os-release | grep PRETTY | cut -d'"' -f2)"
  echo "núcleo: $(uname -r)   arquitectura: $(uname -m)"
  echo
  echo "## Puertos a la escucha"
  ss -tlnH | awk '{print "  " $4}' | sort -u
  echo
  echo "## Servicios habilitados al arranque"
  systemctl list-unit-files --state=enabled --type=service --no-legend | awk '{print "  " $1}'
  echo
  echo "## Cuentas con shell interactiva"
  awk -F: '$7 !~ /(nologin|false|sync)$/ {print "  " $1 " -> " $7}' /etc/passwd
  echo
  echo "## Cuentas con UID 0"
  awk -F: '$3 == 0 {print "  " $1}' /etc/passwd
} > "$DIR/inventario-antes.txt"
sed 's/^/  /' "$DIR/inventario-antes.txt"

# ---------------------------------------------------------------------------
echo
echo "[3/4] Auditoría completa (un par de minutos)"
# ---------------------------------------------------------------------------
# --quick evita las pausas interactivas entre secciones. El conjunto de pruebas
# es el mismo; lo que cambia es que no espera a que pulses una tecla.
lynis audit system --quick >/dev/null 2>&1 || true

cp /var/log/lynis-report.dat "$BASE"
cp /var/log/lynis.log "$DIR/baseline.log" 2>/dev/null || true
chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" "$DIR" 2>/dev/null || true
chmod 444 "$BASE"   # solo lectura: esta referencia no se toca más

# ---------------------------------------------------------------------------
echo
echo "[4/4] Resumen de la línea de partida"
# ---------------------------------------------------------------------------
IDX=$(grep -m1 '^hardening_index=' "$BASE" | cut -d= -f2)
SUG=$(grep -c '^suggestion\[\]=' "$BASE" || true)
AVI=$(grep -c '^warning\[\]=' "$BASE" || true)

echo "  Hardening Index : ${IDX}"
echo "  Sugerencias     : ${SUG}"
echo "  Avisos          : ${AVI}"
echo
echo "  Avisos encontrados:"
grep '^warning\[\]=' "$BASE" | sed 's/warning\[\]=//' | cut -d'|' -f1-2 | sed 's/^/    /'

echo
echo "=========================================="
echo " LÍNEA DE PARTIDA GUARDADA"
echo " $BASE (solo lectura)"
echo "=========================================="
echo
echo "A partir de aquí, cada fase se aplica y se verifica por separado."
echo "La fase 7 vuelve a medir y compara contra este fichero."
