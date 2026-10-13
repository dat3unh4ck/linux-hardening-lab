#!/usr/bin/env bash
#
# fase7-medicion.sh — Auditoría final y comparación con la línea de partida
#
# Repite exactamente la misma auditoría de la fase 1, con la misma versión de
# Lynis, y compara los dos informes. Que la versión sea la misma no es un
# detalle menor: los criterios de puntuación cambian entre versiones, así que
# comparar informes de versiones distintas no mide nada.
#
set -euo pipefail

DIR=/opt/hardening-lab/reports
BASE="$DIR/baseline-report.dat"
FINAL="$DIR/final-report.dat"
RESUMEN="$DIR/comparativa.txt"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

if [[ ! -s "$BASE" ]]; then
  echo "ERROR: no encuentro la línea de partida en $BASE" >&2
  exit 1
fi

mkdir -p "$DIR"

echo "=========================================="
echo " FASE 7 — Medición final"
echo " $(date)"
echo "=========================================="

echo
echo "[1/3] Ejecutando la auditoría (un par de minutos)"
lynis audit system --quick >/dev/null 2>&1 || true
cp /var/log/lynis-report.dat "$FINAL"
cp /var/log/lynis.log "$DIR/final.log" 2>/dev/null || true
chown -R "${SUDO_USER:-root}:${SUDO_USER:-root}" "$DIR" 2>/dev/null || true
echo "  informe guardado en $FINAL"

valor() { grep -E "^$2=" "$1" | head -1 | cut -d= -f2-; }
cuenta() { grep -c "^$2\[\]=" "$1" || true; }

IDX_BASE=$(valor "$BASE" hardening_index)
IDX_FINAL=$(valor "$FINAL" hardening_index)
VER_BASE=$(valor "$BASE" lynis_version)
VER_FINAL=$(valor "$FINAL" lynis_version)
SUG_BASE=$(cuenta "$BASE" suggestion)
SUG_FINAL=$(cuenta "$FINAL" suggestion)
AVI_BASE=$(cuenta "$BASE" warning)
AVI_FINAL=$(cuenta "$FINAL" warning)
TEST_BASE=$(valor "$BASE" tests_executed | tr '|' '\n' | grep -c . || true)
TEST_FINAL=$(valor "$FINAL" tests_executed | tr '|' '\n' | grep -c . || true)

echo
echo "[2/3] Comparando"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
grep '^suggestion\[\]=' "$BASE"  | sed 's/suggestion\[\]=//' | cut -d'|' -f1-2 | sort -u > "$TMP/base.txt"
grep '^suggestion\[\]=' "$FINAL" | sed 's/suggestion\[\]=//' | cut -d'|' -f1-2 | sort -u > "$TMP/final.txt"
comm -23 "$TMP/base.txt" "$TMP/final.txt" > "$TMP/resueltos.txt"
comm -13 "$TMP/base.txt" "$TMP/final.txt" > "$TMP/nuevos.txt"
comm -12 "$TMP/base.txt" "$TMP/final.txt" > "$TMP/pendientes.txt"

{
  echo "=============================================================="
  echo " BASTIONADO DE SERVIDOR UBUNTU — COMPARATIVA"
  echo " Generado: $(date)"
  echo "=============================================================="
  echo
  if [[ "$VER_BASE" != "$VER_FINAL" ]]; then
    echo "  AVISO: versiones de Lynis distintas ($VER_BASE vs $VER_FINAL)."
    echo "  La comparación NO es válida: los criterios cambian entre versiones."
    echo
  fi
  printf '  %-28s %10s %10s %10s\n' "Métrica" "Antes" "Después" "Delta"
  printf '  %-28s %10s %10s %10s\n' "---------------------------" "---------" "---------" "---------"
  printf '  %-28s %10s %10s %+10d\n' "Hardening Index" "$IDX_BASE" "$IDX_FINAL" "$((IDX_FINAL - IDX_BASE))"
  printf '  %-28s %10s %10s %+10d\n' "Sugerencias" "$SUG_BASE" "$SUG_FINAL" "$((SUG_FINAL - SUG_BASE))"
  printf '  %-28s %10s %10s %+10d\n' "Avisos" "$AVI_BASE" "$AVI_FINAL" "$((AVI_FINAL - AVI_BASE))"
  printf '  %-28s %10s %10s %+10d\n' "Pruebas ejecutadas" "$TEST_BASE" "$TEST_FINAL" "$((TEST_FINAL - TEST_BASE))"
  echo
  echo "  Lynis $VER_FINAL  ·  $(valor "$FINAL" os_fullname)  ·  núcleo $(uname -r)"
  echo
  echo "--------------------------------------------------------------"
  echo " RESUELTOS ($(wc -l < "$TMP/resueltos.txt"))"
  echo "--------------------------------------------------------------"
  sed 's/^/  + /' "$TMP/resueltos.txt"
  echo
  echo "--------------------------------------------------------------"
  echo " PENDIENTES ($(wc -l < "$TMP/pendientes.txt"))"
  echo "--------------------------------------------------------------"
  sed 's/^/  - /' "$TMP/pendientes.txt"
  if [[ -s "$TMP/nuevos.txt" ]]; then
    echo
    echo "--------------------------------------------------------------"
    echo " NUEVOS ($(wc -l < "$TMP/nuevos.txt"))"
    echo " Aparecidos tras el bastionado: suelen venir de servicios que"
    echo " antes no existían (auditd, fail2ban) y que traen sus propias"
    echo " recomendaciones."
    echo "--------------------------------------------------------------"
    sed 's/^/  ! /' "$TMP/nuevos.txt"
  fi
  echo
} > "$RESUMEN"

chown "${SUDO_USER:-root}:${SUDO_USER:-root}" "$RESUMEN" 2>/dev/null || true
cat "$RESUMEN"

echo "[3/3] Resumen guardado en $RESUMEN"
echo
echo "Para llevártelo al Mac:"
echo "  scp lab:$RESUMEN ~/hardening-lab/reports/"
echo "  scp lab:$FINAL   ~/hardening-lab/reports/"
