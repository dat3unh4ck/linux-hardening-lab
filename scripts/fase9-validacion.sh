#!/usr/bin/env bash
#
# fase9-validacion.sh — Validación: resiliencia bajo carga y vista perimetral
#
# Las fases 1 a 8 comprueban el sistema DESDE DENTRO. Esta hace las dos
# preguntas que esa mirada no puede responder:
#
#   1. ¿El endurecimiento ha degradado la estabilidad?
#      Limitar el núcleo, prohibir los volcados de memoria y poner topes en
#      limits.conf tiene un coste. Si bajo carga real el sistema se vuelve
#      inestable, mata procesos o pierde eventos de auditoría, el bastionado
#      ha cambiado un riesgo por otro. Hay que provocarlo para saberlo.
#
#   2. ¿Lo que se ve desde fuera coincide con lo que creemos tener?
#      'ss -tln' dice en qué puertos escucha el sistema. No dice cuáles son
#      alcanzables: eso lo decide el cortafuegos. La única forma de saberlo es
#      mirar desde otra máquina. Este script deja preparada esa comparación.
#
# El escaneo perimetral NO se ejecuta aquí a propósito: un nmap contra uno
# mismo atraviesa el bucle local y no prueba nada. El script genera el comando
# exacto para lanzarlo desde el Mac y guarda la vista interna para contrastar.
#
# Uso:   sudo bash fase9-validacion.sh
#        sudo DURACION=120 bash fase9-validacion.sh
#        sudo SALTAR_ESTRES=1 bash fase9-validacion.sh    # solo el perímetro
#
set -euo pipefail

DURACION="${DURACION:-60}"
SALTAR_ESTRES="${SALTAR_ESTRES:-0}"
DIR=/opt/hardening-lab/reports
LOG=/opt/hardening-lab/fase9.log

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 9 — Validación bajo carga y perímetro"
echo " $(date)"
echo "=========================================="

SERVICIOS=(ssh nftables auditd fail2ban)

estado_servicios() {
  for s in "${SERVICIOS[@]}"; do
    printf '%s=%s ' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo desconocido)"
  done
  echo
}

# ---------------------------------------------------------------------------
echo
echo "[1/5] Estado ANTES de la prueba"
# ---------------------------------------------------------------------------
NUCLEOS=$(nproc)
MEM_DISP_KB=$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)
MEM_DISP_MB=$((MEM_DISP_KB / 1024))

echo "  núcleos: ${NUCLEOS}   memoria disponible: ${MEM_DISP_MB} MB"
echo "  carga:   $(cut -d' ' -f1-3 /proc/loadavg)"
echo -n "  servicios: "; estado_servicios
REGLAS_ANTES=$(nft list ruleset 2>/dev/null | grep -c . || echo 0)
echo "  reglas nftables: ${REGLAS_ANTES}"

ss -tlnH | awk '{print $4}' | sort -u > "$DIR/puertos-internos.txt"
echo "  puertos a la escucha (vista interna):"
sed 's/^/     /' "$DIR/puertos-internos.txt"

# Marca temporal para acotar después la lectura del anillo del núcleo.
MARCA=$(date +%s)

# ---------------------------------------------------------------------------
echo
echo "[2/5] Prueba de resiliencia"
# ---------------------------------------------------------------------------
if [[ "$SALTAR_ESTRES" == "1" ]]; then
  echo "  omitida (SALTAR_ESTRES=1)"
else
  apt-get install -y -qq stress-ng >/dev/null 2>&1 || true
  if ! command -v stress-ng >/dev/null 2>&1; then
    echo "  stress-ng no disponible; se omite la prueba de carga."
    SALTAR_ESTRES=1
  else
    # Dimensionado prudente: dos trabajadores de memoria que entre los dos
    # usan como mucho la mitad de la memoria DISPONIBLE. Pedir 1 GB fijo en
    # una VM pequeña no mide resiliencia: invoca al OOM killer y lo único que
    # demuestra es que la máquina tenía poca RAM.
    POR_TRABAJADOR_MB=$((MEM_DISP_MB / 4))
    [[ $POR_TRABAJADOR_MB -lt 64 ]] && POR_TRABAJADOR_MB=64
    echo "  stress-ng: ${NUCLEOS} CPU + 2 x ${POR_TRABAJADOR_MB}MB durante ${DURACION}s"
    echo "  (la sesión SSH debe seguir respondiendo todo el tiempo)"
    echo

    stress-ng --cpu "$NUCLEOS" --vm 2 --vm-bytes "${POR_TRABAJADOR_MB}M" \
              --timeout "${DURACION}s" --metrics-brief >"$DIR/stress-ng.txt" 2>&1 &
    PID_ESTRES=$!

    # ---------------------------------------------------------------------
    echo "[3/5] Estado DURANTE la carga"
    # ---------------------------------------------------------------------
    # Comprobar al final no vale: si un servicio se cae y systemd lo reinicia,
    # al terminar estará "active" y no te enteras. Hay que mirar mientras pasa.
    CAIDAS=0
    MUESTRAS=0
    MAX_CARGA=0
    while kill -0 "$PID_ESTRES" 2>/dev/null; do
      sleep 5
      MUESTRAS=$((MUESTRAS + 1))
      CARGA=$(cut -d' ' -f1 /proc/loadavg)
      [[ $(echo "$CARGA $MAX_CARGA" | awk '{print ($1>$2)}') == 1 ]] && MAX_CARGA=$CARGA

      FALLANDO=""
      for s in "${SERVICIOS[@]}"; do
        if systemctl list-unit-files "${s}.service" >/dev/null 2>&1; then
          systemctl is-active --quiet "$s" || FALLANDO="${FALLANDO}${s} "
        fi
      done
      # El cortafuegos también puede vaciarse: sería el peor fallo posible.
      REGLAS_AHORA=$(nft list ruleset 2>/dev/null | grep -c . || echo 0)
      [[ "$REGLAS_AHORA" -lt "$REGLAS_ANTES" ]] && FALLANDO="${FALLANDO}nftables-reglas "

      if [[ -n "$FALLANDO" ]]; then
        printf '  t+%-3ss  carga %-6s  CAIDO: %s\n' "$((MUESTRAS * 5))" "$CARGA" "$FALLANDO"
        CAIDAS=$((CAIDAS + 1))
      else
        printf '  t+%-3ss  carga %-6s  todo en pie\n' "$((MUESTRAS * 5))" "$CARGA"
      fi
    done
    wait "$PID_ESTRES" 2>/dev/null || true
    echo "  carga máxima alcanzada: ${MAX_CARGA}"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "[4/5] Estado DESPUÉS y rastro en el núcleo"
# ---------------------------------------------------------------------------
echo -n "  servicios: "; estado_servicios
REGLAS_DESPUES=$(nft list ruleset 2>/dev/null | grep -c . || echo 0)
echo "  reglas nftables: ${REGLAS_ANTES} -> ${REGLAS_DESPUES}"

# El anillo del núcleo es donde aparecen el OOM killer, los oops y los
# pánicos. Si el endurecimiento rompe algo bajo presión, se ve aquí.
INCIDENTES=$(dmesg --since "@${MARCA}" 2>/dev/null \
             | grep -icE 'oom-killer|Out of memory|Call Trace|BUG:|general protection|kernel panic' \
             || true)
if [[ "${INCIDENTES:-0}" -gt 0 ]]; then
  echo "  ATENCIÓN: ${INCIDENTES} línea(s) de incidente en el núcleo durante la prueba:"
  dmesg --since "@${MARCA}" 2>/dev/null \
    | grep -iE 'oom-killer|Out of memory|Call Trace|BUG:|general protection|kernel panic' \
    | head -8 | sed 's/^/     /'
else
  echo "  núcleo: sin OOM, sin oops, sin pánicos durante la prueba"
fi

# auditd bajo presión: si pierde eventos, la trazabilidad de la fase 6 es
# aparente, no real. Es justo el tipo de fallo que solo asoma con carga.
if command -v auditctl >/dev/null 2>&1; then
  PERDIDOS=$(auditctl -s 2>/dev/null | awk '/^lost/{print $2}')
  echo "  auditd: ${PERDIDOS:-?} eventos perdidos"
fi

# ---------------------------------------------------------------------------
echo
echo "[5/5] Vista interna frente a vista externa"
# ---------------------------------------------------------------------------
IP=$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | head -1)
PUERTO_SSH=$(ss -tlnH | awk '{print $4}' | grep -oE '[0-9]+$' | sort -un | grep -vE '^(53|25)$' | head -1)

cat <<EOF

  Desde dentro, este sistema escucha en:
$(sed 's/^/     /' "$DIR/puertos-internos.txt")

  Eso NO dice qué es alcanzable: lo decide el cortafuegos. Para comprobarlo
  hace falta mirar desde otra máquina. Desde el Mac:

     nmap -Pn -p- -T4 --reason ${IP:-IP_DE_LA_VM} | tee ~/hardening-lab/reports/nmap-externo.txt

  -Pn  no descarta el objetivo si no responde al ping: nuestras reglas limitan
       ICMP, así que sin esto nmap podría darlo por caído y no escanear nada.
  -p-  los 65535 puertos. Escanear solo los 1000 habituales no demuestra que
       el resto esté cerrado, que es justo lo que queremos demostrar.
  --reason  dice POR QUÉ considera cerrado cada puerto. No es lo mismo un
       'reset' (nadie escucha, pero el paquete llegó) que 'no-response' (el
       cortafuegos lo descartó en silencio). Con política drop esperamos lo
       segundo en todo salvo en ${PUERTO_SSH:-el puerto de SSH}.

  Resultado esperado: un único puerto abierto, ${PUERTO_SSH:-2222}/tcp.
  Cualquier otro puerto abierto desde fuera es un hallazgo.
EOF

echo
echo "=========================================="
if [[ "${CAIDAS:-0}" -eq 0 && "${INCIDENTES:-0}" -eq 0 ]]; then
  echo " FASE 9 — RESILIENCIA OK"
  echo " Ningún servicio cayó y el núcleo no registró incidentes."
else
  echo " FASE 9 — REVISAR"
  echo " caídas de servicio: ${CAIDAS:-0}   incidentes de núcleo: ${INCIDENTES:-0}"
fi
echo " Falta el escaneo externo desde el Mac (comando arriba)."
echo "=========================================="
