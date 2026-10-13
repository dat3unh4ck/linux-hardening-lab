#!/usr/bin/env bash
#
# fase4-firewall.sh — Cortafuegos con nftables y bloqueo de protocolos raros
#
# Hallazgos de Lynis que resuelve:
#   FIRE-4512  (aviso) módulos iptables cargados pero sin reglas activas
#   NETW-3200  x4 — protocolos dccp, sctp, rds y tipc innecesarios
#
# SEGURIDAD — esta fase puede cortarte el acceso. Además de validar y de dejar
# script de reversión, aplica las reglas con un TEMPORIZADOR DE SEGURIDAD:
# si no confirmas en 90 segundos, el sistema restaura solo el estado anterior.
# Así, si las reglas te dejan fuera, no hace falta ni tocar la consola.
#
set -euo pipefail

PUERTO_SSH="${PUERTO_SSH:-2222}"
ESPERA_CONFIRMACION="${ESPERA_CONFIRMACION:-90}"

BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)-firewall"
LOG="/opt/hardening-lab/fase4.log"
REGLAS="/etc/nftables.conf"
RESPALDO_REGLAS="$BACKUP_DIR/nftables-anterior.nft"
REVERTIR="/opt/hardening-lab/revertir-fase4.sh"
UNIDAD_ROLLBACK="nft-rollback"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 4 — Cortafuegos (nftables)"
echo " $(date)"
echo " Puerto SSH a permitir: ${PUERTO_SSH}"
echo "=========================================="

# ---------------------------------------------------------------------------
echo
echo "[1/6] Comprobaciones previas"
# ---------------------------------------------------------------------------

# Que el puerto que vamos a permitir sea REALMENTE el que escucha. Permitir un
# puerto equivocado con política drop es la forma más directa de quedarse fuera.
if ss -tln | grep -qE "[:.]${PUERTO_SSH}\b"; then
  echo "  OK: hay un servicio escuchando en ${PUERTO_SSH}"
else
  echo "  ERROR: nada escucha en el puerto ${PUERTO_SSH}." >&2
  echo "         Abortando: aplicar política drop dejaría el sistema inaccesible." >&2
  ss -tlnp | grep -i ssh || true
  exit 1
fi

# Desde dónde estamos conectados, por si hace falta para diagnóstico.
ORIGEN=$(who am i 2>/dev/null | awk '{print $NF}' | tr -d '()' || true)
echo "  sesión actual desde: ${ORIGEN:-desconocido}"

apt-get install -y -qq nftables >/dev/null
echo "  nftables instalado"

# ---------------------------------------------------------------------------
echo
echo "[2/6] Copia de seguridad del estado actual"
# ---------------------------------------------------------------------------
nft list ruleset > "$RESPALDO_REGLAS" 2>/dev/null || true
[[ -f "$REGLAS" ]] && cp -a "$REGLAS" "$BACKUP_DIR/nftables.conf"
iptables-save > "$BACKUP_DIR/iptables-anterior.rules" 2>/dev/null || true

if [[ -s "$RESPALDO_REGLAS" ]]; then
  echo "  reglas nftables previas guardadas ($(wc -l < "$RESPALDO_REGLAS") líneas)"
else
  echo "  no había reglas nftables previas (coherente con el aviso FIRE-4512)"
fi

# ---------------------------------------------------------------------------
echo
echo "[3/6] Generando el conjunto de reglas"
# ---------------------------------------------------------------------------
cat > "$REGLAS" <<EOF
#!/usr/sbin/nft -f
#
# Conjunto de reglas generado por fase4-firewall.sh — $(date)
#
# Familia 'inet': una sola tabla cubre IPv4 e IPv6. Mantener dos tablas
# separadas es la causa habitual de que IPv6 quede abierto por olvido.

flush ruleset

table inet filter {

    chain input {
        type filter hook input priority filter; policy drop;

        # 1. Tráfico de vuelta de conexiones que hemos iniciado nosotros.
        #    Va primero porque es la mayoría del tráfico: cuanto antes
        #    coincida, menos reglas se evalúan por paquete.
        ct state established,related accept

        # 2. Paquetes en estado inválido: malformados, fuera de secuencia o
        #    propios de escaneos sigilosos (FIN, NULL, Xmas).
        ct state invalid drop

        # 3. Bucle local: imprescindible, muchos servicios hablan por 127.0.0.1.
        iif lo accept

        # 4. Anti-spoofing: nada que llegue por una interfaz real puede decir
        #    legítimamente que viene de localhost.
        iif != lo ip saddr 127.0.0.0/8 drop
        iif != lo ip6 saddr ::1/128 drop

        # 5. ICMP con límite: se permite diagnóstico (ping, traceroute) pero no
        #    inundaciones. Bloquear ICMP entero rompe el descubrimiento de MTU.
        ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded } limit rate 10/second accept

        # 6. ICMPv6: NO es opcional. IPv6 depende de él para el descubrimiento
        #    de vecinos; bloquearlo deja la red IPv6 inutilizable.
        ip6 nexthdr icmpv6 icmpv6 type { echo-request, destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } accept

        # 7. SSH. El límite de tasa frena los ataques automatizados sin estorbar
        #    a una persona. El control real contra fuerza bruta es fail2ban,
        #    que llega en la fase 6; esto solo recorta el ruido.
        tcp dport ${PUERTO_SSH} ct state new limit rate 30/minute burst 10 packets accept

        # 8. Registrar lo descartado, con límite para no inundar el journal.
        #    Sin esto el cortafuegos es una caja negra: no sabrías qué bloquea.
        limit rate 5/minute burst 10 packets log prefix "[nft-drop-input] " level warn
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        # No es un router: nada debe atravesarlo.
    }

    chain output {
        type filter hook output priority filter; policy accept;
        # Salida permitida. Restringirla en un laboratorio rompe apt, DNS y NTP
        # sin aportar gran cosa; en producción sí se acota.
    }
}
EOF

chmod 600 "$REGLAS"
echo "  escrito $REGLAS"

# ---------------------------------------------------------------------------
echo
echo "[4/6] Validando la sintaxis SIN aplicar"
# ---------------------------------------------------------------------------
if nft -c -f "$REGLAS"; then
  echo "  nft -c: sintaxis válida"
else
  echo "  ERROR: el conjunto de reglas tiene errores. No se aplica nada." >&2
  exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "[5/6] Programando el temporizador de seguridad"
# ---------------------------------------------------------------------------
cat > /opt/hardening-lab/nft-rollback.sh <<EOF
#!/usr/bin/env bash
# Restaura el estado de cortafuegos anterior a la fase 4.
nft flush ruleset
if [[ -s "$RESPALDO_REGLAS" ]]; then
  nft -f "$RESPALDO_REGLAS" || true
fi
logger -t hardening-lab "Temporizador de seguridad: reglas nftables revertidas"
EOF
chmod +x /opt/hardening-lab/nft-rollback.sh

systemctl stop "${UNIDAD_ROLLBACK}.timer" 2>/dev/null || true
systemd-run --on-active="${ESPERA_CONFIRMACION}" --unit="$UNIDAD_ROLLBACK" \
  /opt/hardening-lab/nft-rollback.sh >/dev/null 2>&1

echo "  reversión automática programada en ${ESPERA_CONFIRMACION}s"

# ---------------------------------------------------------------------------
echo
echo "[6/6] Aplicando reglas y protocolos"
# ---------------------------------------------------------------------------
nft -f "$REGLAS"
systemctl enable --now nftables >/dev/null 2>&1 || true
echo "  reglas activas"

# NETW-3200: protocolos que ningún servidor normal usa y que han acumulado
# vulnerabilidades. 'install <mod> /bin/true' impide que se carguen bajo
# demanda, que es como se cargarían si alguien crea un socket de ese tipo.
cat > /etc/modprobe.d/blacklist-protocolos-raros.conf <<'EOF'
# NETW-3200 — protocolos de red no utilizados en este servidor.
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF
echo "  protocolos dccp, sctp, rds y tipc bloqueados"

cat > "$REVERTIR" <<EOF
#!/usr/bin/env bash
set -e
systemctl stop ${UNIDAD_ROLLBACK}.timer 2>/dev/null || true
nft flush ruleset
[[ -s "$RESPALDO_REGLAS" ]] && nft -f "$RESPALDO_REGLAS" || true
systemctl disable --now nftables 2>/dev/null || true
rm -f /etc/modprobe.d/blacklist-protocolos-raros.conf
echo "Fase 4 revertida."
EOF
chmod +x "$REVERTIR"

echo
echo "--- reglas activas ---"
nft list ruleset | head -25

echo
echo "=============================================================="
echo " ATENCIÓN: TIENES ${ESPERA_CONFIRMACION} SEGUNDOS"
echo "=============================================================="
cat <<EOF

Las reglas están aplicadas, pero se revertirán SOLAS dentro de
${ESPERA_CONFIRMACION} segundos si no confirmas.

AHORA, desde OTRO terminal del Mac, comprueba que sigues entrando:

    ssh -i ~/.ssh/hardening-lab -p ${PUERTO_SSH} ${SUDO_USER:-usuario}@${ORIGEN:-IP_DE_LA_VM}

Si entras, confirma desde cualquiera de las dos sesiones:

    sudo systemctl stop ${UNIDAD_ROLLBACK}.timer

Si NO entras, no hagas nada: en ${ESPERA_CONFIRMACION} segundos el
cortafuegos se cae solo y recuperas el acceso.

EOF
