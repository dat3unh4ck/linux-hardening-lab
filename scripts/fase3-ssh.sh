#!/usr/bin/env bash
#
# fase3-ssh.sh — Endurecimiento del servicio SSH
#
# Hallazgo de Lynis que resuelve:
#   SSH-7408 x9 — AllowTcpForwarding, ClientAliveCountMax, LogLevel,
#                 MaxAuthTries, MaxSessions, Port, TCPKeepAlive,
#                 X11Forwarding, AllowAgentForwarding
#
# Añade además los controles que Lynis no comprueba pero que son los que de
# verdad importan: sin acceso de root, sin autenticación por contraseña y
# criptografía moderna.
#
# SEGURIDAD — esta fase puede dejarte fuera del sistema. El script:
#   1. Se niega a desactivar la contraseña si no hay ninguna llave autorizada.
#   2. Valida la configuración con 'sshd -t' ANTES de aplicarla.
#   3. Usa 'reload', no 'restart': las sesiones abiertas no se cortan.
#   4. Deja un script de reversión listo.
#
set -euo pipefail

# Puerto de escucha. Ponlo a 22 si prefieres no cambiarlo.
PUERTO_SSH="${PUERTO_SSH:-2222}"

BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)-ssh"
LOG="/opt/hardening-lab/fase3.log"
# El prefijo 00 NO es arbitrario: sshd usa el PRIMER valor que encuentra para
# cada directiva, y lee /etc/ssh/sshd_config.d/*.conf en orden alfabético.
# Ubuntu Server trae 50-cloud-init.conf con "PasswordAuthentication yes", así
# que un fichero 99- se lee DESPUÉS y queda sin efecto. Al revés que en
# sysctl.d, apt.conf.d o los drop-ins de systemd, donde manda el número alto.
DROPIN="/etc/ssh/sshd_config.d/00-hardening.conf"
DROPIN_ANTIGUO="/etc/ssh/sshd_config.d/99-hardening.conf"
SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
REVERTIR="/opt/hardening-lab/revertir-fase3.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 3 — Endurecimiento de SSH"
echo " $(date)"
echo " Puerto destino: ${PUERTO_SSH}"
echo "=========================================="

# ---------------------------------------------------------------------------
echo
echo "[1/6] Comprobaciones previas"
# ---------------------------------------------------------------------------

# ¿Hay alguna llave pública autorizada en alguna cuenta humana?
# Sin esto, desactivar la contraseña es cortarse el acceso.
LLAVES=0
USUARIOS_CON_LLAVE=""
while IFS=: read -r usuario _ uid _ _ home shell; do
  [[ $uid -ge 1000 && $uid -lt 65534 ]] || continue
  [[ "$shell" =~ (nologin|false)$ ]] && continue
  ak="$home/.ssh/authorized_keys"
  if [[ -s "$ak" ]]; then
    n=$(grep -cE '^(ssh-|ecdsa-|sk-)' "$ak" || true)
    if [[ $n -gt 0 ]]; then
      LLAVES=$((LLAVES + n))
      USUARIOS_CON_LLAVE="${USUARIOS_CON_LLAVE}${usuario}(${n}) "
    fi
  fi
done < /etc/passwd

if [[ $LLAVES -gt 0 ]]; then
  echo "  llaves autorizadas encontradas: $LLAVES  -> $USUARIOS_CON_LLAVE"
  DESACTIVAR_PASSWORD=1
else
  echo "  AVISO: no se ha encontrado ninguna llave pública autorizada."
  echo "         NO se desactivará la autenticación por contraseña."
  echo "         Configura una llave con 'ssh-copy-id' y vuelve a ejecutar."
  DESACTIVAR_PASSWORD=0
fi

# ¿La configuración actual es válida? Si ya estaba rota, mejor saberlo ahora.
if sshd -t 2>/dev/null; then
  echo "  configuración sshd actual: válida"
else
  echo "  ERROR: la configuración actual de sshd ya es inválida. Revísala antes." >&2
  sshd -t || true
  exit 1
fi

# Activación por socket: en Ubuntu 24.04 quien escucha el puerto es
# ssh.socket, no sshd. Por eso 'Port' en sshd_config NO cambia nada.
if systemctl is-active --quiet ssh.socket; then
  SOCKET_ACTIVO=1
  echo "  activación por socket: SÍ (el puerto se define en ssh.socket)"
else
  SOCKET_ACTIVO=0
  echo "  activación por socket: no (servicio clásico)"
fi

# ---------------------------------------------------------------------------
echo
echo "[2/6] Copias de seguridad"
# ---------------------------------------------------------------------------
cp -a /etc/ssh/sshd_config "$BACKUP_DIR/sshd_config"
[[ -d /etc/ssh/sshd_config.d ]] && cp -a /etc/ssh/sshd_config.d "$BACKUP_DIR/sshd_config.d"
[[ -d "$SOCKET_DROPIN_DIR" ]] && cp -a "$SOCKET_DROPIN_DIR" "$BACKUP_DIR/ssh.socket.d"
systemctl show ssh.socket -p ListenStream > "$BACKUP_DIR/ssh.socket.listenstream" 2>/dev/null || true
echo "  guardadas en $BACKUP_DIR"

# ---------------------------------------------------------------------------
echo
echo "[3/6] Escribiendo $DROPIN"
# ---------------------------------------------------------------------------
# Se usa un fichero drop-in en sshd_config.d en lugar de editar sshd_config:
# el principal lo puede sustituir una actualización del paquete, y además así
# todo el endurecimiento queda en un único fichero fácil de revisar y revertir.
mkdir -p /etc/ssh/sshd_config.d

{
  echo "# Endurecimiento SSH — generado por fase3-ssh.sh"
  echo "# $(date)"
  echo "# Resuelve SSH-7408 (9 parámetros) y añade los controles de acceso."
  echo
  echo "# --- Hallazgos SSH-7408 de Lynis ---"
  echo "AllowTcpForwarding no        # sin túneles TCP a través de la sesión"
  echo "AllowAgentForwarding no      # sin reenvío del agente de llaves"
  echo "X11Forwarding no             # no hay escritorio que reenviar"
  echo "ClientAliveCountMax 2        # sondas sin respuesta antes de cerrar"
  echo "MaxAuthTries 3               # intentos de autenticación por conexión"
  echo "MaxSessions 2                # sesiones multiplexadas por conexión"
  echo "TCPKeepAlive no              # se prefiere ClientAlive (va cifrado)"
  echo "LogLevel VERBOSE             # registra la huella de la llave usada"
  echo
  echo "# --- Control de acceso ---"
  echo "PermitRootLogin no"
  echo "PermitEmptyPasswords no"
  echo "PubkeyAuthentication yes"
  if [[ $DESACTIVAR_PASSWORD -eq 1 ]]; then
    echo "PasswordAuthentication no"
    echo "KbdInteractiveAuthentication no"
  else
    echo "# PasswordAuthentication no   <-- NO aplicado: no había llaves autorizadas"
  fi
  echo "LoginGraceTime 30            # segundos para completar la autenticación"
  echo "ClientAliveInterval 300      # desconecta sesiones inactivas a los 10 min"
  echo
  echo "# --- Criptografía moderna ---"
  echo "KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512"
  echo "Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com"
  echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com"
  echo "HostKeyAlgorithms ssh-ed25519,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256"
} > "$DROPIN"

chmod 600 "$DROPIN"
echo "  escrito ($(wc -l < "$DROPIN") líneas)"

# Limpia una ejecución anterior que hubiera dejado el fichero con prefijo 99.
if [[ -f "$DROPIN_ANTIGUO" ]]; then
  rm -f "$DROPIN_ANTIGUO"
  echo "  eliminado $DROPIN_ANTIGUO (prefijo incorrecto: se leía después de 50-cloud-init.conf)"
fi

# ---------------------------------------------------------------------------
echo
echo "[4/6] Validando la configuración ANTES de aplicarla"
# ---------------------------------------------------------------------------
if sshd -t; then
  echo "  sshd -t: configuración válida"
else
  echo "  ERROR: configuración inválida. Se revierte y no se aplica nada." >&2
  rm -f "$DROPIN"
  exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "[5/6] Puerto de escucha"
# ---------------------------------------------------------------------------
if [[ "$PUERTO_SSH" == "22" ]]; then
  echo "  se mantiene el 22, no se toca el socket"
elif [[ $SOCKET_ACTIVO -eq 1 ]]; then
  # Con activación por socket el puerto va aquí, no en sshd_config.
  #
  # Dos detalles que cuestan una tarde si no se saben:
  #  1. El 'ListenStream=' vacío limpia la lista heredada. Sin él, el servicio
  #     escucharía en el puerto antiguo Y en el nuevo.
  #  2. Hay que declarar IPv4 e IPv6 por separado. Pasando solo el número de
  #     puerto, systemd enlaza con el comodín IPv6 y delega en la pila dual.
  #     En esta máquina, con net.ipv6.bindv6only=0 (es decir, pila dual
  #     activada), las conexiones IPv4 seguían siendo rechazadas. Declararlas
  #     explícitamente elimina la ambigüedad.
  mkdir -p "$SOCKET_DROPIN_DIR"
  cat > "$SOCKET_DROPIN_DIR/override.conf" <<EOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:${PUERTO_SSH}
ListenStream=[::]:${PUERTO_SSH}
BindIPv6Only=ipv6-only
EOF
  systemctl daemon-reload
  echo "  override de ssh.socket -> puerto ${PUERTO_SSH} (IPv4 + IPv6)"
else
  echo "Port ${PUERTO_SSH}" >> "$DROPIN"
  sshd -t && echo "  Port ${PUERTO_SSH} añadido a $DROPIN"
fi

# ---------------------------------------------------------------------------
echo
echo "[6/6] Aplicando"
# ---------------------------------------------------------------------------
# Script de reversión, por si acaso.
cat > "$REVERTIR" <<EOF
#!/usr/bin/env bash
# Revierte la fase 3 al estado anterior.
set -e
rm -f "$DROPIN"
rm -rf "$SOCKET_DROPIN_DIR"
cp -a "$BACKUP_DIR/sshd_config" /etc/ssh/sshd_config
systemctl daemon-reload
systemctl restart ssh.socket 2>/dev/null || true
systemctl restart ssh
echo "Fase 3 revertida. SSH de nuevo en el puerto 22 con la configuración original."
EOF
chmod +x "$REVERTIR"
echo "  script de reversión: $REVERTIR"

# reload mantiene vivas las sesiones ya establecidas; restart las cortaría.
systemctl reload ssh 2>/dev/null || systemctl restart ssh
if [[ "$PUERTO_SSH" != "22" && $SOCKET_ACTIVO -eq 1 ]]; then
  systemctl restart ssh.socket
fi

echo "  servicio recargado"
echo
echo "--- escuchando en ---"
ss -tlnp 2>/dev/null | grep -E ':(22|'"${PUERTO_SSH}"')\b' || echo "  (revisa con: ss -tlnp | grep ssh)"

# Comprobación explícita de que hay escucha en IPv4: si solo apareciera [::],
# las conexiones IPv4 serían rechazadas y te quedarías fuera al cerrar sesión.
if [[ "$PUERTO_SSH" != "22" ]]; then
  if ss -tln 2>/dev/null | grep -qE "0\.0\.0\.0:${PUERTO_SSH}\b"; then
    echo "  OK: escuchando también en IPv4"
  else
    echo "  FALLO: no hay escucha IPv4 en ${PUERTO_SSH}. Las conexiones IPv4"
    echo "         serán rechazadas. Revierte con: sudo ${REVERTIR}"
  fi
fi

echo
echo "--- configuración EFECTIVA (no la del fichero: la que sshd tiene cargada) ---"
# Escribir una directiva no garantiza que se aplique: si otro fichero de
# sshd_config.d la define antes, gana aquel. 'sshd -T' muestra el valor real
# que usa el demonio, que es lo único que cuenta. Esta comprobación existe
# porque sin ella la fase pasaba por buena con la contraseña aún activa.
EFECTIVA=$(sshd -T 2>/dev/null || true)
FALLOS=0

comprobar() {
  local directiva="$1" esperado="$2"
  local real
  real=$(grep -i "^${directiva} " <<<"$EFECTIVA" | head -1 | cut -d' ' -f2-)
  if [[ "${real,,}" == "${esperado,,}" ]]; then
    printf '  OK    %-28s %s\n' "$directiva" "$real"
  else
    printf '  FALLO %-28s es "%s", se esperaba "%s"\n' "$directiva" "${real:-ausente}" "$esperado"
    FALLOS=$((FALLOS + 1))
  fi
}

comprobar permitrootlogin no
comprobar maxauthtries 3
comprobar maxsessions 2
comprobar x11forwarding no
comprobar allowtcpforwarding no
comprobar allowagentforwarding no
comprobar tcpkeepalive no
comprobar clientalivecountmax 2
comprobar loglevel VERBOSE
comprobar permitemptypasswords no
[[ $DESACTIVAR_PASSWORD -eq 1 ]] && comprobar passwordauthentication no

if [[ $FALLOS -gt 0 ]]; then
  echo
  echo "  !! ${FALLOS} directiva(s) escritas pero NO aplicadas."
  echo "     Causa habitual: otro fichero de /etc/ssh/sshd_config.d/ las define"
  echo "     antes. En sshd gana el PRIMER valor leído, no el último."
  echo "     Comprueba con: sudo grep -rn -i '<directiva>' /etc/ssh/sshd_config.d/"
fi

echo
echo "=========================================="
if [[ $FALLOS -eq 0 ]]; then
  echo " FASE 3 APLICADA Y VERIFICADA"
else
  echo " FASE 3 APLICADA CON ${FALLOS} FALLO(S) — revisar arriba"
fi
echo "=========================================="
cat <<EOF

NO CIERRES ESTA SESIÓN TODAVÍA.

Abre OTRO terminal en el Mac y comprueba que entras:

    ssh -i ~/.ssh/hardening-lab -p ${PUERTO_SSH} $(logname 2>/dev/null || echo usuario)@\$(hostname -I | awk '{print \$1}')

Si entra, ya puedes cerrar esta. Si NO entra, desde esta misma sesión:

    sudo ${REVERTIR}

EOF
if [[ $DESACTIVAR_PASSWORD -eq 0 ]]; then
  echo "RECORDATORIO: la autenticación por contraseña sigue ACTIVA porque no"
  echo "había llaves autorizadas. Configura una y vuelve a ejecutar el script."
fi
