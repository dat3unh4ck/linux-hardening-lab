#!/usr/bin/env bash
#
# fase6-auditoria.sh — Integridad de ficheros, auditoría, registro y defensa activa
#
# Hallazgos de Lynis que resuelve:
#   FINT-4350  sin herramienta de integridad de ficheros      -> AIDE
#   ACCT-9628  sin auditd                                     -> auditd + reglas
#   ACCT-9626  sysstat deshabilitado                          -> sysstat
#   ACCT-9622  contabilidad de procesos desactivada           -> acct
#   DEB-0880   sin fail2ban                                   -> fail2ban
#   BANN-7126  sin banner legal en /etc/issue                 -> banner
#   BANN-7130  sin banner legal en /etc/issue.net             -> banner
#   PKGS-7370  sin debsums                                    -> debsums
#   PKGS-7394  sin apt-show-versions                          -> apt-show-versions
#   DEB-0811   sin apt-listchanges                            -> apt-listchanges
#   HRDN-7230  sin escáner de malware                         -> ClamAV
#
# Sin riesgo para el acceso. La construcción de la base de datos de AIDE tarda
# varios minutos sin mostrar progreso: no está colgado.
#
set -euo pipefail

PUERTO_SSH="${PUERTO_SSH:-2222}"
INSTALAR_CLAMAV="${INSTALAR_CLAMAV:-1}"
CONSTRUIR_AIDE="${CONSTRUIR_AIDE:-1}"

BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)-auditoria"
LOG="/opt/hardening-lab/fase6.log"
REVERTIR="/opt/hardening-lab/revertir-fase6.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1
export DEBIAN_FRONTEND=noninteractive

echo "=========================================="
echo " FASE 6 — Integridad, auditoría y registro"
echo " $(date)"
echo "=========================================="

# ---------------------------------------------------------------------------
echo
echo "[1/7] Banners legales"
# ---------------------------------------------------------------------------
# BANN-7126 / BANN-7130. No son decorativos: en varias jurisdicciones el aviso
# previo es lo que permite perseguir un acceso no autorizado, porque elimina la
# defensa de "no sabía que estaba prohibido". Y deliberadamente NO revelan
# sistema operativo ni versión, que es información útil para un atacante.
BANNER='***************************************************************************
                        ACCESO RESTRINGIDO

Este sistema es de uso exclusivamente autorizado. Toda actividad puede ser
monitorizada y registrada. El acceso o uso no autorizado puede dar lugar a
responsabilidades civiles y penales.

Si no dispone de autorizacion expresa, desconecte ahora.
***************************************************************************
'
cp -a /etc/issue /etc/issue.net "$BACKUP_DIR/" 2>/dev/null || true
printf '%s' "$BANNER" > /etc/issue
printf '%s' "$BANNER" > /etc/issue.net

# Que SSH lo muestre ANTES de autenticar.
if ! grep -qs '^Banner' /etc/ssh/sshd_config.d/00-hardening.conf; then
  echo "Banner /etc/issue.net" >> /etc/ssh/sshd_config.d/00-hardening.conf
fi
sshd -t && systemctl reload ssh
echo "  /etc/issue y /etc/issue.net escritos; SSH los muestra antes del login"

# ---------------------------------------------------------------------------
echo
echo "[2/7] Contabilidad y métricas del sistema"
# ---------------------------------------------------------------------------
apt-get install -y -qq acct sysstat >/dev/null

# ACCT-9626: sysstat viene instalado pero DESACTIVADO en Ubuntu. Instalarlo sin
# habilitarlo no resuelve el hallazgo; hay que tocar su fichero default.
if [[ -f /etc/default/sysstat ]]; then
  cp -a /etc/default/sysstat "$BACKUP_DIR/" 2>/dev/null || true
  sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
fi
systemctl enable --now sysstat >/dev/null 2>&1 || true
systemctl enable --now acct >/dev/null 2>&1 || true
echo "  acct y sysstat instalados y habilitados"

# ---------------------------------------------------------------------------
echo
echo "[3/7] auditd y reglas de auditoría"
# ---------------------------------------------------------------------------
apt-get install -y -qq auditd audispd-plugins >/dev/null

cat > /etc/audit/rules.d/99-hardening.rules <<'EOF'
## Reglas de auditoría — generadas por fase6-auditoria.sh
## Orientadas a lo que un SOC necesita correlacionar: quién tocó las
## credenciales, quién escaló privilegios y quién alteró la propia auditoría.

# Vaciar reglas previas y fijar el tamaño del buffer.
-D
-b 8192
-f 1

## --- Identidades y credenciales ---
-w /etc/passwd -p wa -k identidades
-w /etc/shadow -p wa -k identidades
-w /etc/group -p wa -k identidades
-w /etc/gshadow -p wa -k identidades
-w /etc/sudoers -p wa -k escalada
-w /etc/sudoers.d/ -p wa -k escalada

## --- Autenticación y SSH ---
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
-w /etc/pam.d/ -p wa -k autenticacion

## --- Uso de privilegios ---
-a always,exit -F arch=b64 -S execve -C uid!=euid -F euid=0 -k escalada
-w /usr/bin/sudo -p x -k escalada
-w /var/log/sudo.log -p wa -k escalada

## --- Cambios en la configuración de red y cortafuegos ---
-w /etc/nftables.conf -p wa -k cortafuegos
-w /etc/hosts -p wa -k red
-w /etc/sysctl.d/ -p wa -k red

## --- Carga y descarga de módulos del núcleo ---
-a always,exit -F arch=b64 -S init_module,delete_module,finit_module -k modulos

## --- Montaje de sistemas de ficheros (exfiltración por medios extraíbles) ---
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -k montajes

## --- Protección de la propia auditoría ---
## Debe ir la ÚLTIMA: a partir de aquí las reglas quedan inmutables hasta
## reiniciar. Si un atacante con root intenta desactivar auditd, queda registrado.
-e 2
EOF

augenrules --load >/dev/null 2>&1 || true
systemctl enable --now auditd >/dev/null 2>&1 || true
echo "  auditd activo con $(auditctl -l 2>/dev/null | wc -l) reglas cargadas"

# ---------------------------------------------------------------------------
echo
echo "[4/7] fail2ban"
# ---------------------------------------------------------------------------
apt-get install -y -qq fail2ban >/dev/null

# Detalle crítico de integración: por defecto fail2ban banea con iptables. Como
# el cortafuegos de la fase 4 es nftables, esas reglas irían por un camino
# distinto del que usa este laboratorio. Hay que decirle que use nftables explícitamente.
if [[ -f /etc/fail2ban/action.d/nftables.conf ]]; then
  ACCION='nftables[type=multiport]'
elif [[ -f /etc/fail2ban/action.d/nftables-multiport.conf ]]; then
  ACCION='nftables-multiport'
else
  ACCION='iptables-multiport'
  echo "  AVISO: no se encontró la acción nftables; se usa iptables (revisar)"
fi

cat > /etc/fail2ban/jail.local <<EOF
# Configuración local de fail2ban — fase6-auditoria.sh

[DEFAULT]
# Banea con nftables para integrarse con el cortafuegos de la fase 4.
banaction = ${ACCION}
banaction_allports = ${ACCION}

# Nunca banear la red local del laboratorio ni el propio equipo.
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16 10.0.0.0/8 172.16.0.0/12

bantime  = 1h
findtime = 10m
maxretry = 3

[sshd]
enabled = true
# El puerto NO es el 22: lo cambiamos en la fase 3. Dejar el valor por defecto
# haría que fail2ban vigilase un puerto donde no hay nada.
port     = ${PUERTO_SSH}
# Ubuntu 24.04 registra la autenticación en el journal, no en /var/log/auth.log.
backend  = systemd
maxretry = 3
bantime  = 1h
EOF

systemctl enable --now fail2ban >/dev/null 2>&1 || true
sleep 2
echo "  fail2ban activo, acción de bloqueo: ${ACCION}"

# ---------------------------------------------------------------------------
echo
echo "[5/7] Verificación de paquetes"
# ---------------------------------------------------------------------------
apt-get install -y -qq debsums apt-show-versions apt-listchanges >/dev/null
echo "  debsums, apt-show-versions y apt-listchanges instalados"

# ---------------------------------------------------------------------------
echo
echo "[6/7] Escáner de malware"
# ---------------------------------------------------------------------------
if [[ "$INSTALAR_CLAMAV" == "1" ]]; then
  apt-get install -y -qq clamav >/dev/null
  echo "  ClamAV instalado; descargando firmas en segundo plano"
  systemctl stop clamav-freshclam >/dev/null 2>&1 || true
  (freshclam >/dev/null 2>&1; systemctl start clamav-freshclam >/dev/null 2>&1) &
  echo "  (la descarga son ~300 MB; continúa por su cuenta)"
else
  echo "  omitido (INSTALAR_CLAMAV=0)"
fi

# ---------------------------------------------------------------------------
echo
echo "[7/7] AIDE — integridad de ficheros"
# ---------------------------------------------------------------------------
apt-get install -y -qq aide aide-common >/dev/null
echo "  AIDE instalado"

if [[ "$CONSTRUIR_AIDE" == "1" ]]; then
  echo "  construyendo la base de datos inicial..."
  echo "  ESTO TARDA VARIOS MINUTOS Y NO MUESTRA PROGRESO. No lo interrumpas."
  INICIO=$(date +%s)
  aideinit -y -f >/dev/null 2>&1 || aideinit >/dev/null 2>&1 || true
  if [[ -f /var/lib/aide/aide.db.new ]]; then
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
  fi
  echo "  base de datos lista en $(( ($(date +%s) - INICIO) / 60 )) min $(( ($(date +%s) - INICIO) % 60 ))s"
else
  echo "  construcción omitida (CONSTRUIR_AIDE=0); ejecuta 'sudo aideinit' después"
fi

# ---------------------------------------------------------------------------
echo
echo "=== VERIFICACIÓN ==="
# ---------------------------------------------------------------------------
FALLOS=0
comprobar_servicio() {
  if systemctl is-active --quiet "$1"; then
    printf '  OK    servicio %-20s activo\n' "$1"
  else
    printf '  FALLO servicio %-20s %s\n' "$1" "$(systemctl is-active "$1" 2>&1)"
    FALLOS=$((FALLOS + 1))
  fi
}
comprobar_fichero() {
  if [[ -s "$1" ]]; then
    printf '  OK    %-40s %s bytes\n' "$1" "$(stat -c%s "$1")"
  else
    printf '  FALLO %-40s ausente o vacío\n' "$1"
    FALLOS=$((FALLOS + 1))
  fi
}

comprobar_servicio auditd
comprobar_servicio fail2ban
comprobar_servicio sysstat
comprobar_fichero /etc/issue
comprobar_fichero /etc/issue.net
comprobar_fichero /etc/fail2ban/jail.local
comprobar_fichero /etc/audit/rules.d/99-hardening.rules

echo "  reglas de auditd cargadas: $(auditctl -l 2>/dev/null | wc -l)"
echo "  jaulas de fail2ban: $(fail2ban-client status 2>/dev/null | grep -i 'jail list' | cut -d: -f2 | xargs || echo '?')"
if [[ -f /var/lib/aide/aide.db ]]; then
  echo "  base de datos AIDE: $(stat -c%s /var/lib/aide/aide.db) bytes"
else
  echo "  AIDE: base de datos aún no construida"
fi

cat > "$REVERTIR" <<EOF
#!/usr/bin/env bash
set -e
systemctl disable --now fail2ban auditd sysstat acct 2>/dev/null || true
rm -f /etc/fail2ban/jail.local /etc/audit/rules.d/99-hardening.rules
cp -a "$BACKUP_DIR/issue" /etc/issue 2>/dev/null || true
cp -a "$BACKUP_DIR/issue.net" /etc/issue.net 2>/dev/null || true
sed -i '/^Banner /d' /etc/ssh/sshd_config.d/00-hardening.conf 2>/dev/null || true
systemctl reload ssh 2>/dev/null || true
echo "Fase 6 revertida (los paquetes instalados se conservan)."
EOF
chmod +x "$REVERTIR"

echo
echo "=========================================="
if [[ $FALLOS -eq 0 ]]; then
  echo " FASE 6 APLICADA Y VERIFICADA"
else
  echo " FASE 6 APLICADA CON ${FALLOS} FALLO(S)"
fi
echo " Reversión: sudo ${REVERTIR}"
echo "=========================================="
