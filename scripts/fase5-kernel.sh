#!/usr/bin/env bash
#
# fase5-kernel.sh — Endurecimiento del núcleo, la pila de red y los volcados
#
# Hallazgos de Lynis que resuelve:
#   KRNL-6000  valores de sysctl que difieren del perfil recomendado
#   KRNL-5820  volcados de memoria (core dumps) sin deshabilitar
#   USB-1000   controlador de almacenamiento USB cargado sin necesitarse
#
# Cada parámetro se aplica solo si la clave EXISTE en este núcleo, y después se
# comprueba el valor realmente activo. Escribir en /etc/sysctl.d no garantiza
# que se aplique: un fichero posterior puede pisarlo, o la clave puede no
# existir en esta versión del kernel.
#
set -euo pipefail

BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)-kernel"
LOG="/opt/hardening-lab/fase5.log"
# El prefijo "zz" NO es arbitrario. En sysctl gana el ÚLTIMO fichero aplicado,
# y systemd los ordena alfabéticamente juntando /etc/sysctl.d, /run/sysctl.d y
# /usr/lib/sysctl.d. Ubuntu trae /usr/lib/sysctl.d/99-protect-links.conf, que
# con el nombre "99-hardening.conf" se aplicaba DESPUÉS y pisaba
# fs.protected_fifos. Con "99-zz-" este fichero ordena el último.
#
# Ojo: es la regla CONTRARIA a sshd_config, donde gana el PRIMER valor leído.
SYSCTL_FILE="/etc/sysctl.d/99-zz-hardening.conf"
SYSCTL_FILE_ANTIGUO="/etc/sysctl.d/99-hardening.conf"
REVERTIR="/opt/hardening-lab/revertir-fase5.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 5 — Núcleo, red y volcados"
echo " $(date)"
echo "=========================================="

declare -A PARAMS
declare -a ORDEN

# add <clave> <valor> <motivo>
add() {
  PARAMS["$1"]="$2"
  ORDEN+=("$1")
  COMENTARIO["$1"]="$3"
}
declare -A COMENTARIO

# --- Protección del propio núcleo -----------------------------------------
add kernel.kptr_restrict 2 \
  "Oculta las direcciones del kernel en /proc. Sin esto, un exploit local puede leerlas para saltarse KASLR."
add kernel.dmesg_restrict 1 \
  "Solo root lee el buffer del kernel: dmesg filtra información útil para un atacante local."
add kernel.sysrq 0 \
  "Desactiva la tecla mágica SysRq, que permite acciones privilegiadas desde el teclado físico."
add kernel.yama.ptrace_scope 1 \
  "Un proceso solo puede depurar a sus hijos. Frena el robo de credenciales desde la memoria de otro proceso."
add kernel.randomize_va_space 2 \
  "ASLR completa: aleatoriza pila, montón y bibliotecas en cada ejecución."
add kernel.unprivileged_bpf_disabled 1 \
  "eBPF solo para root. Ha sido origen recurrente de escaladas de privilegios."
add net.core.bpf_jit_harden 2 \
  "Endurece el compilador JIT de eBPF contra ataques de pulverización de JIT."

# --- Sistema de ficheros ---------------------------------------------------
add fs.protected_hardlinks 1 \
  "Impide crear enlaces duros a ficheros sobre los que no se tienen permisos."
add fs.protected_symlinks 1 \
  "Evita el abuso de enlaces simbólicos en directorios compartidos como /tmp."
add fs.protected_fifos 2 \
  "Mitiga ataques por FIFOs colocados en directorios con sticky bit."
add fs.protected_regular 2 \
  "Mismo razonamiento, para ficheros regulares."
add fs.suid_dumpable 0 \
  "KRNL-5820: los binarios SUID nunca vuelcan memoria, que podría contener secretos."

# --- Pila de red -----------------------------------------------------------
add net.ipv4.tcp_syncookies 1 \
  "Defensa frente a inundaciones SYN sin consumir la cola de conexiones."
add net.ipv4.conf.all.rp_filter 1 \
  "Filtrado de ruta inversa: descarta paquetes cuya dirección de origen no concuerda con la ruta."
add net.ipv4.conf.default.rp_filter 1 \
  "Lo mismo para las interfaces que aparezcan después."
add net.ipv4.conf.all.accept_redirects 0 \
  "Ignora redirecciones ICMP: un atacante podría usarlas para desviar tráfico."
add net.ipv4.conf.default.accept_redirects 0 \
  "Idem por defecto."
add net.ipv4.conf.all.secure_redirects 0 \
  "Ni siquiera desde las pasarelas declaradas."
add net.ipv4.conf.all.send_redirects 0 \
  "Esta máquina no es un router: no debe emitir redirecciones."
add net.ipv4.conf.default.send_redirects 0 \
  "Idem por defecto."
add net.ipv4.conf.all.accept_source_route 0 \
  "El enrutado desde el origen permite al emisor elegir la ruta; sirve para eludir controles."
add net.ipv4.conf.default.accept_source_route 0 \
  "Idem por defecto."
add net.ipv4.icmp_echo_ignore_broadcasts 1 \
  "No responde a pings dirigidos a difusión: evita ser amplificador en un ataque smurf."
add net.ipv4.icmp_ignore_bogus_error_responses 1 \
  "No registra respuestas ICMP malformadas, que solo sirven para llenar el log."
add net.ipv4.conf.all.log_martians 1 \
  "Registra paquetes con direcciones imposibles: señal temprana de suplantación."
add net.ipv6.conf.all.accept_redirects 0 \
  "Equivalente IPv6. Olvidar esta mitad es el error más común del endurecimiento de red."
add net.ipv6.conf.default.accept_redirects 0 \
  "Idem por defecto."
add net.ipv6.conf.all.accept_source_route 0 \
  "Equivalente IPv6."
add net.ipv6.conf.all.accept_ra 0 \
  "No acepta anuncios de router: la IP es estática y los RA pueden falsificarse."

# ---------------------------------------------------------------------------
echo
echo "[1/5] Guardando valores actuales"
# ---------------------------------------------------------------------------
[[ -f "$SYSCTL_FILE" ]] && cp -a "$SYSCTL_FILE" "$BACKUP_DIR/"
{
  echo "# Valores previos a la fase 5 — $(date)"
  for clave in "${ORDEN[@]}"; do
    actual=$(sysctl -n "$clave" 2>/dev/null || echo "NO_EXISTE")
    echo "${clave} = ${actual}"
  done
} > "$BACKUP_DIR/sysctl-anterior.txt"
cp -a /etc/security/limits.conf "$BACKUP_DIR/" 2>/dev/null || true
echo "  guardados en $BACKUP_DIR/sysctl-anterior.txt"

# ---------------------------------------------------------------------------
echo
echo "[2/5] Generando $SYSCTL_FILE"
# ---------------------------------------------------------------------------
OMITIDOS=0
{
  echo "# Endurecimiento de núcleo y red — generado por fase5-kernel.sh"
  echo "# $(date)"
  echo "#"
  echo "# Solo se incluyen claves que existen en este núcleo ($(uname -r))."
  echo
  for clave in "${ORDEN[@]}"; do
    if sysctl -n "$clave" >/dev/null 2>&1; then
      echo "# ${COMENTARIO[$clave]}"
      echo "${clave} = ${PARAMS[$clave]}"
      echo
    fi
  done
} > "$SYSCTL_FILE"

for clave in "${ORDEN[@]}"; do
  sysctl -n "$clave" >/dev/null 2>&1 || {
    echo "  omitida (no existe en este núcleo): $clave"
    OMITIDOS=$((OMITIDOS + 1))
  }
done

# Elimina una ejecución anterior que usara el nombre sin "zz", para no dejar
# dos ficheros compitiendo.
if [[ -f "$SYSCTL_FILE_ANTIGUO" ]]; then
  rm -f "$SYSCTL_FILE_ANTIGUO"
  echo "  eliminado $SYSCTL_FILE_ANTIGUO (ordenaba antes que 99-protect-links.conf)"
fi

chmod 644 "$SYSCTL_FILE"
echo "  escrito: $(( ${#ORDEN[@]} - OMITIDOS )) parámetros, $OMITIDOS omitidos"

# ---------------------------------------------------------------------------
echo
echo "[3/5] Aplicando"
# ---------------------------------------------------------------------------
sysctl --system >/dev/null 2>&1
echo "  sysctl --system ejecutado"

# ---------------------------------------------------------------------------
echo
echo "[4/5] Volcados de memoria y almacenamiento USB"
# ---------------------------------------------------------------------------
# KRNL-5820: tres capas, porque cada una la aplica un componente distinto.
if ! grep -qE '^\s*\*\s+hard\s+core\s+0' /etc/security/limits.conf; then
  printf '\n# KRNL-5820 — sin volcados de memoria\n*   hard   core   0\n*   soft   core   0\n' >> /etc/security/limits.conf
  echo "  limits.conf: core 0 (límite por sesión PAM)"
else
  echo "  limits.conf: ya estaba configurado"
fi

mkdir -p /etc/systemd/coredump.conf.d
cat > /etc/systemd/coredump.conf.d/99-hardening.conf <<'EOF'
# KRNL-5820 — systemd-coredump no recoge ni almacena volcados.
[Coredump]
Storage=none
ProcessSizeMax=0
EOF
echo "  systemd-coredump: almacenamiento deshabilitado"

# USB-1000: en un servidor virtualizado no hay almacenamiento USB legítimo, y
# es un vector clásico de exfiltración y de arranque de código no autorizado.
cat > /etc/modprobe.d/blacklist-usb-storage.conf <<'EOF'
# USB-1000 — sin almacenamiento USB en este servidor.
install usb-storage /bin/true
EOF
echo "  usb-storage bloqueado"

systemctl daemon-reload 2>/dev/null || true

# ---------------------------------------------------------------------------
echo
echo "[5/5] Verificación de los valores REALMENTE activos"
# ---------------------------------------------------------------------------
FALLOS=0
for clave in "${ORDEN[@]}"; do
  esperado="${PARAMS[$clave]}"
  real=$(sysctl -n "$clave" 2>/dev/null || echo "NO_EXISTE")
  if [[ "$real" == "NO_EXISTE" ]]; then
    printf '  --    %-45s (no existe en este núcleo)\n' "$clave"
  elif [[ "$real" == "$esperado" ]]; then
    printf '  OK    %-45s %s\n' "$clave" "$real"
  else
    printf '  FALLO %-45s es %s, se esperaba %s\n' "$clave" "$real" "$esperado"
    FALLOS=$((FALLOS + 1))
  fi
done

cat > "$REVERTIR" <<EOF
#!/usr/bin/env bash
set -e
rm -f "$SYSCTL_FILE" "$SYSCTL_FILE_ANTIGUO"
rm -f /etc/systemd/coredump.conf.d/99-hardening.conf
rm -f /etc/modprobe.d/blacklist-usb-storage.conf
cp -a "$BACKUP_DIR/limits.conf" /etc/security/limits.conf 2>/dev/null || true
sysctl --system >/dev/null
systemctl daemon-reload
echo "Fase 5 revertida. Algunos valores de sysctl solo vuelven del todo tras reiniciar."
EOF
chmod +x "$REVERTIR"

echo
echo "=========================================="
if [[ $FALLOS -eq 0 ]]; then
  echo " FASE 5 APLICADA Y VERIFICADA"
else
  echo " FASE 5 APLICADA CON ${FALLOS} FALLO(S) — revisar arriba"
fi
echo " Reversión: sudo ${REVERTIR}"
echo "=========================================="
echo
echo "NOTA: el bloqueo de usb-storage y los volcados surten efecto completo"
echo "tras reiniciar. Los sysctl ya están activos."
