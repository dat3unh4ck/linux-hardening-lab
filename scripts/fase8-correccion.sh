#!/usr/bin/env bash
#
# fase8-correccion.sh — Corrige las regresiones que introdujo el propio bastionado
#
# Hallazgos que resuelve:
#   MAIL-8818  (aviso) el banner SMTP revela sistema operativo y software
#   MAIL-8820  el comando VRFY permite enumerar cuentas locales
#   FINT-4402  AIDE podría no estar usando SHA256/SHA512
#
# ---------------------------------------------------------------------------
# POR QUÉ EXISTE ESTA FASE
# ---------------------------------------------------------------------------
# La fase 6 instaló AIDE con:
#
#     apt-get install -y -qq aide aide-common
#
# aide-common RECOMIENDA un agente de correo, porque envía su informe diario
# por email. APT instala las recomendaciones por defecto, así que entró
# Postfix como dependencia automática:
#
#     Install: ... aide-common, bsd-mailx (automatic), postfix (automatic)
#
# Y quedó habilitado al arranque, con inet_interfaces=all, escuchando en
# 0.0.0.0:25 y [::]:25 — todas las interfaces, IPv4 e IPv6.
#
# Es decir: instalar una herramienta de seguridad ABRIÓ un servicio de red
# que nadie pidió. El cortafuegos de la fase 4 (política drop, solo 2222) es
# lo único que impidió que quedara expuesto a la red. Defensa en profundidad
# funcionando como debe, pero el servicio no tiene por qué estar ahí.
#
# LECCIÓN: después de bastionar hay que volver a inventariar los puertos a la
# escucha. Las herramientas de seguridad también traen dependencias.
#
# ---------------------------------------------------------------------------
# DOS MODOS
# ---------------------------------------------------------------------------
#   MODO=restringir  (por defecto)
#       Deja Postfix solo en loopback, le quita el banner identificativo y
#       desactiva VRFY. El correo local sigue funcionando, así que el informe
#       diario de AIDE llega al buzón de root y se lee con `mail`.
#
#   MODO=eliminar
#       Desinstala Postfix y bsd-mailx. AIDE sigue auditando y escribiendo en
#       /var/log/aide/, simplemente no envía correo. Menos superficie, menos
#       funcionalidad.
#
# Uso:   sudo ./fase8-correccion.sh
#        sudo MODO=eliminar ./fase8-correccion.sh
#
set -euo pipefail

MODO="${MODO:-restringir}"
BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)-correccion"
LOG="/opt/hardening-lab/fase8.log"
REVERTIR="/opt/hardening-lab/revertir-fase8.sh"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

if [[ "$MODO" != "restringir" && "$MODO" != "eliminar" ]]; then
  echo "ERROR: MODO debe ser 'restringir' o 'eliminar' (recibido: $MODO)." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 8 — Corrección de regresiones"
echo " $(date)"
echo " Modo: ${MODO}"
echo "=========================================="

# ---------------------------------------------------------------------------
echo
echo "[1/5] Inventario de puertos a la escucha ANTES"
# ---------------------------------------------------------------------------
# Este inventario es el entregable de la fase, tanto o más que el arreglo:
# demuestra qué había abierto y qué queda abierto al terminar.
ss -tlnH | awk '{print $4}' | sort -u > "$BACKUP_DIR/puertos-antes.txt"
sed 's/^/  /' "$BACKUP_DIR/puertos-antes.txt"

if ! command -v postconf >/dev/null 2>&1; then
  echo
  echo "  Postfix no está instalado. Nada que corregir en el apartado de correo."
  POSTFIX_PRESENTE=0
else
  POSTFIX_PRESENTE=1
fi

# ---------------------------------------------------------------------------
echo
echo "[2/5] Corrigiendo el servicio de correo"
# ---------------------------------------------------------------------------
if [[ $POSTFIX_PRESENTE -eq 1 ]]; then
  cp -a /etc/postfix/main.cf "$BACKUP_DIR/main.cf" 2>/dev/null || true
  postconf -n > "$BACKUP_DIR/postconf-n-anterior.txt" 2>/dev/null || true

  if [[ "$MODO" == "eliminar" ]]; then
    systemctl disable --now postfix >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq postfix bsd-mailx >/dev/null 2>&1 || true
    apt-get autoremove -y -qq >/dev/null 2>&1 || true
    echo "  Postfix y bsd-mailx desinstalados"
    echo "  NOTA: AIDE sigue auditando; su informe queda en /var/log/aide/ en vez de por correo."
  else
    # inet_interfaces: el parámetro que importa. 'all' escucha en todas las
    # interfaces; 'loopback-only' solo en 127.0.0.1 y ::1. Para entregar
    # correo generado por el propio sistema (cron, AIDE) basta con loopback.
    postconf -e 'inet_interfaces = loopback-only'

    # MAIL-8818: el banner por defecto incluye $mail_name y "(Ubuntu)", que
    # regala la distribución y el software a cualquiera que abra el puerto.
    # El RFC 5321 solo exige el nombre de host; lo demás sobra.
    postconf -e 'smtpd_banner = $myhostname ESMTP'

    # MAIL-8820: VRFY permite preguntar "¿existe el usuario X?" y enumerar
    # cuentas locales sin autenticarse. No hace falta para nada legítimo.
    postconf -e 'disable_vrfy_command = yes'

    systemctl restart postfix
    echo "  inet_interfaces  = loopback-only"
    echo "  smtpd_banner     = \$myhostname ESMTP"
    echo "  disable_vrfy_command = yes"
    echo "  postfix reiniciado"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "[3/5] FINT-4402 — resumen criptográfico de AIDE"
# ---------------------------------------------------------------------------
# Lynis avisa de que AIDE podría usar resúmenes débiles. En Ubuntu la
# configuración NO está toda en aide.conf: se ensambla desde
# /etc/aide/aide.conf.d/. Antes de cambiar nada, miramos qué hay de verdad.
if [[ -d /etc/aide ]]; then
  CKSUM=$(grep -rhiE '^[[:space:]]*Checksums[[:space:]]*=' \
            /etc/aide/aide.conf /etc/aide/aide.conf.d/ 2>/dev/null | tail -1 || true)

  if [[ -z "$CKSUM" ]]; then
    # Sin directiva explícita: puede estar implícita en las definiciones de
    # grupo (Full, Checksums...). Buscamos si sha256/sha512 aparecen por algún lado.
    if grep -rqiE 'sha(256|512)' /etc/aide/aide.conf /etc/aide/aide.conf.d/ 2>/dev/null; then
      echo "  sin directiva 'Checksums=', pero sha256/sha512 sí aparecen en la configuración"
      echo "  -> probable falso positivo de Lynis: busca la directiva, no el algoritmo efectivo"
    else
      mkdir -p /etc/aide/aide.conf.d
      cat > /etc/aide/aide.conf.d/99-zz-hardening-checksums <<'EOF'
# FINT-4402 — resúmenes criptográficos fuertes.
# md5 y sha1 tienen colisiones prácticas: un atacante puede modificar un
# fichero y conservar el mismo resumen, que es justo lo que AIDE debe detectar.
Checksums = sha256+sha512
EOF
      echo "  escrito /etc/aide/aide.conf.d/99-zz-hardening-checksums (sha256+sha512)"
      echo "  NOTA: hay que regenerar la base: sudo aideinit -y -f"
    fi
  else
    echo "  directiva encontrada: ${CKSUM}"
    if echo "$CKSUM" | grep -qiE 'sha(256|512)'; then
      echo "  -> ya usa resúmenes fuertes; el hallazgo de Lynis es un falso positivo"
    else
      echo "  -> resumen DÉBIL. Revísalo a mano antes de tocar nada:"
      echo "     grep -rn 'Checksums' /etc/aide/"
    fi
  fi
else
  echo "  AIDE no está instalado; nada que revisar."
fi

# ---------------------------------------------------------------------------
echo
echo "[4/5] Verificación del estado REALMENTE activo"
# ---------------------------------------------------------------------------
# Igual que en el resto del laboratorio: escribir la directiva no es
# aplicarla. Aquí se comprueba contra el sistema, no contra el fichero.
FALLOS=0

if [[ $POSTFIX_PRESENTE -eq 1 && "$MODO" == "restringir" ]]; then
  EXPUESTO=$(ss -tlnH 2>/dev/null | awk '{print $4}' | grep -E '(^0\.0\.0\.0|^\[?::\]?):25$' || true)
  if [[ -n "$EXPUESTO" ]]; then
    echo "  FALLO  el puerto 25 sigue escuchando en todas las interfaces:"
    echo "$EXPUESTO" | sed 's/^/         /'
    FALLOS=$((FALLOS + 1))
  else
    echo "  OK     el puerto 25 ya no escucha en interfaces externas"
    ss -tlnH 2>/dev/null | awk '$4 ~ /:25$/ {print "         ahora en " $4}'
  fi

  BANNER_EFECTIVO=$(postconf -h smtpd_banner 2>/dev/null || echo "")
  if echo "$BANNER_EFECTIVO" | grep -qiE 'mail_name|ubuntu|debian'; then
    echo "  FALLO  el banner sigue revelando software: ${BANNER_EFECTIVO}"
    FALLOS=$((FALLOS + 1))
  else
    echo "  OK     banner: ${BANNER_EFECTIVO}"
  fi

  VRFY=$(postconf -h disable_vrfy_command 2>/dev/null || echo "")
  if [[ "$VRFY" == "yes" ]]; then
    echo "  OK     VRFY desactivado"
  else
    echo "  FALLO  VRFY sigue activo (disable_vrfy_command = ${VRFY:-vacío})"
    FALLOS=$((FALLOS + 1))
  fi
fi

if [[ "$MODO" == "eliminar" ]]; then
  if ss -tlnH 2>/dev/null | awk '{print $4}' | grep -q ':25$'; then
    echo "  FALLO  algo sigue escuchando en el puerto 25"
    FALLOS=$((FALLOS + 1))
  else
    echo "  OK     nada escucha en el puerto 25"
  fi
fi

echo
echo "  --- puertos a la escucha DESPUÉS ---"
ss -tlnH | awk '{print $4}' | sort -u > "$BACKUP_DIR/puertos-despues.txt"
sed 's/^/  /' "$BACKUP_DIR/puertos-despues.txt"

echo
echo "  --- diferencia ---"
# Ojo con 'pipefail' aquí: diff devuelve 1 cuando los ficheros DIFIEREN, que es
# justo el caso normal. Si se mete el diff directamente en un 'if', pipefail
# propaga ese 1, la condición se evalúa como falsa y el script informa de "sin
# cambios" justo después de haberlos impreso. Se captura la salida primero y se
# decide sobre su contenido, no sobre el código de salida.
DIFERENCIA=$(diff -u "$BACKUP_DIR/puertos-antes.txt" "$BACKUP_DIR/puertos-despues.txt" \
             | grep -E '^[+-][^+-]' || true)
if [[ -n "$DIFERENCIA" ]]; then
  echo "$DIFERENCIA" | sed 's/^/  /'
else
  echo "  (sin cambios)"
fi

# ---------------------------------------------------------------------------
echo
echo "[5/5] Script de reversión"
# ---------------------------------------------------------------------------
cat > "$REVERTIR" <<EOF
#!/usr/bin/env bash
set -e
if [[ -f "$BACKUP_DIR/main.cf" ]]; then
  cp -a "$BACKUP_DIR/main.cf" /etc/postfix/main.cf
  systemctl restart postfix 2>/dev/null || true
  echo "main.cf restaurado."
else
  echo "No había main.cf guardado (¿se usó MODO=eliminar?). Reinstala con: apt-get install postfix"
fi
rm -f /etc/aide/aide.conf.d/99-zz-hardening-checksums
echo "Fase 8 revertida."
EOF
chmod +x "$REVERTIR"
echo "  escrito ${REVERTIR}"

echo
echo "=========================================="
if [[ $FALLOS -eq 0 ]]; then
  echo " FASE 8 APLICADA Y VERIFICADA"
else
  echo " FASE 8 APLICADA CON ${FALLOS} FALLO(S) — revisar arriba"
fi
echo " Reversión: sudo ${REVERTIR}"
echo "=========================================="
echo
echo "Siguiente paso: volver a medir con la misma versión de Lynis."
echo "  sudo bash fase7-medicion.sh"
