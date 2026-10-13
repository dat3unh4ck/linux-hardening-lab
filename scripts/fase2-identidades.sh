#!/usr/bin/env bash
#
# fase2-identidades.sh — Gestión de identidades, contraseñas y permisos por defecto
#
# Hallazgos de Lynis que resuelve:
#   AUTH-9230  Configurar rondas de hashing de contraseñas en /etc/login.defs
#   AUTH-9286  Configurar edad mínima y máxima de contraseña
#   AUTH-9328  umask por defecto más estricta (027 en lugar de 022)
#   AUTH-9262  Instalar un módulo PAM de robustez de contraseñas
#   AUTH-9229  Revisar configuración PAM y caducidad de contraseñas
#   AUTH-9282  Fijar fecha de caducidad en las cuentas con contraseña
#   DEB-0280   Instalar libpam-tmpdir ($TMP y $TMPDIR privados por sesión PAM)
#
# Es idempotente: se puede ejecutar varias veces sin efectos acumulativos.
# Hace copia de seguridad de cada fichero antes de tocarlo.
#
set -euo pipefail

BACKUP_DIR="/opt/hardening-lab/backups/$(date +%Y%m%d-%H%M%S)"
LOG="/opt/hardening-lab/fase2.log"

if [[ $EUID -ne 0 ]]; then
  echo "ERROR: ejecútalo con sudo." >&2
  exit 1
fi

mkdir -p "$BACKUP_DIR" "$(dirname "$LOG")"
exec > >(tee -a "$LOG") 2>&1

echo "=========================================="
echo " FASE 2 — Identidades y contraseñas"
echo " $(date)"
echo " Copias de seguridad en: $BACKUP_DIR"
echo "=========================================="

backup() {
  [[ -f "$1" ]] && cp -a "$1" "$BACKUP_DIR/$(basename "$1")" && echo "  copia: $1"
}

# Fija 'clave valor' en /etc/login.defs dejando UNA sola directiva activa.
#
# Elimina primero todas las líneas ACTIVAS de esa clave y añade una al final.
# El detalle importante es que el patrón NO admite almohadilla: login.defs
# documenta cada parámetro con ejemplos comentados encima, y un patrón del tipo
# '^[[:space:]]*#?[[:space:]]*CLAVE' encajaría también con esos comentarios,
# convirtiendo la documentación en directivas duplicadas. Además sed sustituye
# todas las coincidencias, no la primera.
#
# Al borrar y volver a añadir, el script es idempotente de verdad: ejecutarlo
# dos veces deja exactamente el mismo fichero, y además repara duplicados
# preexistentes.
set_logindefs() {
  local clave="$1" valor="$2" f=/etc/login.defs
  local previas
  previas=$(grep -cE "^[[:space:]]*${clave}[[:space:]]" "$f" || true)
  sed -i -E "/^[[:space:]]*${clave}[[:space:]]/d" "$f"
  printf '%s\t%s\n' "$clave" "$valor" >> "$f"
  if [[ "$previas" -gt 1 ]]; then
    echo "  login.defs: ${clave} = ${valor}  (se eliminaron ${previas} duplicadas)"
  else
    echo "  login.defs: ${clave} = ${valor}"
  fi
}

# ---------------------------------------------------------------------------
echo
echo "[1/4] Políticas de contraseña y umask en /etc/login.defs"
# ---------------------------------------------------------------------------
backup /etc/login.defs

set_logindefs PASS_MAX_DAYS 90    # caducidad máxima
set_logindefs PASS_MIN_DAYS 7     # mínimo entre cambios (evita rotar para volver a la misma)
set_logindefs PASS_WARN_AGE 7     # aviso previo
set_logindefs UMASK 027           # ficheros nuevos sin permisos para "otros"

# Rondas de derivación del hash. Solo tienen efecto si ENCRYPT_METHOD es SHA256
# o SHA512; con yescrypt se ignoran. Esta instalación de Ubuntu 24.04 viene con
# ENCRYPT_METHOD=SHA512, así que aquí sí se aplican: 65536 rondas encarecen
# notablemente un ataque por fuerza bruta contra /etc/shadow.
set_logindefs SHA_CRYPT_MIN_ROUNDS 65536
set_logindefs SHA_CRYPT_MAX_ROUNDS 65536

metodo=$(grep -E '^[[:space:]]*ENCRYPT_METHOD' /etc/login.defs | awk '{print $2}' || true)
echo "  método de hashing: ${metodo:-no definido}"
case "${metodo:-}" in
  SHA512|SHA256) echo "    -> las rondas configuradas SÍ se aplican" ;;
  YESCRYPT)      echo "    -> yescrypt ignora SHA_CRYPT_*_ROUNDS (no pasa nada, es más robusto)" ;;
  *)             echo "    -> método no reconocido, revisar manualmente" ;;
esac

# ---------------------------------------------------------------------------
echo
echo "[2/4] Módulos PAM: robustez de contraseñas y directorio temporal privado"
# ---------------------------------------------------------------------------
export DEBIAN_FRONTEND=noninteractive
apt-get install -y -qq libpam-pwquality libpam-tmpdir >/dev/null
echo "  instalados: libpam-pwquality, libpam-tmpdir"

# La configuración va en /etc/security/pwquality.conf, no editando
# /etc/pam.d/common-password a mano: ese fichero lo regenera pam-auth-update
# y se perdería el cambio. Esta vía sobrevive a las actualizaciones.
backup /etc/security/pwquality.conf

set_pwquality() {
  local clave="$1" valor="$2" f=/etc/security/pwquality.conf
  if grep -qE "^[[:space:]]*#?[[:space:]]*${clave}[[:space:]]*=" "$f"; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*${clave}[[:space:]]*=.*|${clave} = ${valor}|" "$f"
  else
    printf '%s = %s\n' "$clave" "$valor" >> "$f"
  fi
  echo "  pwquality: ${clave} = ${valor}"
}

set_pwquality minlen 14      # longitud mínima
set_pwquality dcredit -1     # al menos un dígito
set_pwquality ucredit -1     # al menos una mayúscula
set_pwquality lcredit -1     # al menos una minúscula
set_pwquality ocredit -1     # al menos un símbolo
set_pwquality difok 3        # al menos 3 caracteres distintos de la anterior
set_pwquality retry 3        # intentos antes de rendirse
set_pwquality enforcing 1    # aplicar también a root cuando cambia contraseñas ajenas

# ---------------------------------------------------------------------------
echo
echo "[3/4] Aplicar caducidad a las cuentas existentes"
# ---------------------------------------------------------------------------
# login.defs solo rige para cuentas NUEVAS. Las que ya existen conservan sus
# valores, así que hay que aplicárselos explícitamente con chage.
# Solo cuentas humanas: UID >= 1000, con shell válida, excluyendo nobody.
while IFS=: read -r usuario _ uid _ _ _ shell; do
  [[ $uid -ge 1000 && $uid -lt 65534 ]] || continue
  [[ "$shell" =~ (nologin|false)$ ]] && continue
  chage -M 90 -m 7 -W 7 "$usuario"
  echo "  $usuario (uid $uid): max 90, min 7, aviso 7"
done < /etc/passwd

# ---------------------------------------------------------------------------
echo
echo "[4/4] Verificación"
# ---------------------------------------------------------------------------
echo "--- /etc/login.defs (debe haber UNA línea por clave) ---"
for clave in PASS_MAX_DAYS PASS_MIN_DAYS PASS_WARN_AGE UMASK SHA_CRYPT_MIN_ROUNDS SHA_CRYPT_MAX_ROUNDS; do
  n=$(grep -cE "^[[:space:]]*${clave}[[:space:]]" /etc/login.defs || true)
  v=$(grep -E "^[[:space:]]*${clave}[[:space:]]" /etc/login.defs | awk '{print $2}' | tr '\n' ' ')
  if [[ "$n" -eq 1 ]]; then
    printf '  OK    %-22s %s\n' "$clave" "$v"
  else
    printf '  FALLO %-22s %s directivas activas: %s\n' "$clave" "$n" "$v"
  fi
done

echo "--- pam_pwquality presente en common-password ---"
grep -q 'pam_pwquality.so' /etc/pam.d/common-password \
  && echo "  OK" \
  || echo "  AVISO: no aparece — revisa 'pam-auth-update'"

echo "--- pam_tmpdir presente en common-session ---"
grep -q 'pam_tmpdir.so' /etc/pam.d/common-session \
  && echo "  OK" \
  || echo "  AVISO: no aparece"

echo "--- caducidad de las cuentas humanas ---"
while IFS=: read -r usuario _ uid _ _ _ shell; do
  [[ $uid -ge 1000 && $uid -lt 65534 ]] || continue
  [[ "$shell" =~ (nologin|false)$ ]] && continue
  echo "  $usuario: $(chage -l "$usuario" | grep -i 'Maximum number' | cut -d: -f2 | xargs) días"
done < /etc/passwd

echo
echo "=========================================="
echo " FASE 2 COMPLETADA"
echo " Log: $LOG"
echo " Para revertir: cp $BACKUP_DIR/* a sus rutas originales"
echo "=========================================="
echo
echo "NOTA: la umask 027 y las reglas de pwquality se aplican a partir de ahora."
echo "Tu contraseña actual NO se invalida, pero la próxima que pongas deberá"
echo "tener 14 caracteres con mayúscula, minúscula, dígito y símbolo."
