# Fallos encontrados durante el laboratorio

Esta es la parte útil del proyecto. Los scripts se pueden copiar de cualquier
guía; lo que no se copia es haberse chocado con estos seis problemas y haber
entendido por qué pasaban.

Todos tienen el mismo patrón de fondo:

> **Escribir una directiva, que el fichero valide y que el servicio la cargue
> no significa que la configuración esté aplicada.**

Cinco de los seis se detectaron comprobando el estado *efectivo* del sistema,
no leyendo el fichero que acabábamos de escribir. Uno se detectó intentando
hacer justo lo que la configuración decía impedir.

---

## 1. Un `?` en una expresión regular convirtió comentarios en directivas

**Fase 2 — identidades y contraseñas**

**Síntoma.** Tras aplicar la fase, `/etc/login.defs` tenía tres líneas `UMASK`
y dos de cada `PASS_MAX_DAYS`, `PASS_MIN_DAYS` y `PASS_WARN_AGE`.

**Causa.** La función que fijaba cada valor usaba un `sed` con el `#` opcional:

```bash
sed -i -E "s/^#?\s*${clave}.*/${clave}\t${valor}/" /etc/login.defs
```

`#?` hace que la expresión case **tanto con la directiva activa como con la
línea comentada que la documenta**. El fichero de Ubuntu trae varias líneas
comentadas de ejemplo para la misma clave, así que cada una se convirtió en una
directiva real. El resultado no era solo feo: con valores contradictorios,
cuál gana depende del orden de lectura.

**Arreglo.** Borrar todas las apariciones y añadir una sola al final:

```bash
set_logindefs() {
  local clave="$1" valor="$2" f=/etc/login.defs
  local previas
  previas=$(grep -cE "^[[:space:]]*${clave}[[:space:]]" "$f" || true)
  sed -i -E "/^[[:space:]]*${clave}[[:space:]]/d" "$f"
  printf '%s\t%s\n' "$clave" "$valor" >> "$f"
  # ...y después contar que quede exactamente una
}
```

**Lección.** Un `sed` que modifica configuración se prueba contra una copia del
fichero real antes de tocar el sistema, y se verifica contando las apariciones
resultantes. Un `?` mal puesto no da error: da un fichero plausible y roto.

---

## 2. `ListenStream=2222` dejó el servicio solo en IPv6

**Fase 3 — SSH**

**Síntoma.** Tras cambiar el puerto, `ssh -p 2222` daba `Connection refused`
desde el Mac, pero el servicio estaba activo y sin errores.

**Causa.** En Ubuntu 24.04 el puerto de SSH lo gobierna `ssh.socket`
(activación por socket de systemd), no `sshd_config`. Al escribir un
`ListenStream=2222` a secas, systemd vinculó el socket **solo a IPv6**, y la
conexión IPv4 no encontraba nada escuchando.

**Arreglo.** Declarar las dos familias de forma explícita:

```ini
[Socket]
ListenStream=
ListenStream=0.0.0.0:2222
ListenStream=[::]:2222
BindIPv6Only=ipv6-only
```

La primera línea vacía es obligatoria: limpia los valores heredados de la
unidad original. Sin ella se suman en vez de sustituirse.

**Lección.** Cuando una unidad de systemd acepta una lista, un `override.conf`
**añade** a lo que ya hay salvo que se vacíe primero. Y al cambiar un puerto,
comprobarlo con `ss -tln` para ver en qué familias quedó escuchando.

---

## 3. `PasswordAuthentication no` estaba escrito, cargado… y sin efecto

**Fase 3 — SSH. El más grave de todos.**

**Síntoma.** El fichero lo decía. `sshd -t` validaba sin quejas. El servicio
había recargado. Y aun así **se podía entrar con contraseña**.

**Causa.** `sshd_config` resuelve los conflictos quedándose con el **primer
valor que lee**, no con el último. Es la regla contraria a casi todo lo demás
en Unix. Nuestro fichero se llamaba `99-hardening.conf`, y Ubuntu trae
`/etc/ssh/sshd_config.d/50-cloud-init.conf` con `PasswordAuthentication yes`.
Al ordenar alfabéticamente, el 50 se lee antes que el 99: gana cloud-init.

**Arreglo.** Renombrar el fichero a `00-hardening.conf` y, sobre todo, añadir
una verificación del estado efectivo con `sshd -T`, que es lo único que
muestra la configuración ya resuelta:

```bash
comprobar() {
  local clave="$1" esperado="$2" real
  real=$(sshd -T 2>/dev/null | grep -i "^${clave} " | awk '{print $2}')
  [[ "${real,,}" == "${esperado,,}" ]]
}
```

**Lección.** Y la más importante: **esto no lo cazó ninguna verificación de
configuración. Lo cazó intentar entrar con contraseña.** Una prueba funcional
contra el comportamiento real vale más que diez comprobaciones sobre el
fichero.

---

## 4. `fs.protected_fifos` se quedó en 1 pese a pedir 2

**Fase 5 — núcleo y red**

**Síntoma.** De 29 parámetros de sysctl, 28 quedaron con el valor pedido y uno
no. El fichero lo declaraba correctamente.

**Causa.** La misma clase de problema que el anterior, **con la regla
invertida**. systemd junta `/etc/sysctl.d`, `/run/sysctl.d` y
`/usr/lib/sysctl.d`, los ordena alfabéticamente y aplica **el último**. Ubuntu
trae `/usr/lib/sysctl.d/99-protect-links.conf`; nuestro `99-hardening.conf`
ordenaba antes, así que el de Ubuntu lo pisaba.

Se confirmó con:

```bash
systemd-analyze cat-config sysctl.d | grep -n protected_fifos
```

**Arreglo.** Renombrar a `99-zz-hardening.conf` para que ordene el último, y
eliminar el fichero antiguo para no dejar dos compitiendo.

**Lección.** Las dos reglas de precedencia conviven en el mismo sistema y son
opuestas:

| Mecanismo | Gana |
|---|---|
| `sshd_config` y sus drop-ins | el **primer** valor leído |
| `sysctl.d` | el **último** fichero aplicado |

No hay forma de deducirlo: hay que saberlo o comprobarlo.

---

## 5. Instalar AIDE abrió un servidor SMTP a toda la red

**Fase 6 — auditoría. Una regresión causada por el propio bastionado.**

**Síntoma.** Tras la fase 6, la medición mostró un aviso nuevo: `MAIL-8818`,
divulgación de información en el banner SMTP. En un servidor que no tenía
—ni debía tener— servicio de correo.

**Causa.** La traza de APT no deja dudas:

```
Commandline: apt-get install -y -qq aide aide-common
Install: ... aide-common, bsd-mailx (automatic), postfix (automatic)
```

`aide-common` **recomienda** un agente de correo porque envía su informe diario
por email, y APT instala las recomendaciones por defecto. Postfix entró como
dependencia automática, quedó habilitado al arranque y con
`inet_interfaces = all`:

```
LISTEN 0.0.0.0:25
LISTEN [::]:25
```

Todas las interfaces, IPv4 e IPv6. Lo único que impidió que quedara expuesto
fue el cortafuegos de la fase 4 (política `drop`, solo el puerto de SSH
permitido). Defensa en profundidad haciendo exactamente su trabajo.

**Arreglo.** Fase 8: `inet_interfaces = loopback-only`, banner sin
identificación de software y `disable_vrfy_command = yes`. El correo local
sigue funcionando, así que AIDE puede seguir entregando su informe.

**Lección.** Instalar herramientas de seguridad **añade superficie de ataque**.
Después de bastionar hay que volver a inventariar los puertos a la escucha.
Por eso la fase 8 compara el inventario antes y después y enseña el diff: es
la comprobación que debería haber ido al final de la fase 6.

---

## 6. `pipefail` hizo que un script informara al revés

**Fase 8 — el fallo más tonto, y aun así instructivo**

**Síntoma.** La sección que compara puertos imprimía el diff **y a continuación**
`(sin cambios)`. Las dos cosas.

**Causa.**

```bash
if diff -u antes.txt despues.txt | grep -E '^[+-][^+-]' | sed 's/^/  /'; then
```

`diff` devuelve **1** cuando los ficheros difieren. No es un error: es su forma
de comunicar que hay cambios. Con `set -o pipefail` ese 1 se propaga a toda la
tubería, la condición se evalúa como falsa y el script cae al `else` después de
haber impreso ya la salida.

**Arreglo.** Capturar la salida y decidir sobre su contenido, no sobre el
código de salida:

```bash
DIFERENCIA=$(diff -u antes.txt despues.txt | grep -E '^[+-][^+-]' || true)
if [[ -n "$DIFERENCIA" ]]; then
  echo "$DIFERENCIA" | sed 's/^/  /'
else
  echo "  (sin cambios)"
fi
```

**Lección.** `set -euo pipefail` es la línea correcta en casi todos los scripts,
pero hay que conocer los comandos que usan el código de salida para comunicar
información en vez de error: `diff`, `grep`, `cmp`. Con ellos hace falta
`|| true` y decidir sobre la salida.

---

## Resumen

| # | Fase | Problema | Cómo se detectó |
|---|------|----------|-----------------|
| 1 | 2 | Regex convirtió comentarios en directivas | Contando apariciones tras aplicar |
| 2 | 3 | Socket vinculado solo a IPv6 | `ss -tln` + intento de conexión |
| 3 | 3 | Drop-in pisado por cloud-init | **Intentando entrar con contraseña** |
| 4 | 5 | Fichero sysctl pisado por el de Ubuntu | Comparando valor pedido vs `sysctl -n` |
| 5 | 6 | Dependencia abrió el puerto 25 | Volviendo a medir con Lynis |
| 6 | 8 | `pipefail` invirtió una condición | Leyendo la salida del propio script |

Cuatro de los seis son problemas de **precedencia u orden**, y ninguno produjo
un mensaje de error. Todos los ficheros eran sintácticamente válidos y todos
los servicios arrancaron sin quejarse.
