# Hallazgos que no se arreglaron, y por qué

Al terminar quedaban 17 sugerencias y 2 avisos. **Cinco de ellos son
limitaciones de la herramienta, no controles sin aplicar**, y arreglarlos habría
significado empeorar la configuración para contentar a un script.

Los cinco están demostrados aquí uno por uno, con la comprobación que lo prueba
en cada caso. Decidir esto —y poder justificarlo— es parte del trabajo: un
informe de auditoría que solo dice "quedan 17 hallazgos" no vale nada; lo que
vale es saber cuáles son reales.

Los cinco comparten el mismo mecanismo: **Lynis busca una cadena de texto en un
fichero de configuración, y el sistema resuelve ese ajuste en otro sitio** —en
una unidad de systemd, en otro idioma, en otra pila de filtrado, en otro formato
de fichero, o en un grupo interno de la propia herramienta auditada.

Comprobado todo contra Lynis **3.0.9** sobre **Ubuntu 24.04.5 LTS**. En
versiones posteriores alguno de estos puede estar ya resuelto.

---

## SSH-7408 — "Consider hardening SSH configuration"

**Lo que dice el informe.** Queda un único parámetro señalado:

```
ssh_option_port=Port (set 22 to )
```

**Lo que pasa de verdad.** El servicio escucha en el 2222:

```
$ sudo sshd -T | grep -i '^port'
port 22

$ ss -tln | grep 2222
LISTEN  0  4096  0.0.0.0:2222  0.0.0.0:*
LISTEN  0  4096     [::]:2222     [::]:*
```

**Por qué.** En Ubuntu 24.04 el puerto lo gobierna `ssh.socket`, no
`sshd_config`. Lynis lee el puerto de `sshd -T`, que al no encontrar ninguna
directiva `Port` responde con el valor por defecto. Lynis no contempla la
activación por socket.

**Por qué no se arregla.** Para que Lynis lo diera por bueno habría que
declarar `Port 2222` en `sshd_config`, donde es **inerte** —no cambia nada—
y queda una directiva que miente sobre dónde escucha el servicio. Peor que el
hallazgo.

De los nueve parámetros que SSH-7408 señalaba en la línea de partida,
ocho se resolvieron. Queda este.

---

## BANN-7126 y BANN-7130 — "Add a legal banner"

**Lo que dice el informe.** Faltan los avisos legales en `/etc/issue` y
`/etc/issue.net`.

**Lo que pasa de verdad.** Los dos ficheros existen, con 441 bytes cada uno, y
el aviso aparece en cada conexión. El propio log de Lynis lo confirma:

```
BANN-7124 (Check issue banner file)              → sin sugerencia  ✓ el fichero existe
BANN-7126 (Check issue banner file CONTENTS)     → sugerencia      ✗
BANN-7128 (Check issue.net banner file)          → sin sugerencia  ✓
BANN-7130 (Check issue.net banner file CONTENTS) → sugerencia      ✗
```

Las pruebas de existencia pasan. Solo fallan las de contenido.

**Por qué.** Lynis recorre una lista de 31 palabras clave **en inglés** y exige
**cinco coincidencias como mínimo** (`COUNT > 4`):

```sh
for ITEM in ${LEGAL_BANNER_STRINGS}; do
    FIND=$(${GREPBINARY} -i "${ITEM}" ${FILE})
    if HasData "${FIND}"; then COUNT=$((COUNT + 1)); fi
done
```

Pasando nuestro banner en español por el mismo bucle:

```
monitor  → SÍ  (monitorizada)
penal    → SÍ  (penales)

COUNT = 2   (exige > 4)   → FALLA
```

Y todo lo demás se queda a una o dos letras:

| En el banner | Lynis busca | |
|---|---|---|
| acce**so** | acce**ss** | ✗ |
| a**u**tori**z**ado | a**u**thori | ✗ |
| si**s**tema | s**y**stem | ✗ |
| restri**ngi**do | restri**cte**d | ✗ |
| des**con**ecte | **conn**ect | ✗ |

**La prueba no mide si hay un aviso legal. Mide si está en inglés.**

**Por qué no se arregla.** Un aviso legal existe para que lo lea quien se
conecta. Traducirlo al inglés en una organización hispanohablante lo deja sin
efecto práctico —y probablemente sin efecto legal— a cambio de dos puntos de
un índice.

La salida razonable sería un banner **bilingüe**, que es lo que hacen muchas
organizaciones reales: cumple con las dos cosas. Queda apuntado como mejora,
no como corrección.

---

## FIRE-4512 — "iptables module(s) loaded, but no rules active" (aviso)

**Lo que dice el informe.**

```
firewall_software[]=iptables
firewall_software[]=nftables
firewall_active=1
firewall_installed=1
firewall_empty_ruleset=1
firewall_no_logging[]=iptables
```

**Lo que pasa de verdad.**

```
reglas iptables : 0
reglas nftables : 20
```

**Por qué.** Lynis detecta las dos pilas pero cuenta las reglas de iptables,
que efectivamente está vacío porque todo el cortafuegos vive en nftables.
Por el mismo motivo informa de que no hay registro de descartes, cuando la
cadena `input` sí los registra:

```
limit rate 5/minute burst 10 packets log prefix "[nft-drop-input] " level warn
```

**Por qué no se arregla.** La única forma de silenciarlo sería duplicar las
reglas en iptables, que es exactamente lo que no se debe hacer: dos pilas de
filtrado sobre el mismo tráfico, con el riesgo de que diverjan y nadie sepa
cuál manda.

---

## PKGS-7388 — "Can't find any security repository" (aviso)

Este aviso estaba ya en la línea de partida, antes de tocar nada.

**Lo que pasa de verdad.**

```
/etc/apt/sources.list                   : 0 coincidencias de "security"
/etc/apt/sources.list.d/ubuntu.sources  : 1 coincidencia
```

**Por qué.** Ubuntu 24.04 migró al formato **deb822**: los repositorios ya no
se declaran en líneas `deb http://...` dentro de `sources.list`, sino en
estrofas dentro de `ubuntu.sources`, donde todas las suites —incluida
`noble-security`— van en un único campo `Suites:`. Lynis 3.0.9 busca el formato
antiguo y no encuentra nada.

El repositorio de seguridad **está habilitado**: `apt` ofrece actualizaciones
de seguridad con normalidad.

**Por qué no se arregla.** Volver al formato antiguo para contentar a la
herramienta sería ir hacia atrás en la propia distribución.

---

## FINT-4402 — "Use SHA256 or SHA512 to create checksums in AIDE"

**Lo que dice el informe.** AIDE estaría usando resúmenes criptográficos
débiles.

**Lo que ve Lynis.** La configuración dice exactamente esto:

```
/etc/aide/aide.conf:41:Checksums = H
```

Ni `sha256` ni `sha512` aparecen como texto. Lynis busca esas cadenas
literales, no las encuentra y avisa.

**Lo que pasa de verdad.** `H` no está definido en ningún fichero de
`/etc/aide/` porque es un **grupo compuesto interno** de AIDE. El propio
binario lo declara:

```
$ aide --version
Default compound groups:
  H: md5+sha1+rmd160+tiger+crc32+haval+gost+crc32b+sha256+sha512+whirlpool
```

Y no se queda en la configuración: la cabecera de la base de datos lista las
columnas que AIDE **calculó y almacenó** para cada fichero, que es el dato que
manda. La base son 26 MB comprimidos con gzip, así que hay que leerla con
`zcat` —un `grep` plano no devuelve nada, que es justo lo que despistó al
principio—:

```bash
$ sudo zcat -f /var/lib/aide/aide.db | grep -m1 '@@db_spec'
@@db_spec name lname perm uid gid size ctime mtime inode bcount lcount
          md5 sha1 rmd160 tiger crc32 haval gost crc32b attr acl
          sha256 sha512 selinux xattrs whirlpool e2fsattrs capabilities
```

`sha256` y `sha512` están ahí.

**Por qué no es una debilidad que la lista incluya md5.** AIDE exige que
coincidan **todos** los resúmenes a la vez, de modo que la fortaleza del
conjunto es la del algoritmo más fuerte, no la del más débil. Modificar un
fichero sin que AIDE lo detecte exigiría una colisión simultánea en sha512.

**Por qué no se arregla.** No hay nada que arreglar. La única forma de
silenciarlo sería escribir `Checksums = sha256+sha512` en vez de `H`, lo que
*reduciría* el número de algoritmos comprobados para que una herramienta
reconozca una cadena de texto.

La fase 8 incluye el arreglo por si hiciera falta, pero **no lo aplica a
ciegas**: comprueba primero qué hay configurado y, al encontrar un grupo que no
sabe resolver, se detiene y avisa de que hay que revisarlo a mano. Que se
detuviera es lo que permitió llegar hasta aquí en vez de degradar una
configuración correcta.

---

## Lo que queda realmente pendiente

Estos sí son hallazgos legítimos, no arreglados porque exigen decisiones fuera
del alcance de un laboratorio:

| Hallazgo | Por qué queda fuera |
|---|---|
| `FILE-6310` ×3 | Particiones separadas para `/home`, `/tmp` y `/var`: se decide al instalar, no después |
| `BOOT-5122` | Contraseña en GRUB: en una VM de laboratorio estorba más de lo que aporta |
| `LOGG-2154` | Registro centralizado: hace falta un segundo servidor |
| `NAME-4028` | Dominio DNS: la máquina no está en ninguno |
| `TOOL-5002` | Herramientas de automatización: fuera del alcance |
| `AUTH-9229` | Revisión completa de PAM: se tocó lo justo; una revisión a fondo merece fase propia |
