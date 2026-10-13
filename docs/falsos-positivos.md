# Hallazgos que no se arreglaron, y por qué

Al terminar quedaban 17 sugerencias y 2 avisos. Algunos son limitaciones de la
herramienta, no controles sin aplicar, y **arreglarlos habría significado
empeorar la configuración para contentar a un script**.

Decidir eso —y poder demostrarlo— es parte del trabajo. Un informe de auditoría
que solo dice "quedan 17 hallazgos" no vale nada; lo que vale es saber cuáles
son reales.

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

> **Estado: sin confirmar.** Es el único hallazgo pendiente de verificar, y se
> deja aquí abierto en vez de darlo por bueno.

**Lo que se sabe.** La configuración dice:

```
/etc/aide/aide.conf:41:Checksums = H
```

y `H` **no está definido en ningún fichero de `/etc/aide/`**, lo que indica que
es un grupo interno de AIDE. El binario es 0.18.6 compilado con `use Mhash: yes`.

**La hipótesis.** `H` se expande al conjunto de algoritmos compilados, que
incluiría sha256 y sha512 junto a otros más antiguos. Si fuera así, no sería
una debilidad: **AIDE exige que coincidan todos los resúmenes a la vez**, de
modo que la fortaleza del conjunto es la del algoritmo más fuerte, no la del
más débil. Falsificar un fichero exigiría una colisión simultánea en sha512.

**Cómo se confirma.** La cabecera de la base de datos lista las columnas que
AIDE calculó y almacenó de verdad, que es el dato que manda:

```bash
sudo grep -m1 '@@db_spec' /var/lib/aide/aide.db
```

Si ahí aparecen `sha256` y `sha512`, es un falso positivo más y no hay nada que
hacer. Si solo aparecen `md5` y `sha1`, el hallazgo es real y serio: un atacante
podría modificar un binario conservando el resumen, que es justo lo que AIDE
existe para detectar.

La fase 8 incluye el arreglo, pero **no lo aplica a ciegas**: comprueba primero
qué hay configurado y avisa de que hace falta revisarlo a mano.

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
