# Bastionado de servidor Ubuntu 24.04

Endurecimiento por fases de un Ubuntu Server 24.04 LTS, medido con Lynis antes y
después. Nueve scripts, cada uno con copia de seguridad, verificación del estado
efectivo y su propio script de reversión.

Al terminar audité mi propio trabajo y me encontré con que el bastionado había
dejado un servidor SMTP escuchando en todas las interfaces.

## Resultado

| Métrica | Línea de partida | Tras bastionar | Tras corregir |
|---|---|---|---|
| Hardening Index | 61 | 82 | 82 |
| Sugerencias | 46 | 19 | 17 |
| Avisos | 2 | 3 | 2 |
| Pruebas ejecutadas | 255 | 265 | 265 |

`Lynis 3.0.9` · `Ubuntu 24.04.5 LTS` · `núcleo 6.8.0-146-generic` · `arm64`

22 hallazgos resueltos. Los dos avisos que quedan son limitaciones de la
herramienta, documentadas una a una en
[`docs/falsos-positivos.md`](docs/falsos-positivos.md): no queda ningún aviso real
sin atender.

El índice no sube entre la segunda columna y la tercera. La corrección cerró un
puerto 25 que estaba abierto a toda la red y no movió el número. Si hubiera ido a
por la puntuación, ese hallazgo —el único serio que quedaba— lo habría ignorado.

## Qué tiene este laboratorio

Aplicar controles de bastionado es la parte fácil; hay guías de sobra. Lo que
documento aquí es lo otro.

### Comprobar el estado efectivo, no el fichero escrito

Es el hilo de todo el proyecto: escribir una directiva, que el fichero valide y
que el servicio la cargue no significa que la configuración esté aplicada.

Por eso cada fase comprueba el sistema, no lo que acaba de escribir: `sshd -T`
para SSH, `sysctl -n` para el núcleo, `ss -tln` para los puertos, `systemctl
is-active` para los servicios.

Y aun así, el fallo más grave no lo cazó ninguna de esas comprobaciones. Lo cacé
intentando entrar con contraseña después de haberla desactivado.

### Auditar el propio bastionado

La fase 6 instaló AIDE. `aide-common` recomienda un agente de correo para enviar
su informe diario, y APT instala las recomendaciones por defecto:

```
Commandline: apt-get install -y -qq aide aide-common
Install: ... aide-common, bsd-mailx (automatic), postfix (automatic)
```

Postfix quedó habilitado al arranque, con `inet_interfaces = all`:

```
LISTEN  0.0.0.0:25
LISTEN  [::]:25
```

Instalar una herramienta de seguridad me abrió un servicio de red que no pedí. Lo
único que evitó que quedara expuesto fue el cortafuegos de la fase 4. La fase 8 lo
corrige y, sobre todo, inventaría los puertos a la escucha antes y después y
enseña el diff: la comprobación que tendría que haber cerrado la fase 6.

### Separar hallazgo real de limitación de la herramienta

De los seis hallazgos que quedaban al final, cinco son falsos positivos y los
demuestro uno por uno. El sexto era real: el del puerto 25.

Perseguir los cinco habría sido degradar una configuración correcta: volver al
puerto 22, escribir el aviso legal en inglés, duplicar las reglas del cortafuegos
en iptables, volver a `sources.list` en una distribución que ya no lo usa, y bajar
de once a dos los algoritmos con los que AIDE firma cada fichero. Todo para que
una herramienta reconociera unas cadenas de texto.

Un informe que dice "quedan 17 hallazgos" no sirve de mucho. Lo que sirve es saber
cuáles son reales.

### Mirarlo desde fuera

Las ocho primeras fases comprueban el sistema desde dentro. La novena lo escanea
desde otra máquina, y ahí salió algo que ninguna comprobación interna podía ver:

| Sondeo desde el Mac | Resultado |
|---|---|
| 10.000 puertos a 2.000 paq/s | 10.000 filtrados, ninguno abierto |
| 1 puerto (`-p 2222`), una sonda | `2222/tcp open`, `syn-ack` |

Misma máquina, mismas reglas, noventa segundos de diferencia. La causa es el
`limit rate 30/minute burst 10 packets` de la regla de SSH: cuando se supera el
límite, la regla deja de coincidir y el paquete cae hasta el descarte final, así
que un escáner rápido no encuentra el servicio.

Ese efecto no lo diseñé; la regla estaba para frenar la fuerza bruta. Y no es
seguridad por oscuridad, porque un atacante paciente lo encuentra en medio
segundo. Lo que sí tiene es un coste operativo que conviene nombrar, porque mi
propio inventario de activos también se lo pierde.
[`docs/validacion-externa.md`](docs/validacion-externa.md) lo cuenta entero, con la
prueba de carga y dos tropiezos con el propio nmap.

## Las nueve fases

| Fase | Qué hace | Hallazgos de Lynis |
|---|---|---|
| 1 · Línea de partida | Mide sin tocar nada. Inventario de puertos, servicios y cuentas | — |
| 2 · Identidades | Caducidad y robustez de contraseñas, `umask`, `pam_pwquality`, `libpam-tmpdir` | `AUTH-9230/9262/9282/9286/9328`, `DEB-0280` |
| 3 · SSH | Puerto 2222 vía `ssh.socket`, solo clave pública, sin acceso de `root`, cifrados modernos | `SSH-7408` (8 de 9) |
| 4 · Cortafuegos | nftables familia `inet`, política `drop`, anti-spoofing, ICMP limitado, descartes registrados. Reversión automática a los 90 s | `FIRE-4512`, `NETW-3200` ×4 |
| 5 · Núcleo y red | 29 parámetros de `sysctl`, cada uno con su motivo, sin volcados de memoria ni almacenamiento USB | `KRNL-5820`, `USB-1000` |
| 6 · Auditoría | `auditd`, `fail2ban`, AIDE, ClamAV, `sysstat`, `acct`, `debsums`, avisos legales | `ACCT-9622/9626/9628`, `DEB-0880/0811`, `FINT-4350`, `HRDN-7230`, `PKGS-7370/7394` |
| 7 · Medición | Repite la auditoría con la misma versión de Lynis y compara: resueltos / pendientes / nuevos | — |
| 8 · Corrección | Arregla las regresiones de la fase 6. Inventario de puertos antes/después | `MAIL-8818`, `MAIL-8820` |
| 9 · Validación | Resiliencia bajo carga con `stress-ng` comprobando los servicios durante la prueba, y escaneo perimetral desde otra máquina | — |

Todas las fases hacen lo mismo: copia de seguridad con marca de tiempo →
aplicación → verificación del estado efectivo → script de reversión.

## Los seis fallos que me encontré

Están al completo —síntoma, causa, cómo lo detecté, arreglo y lección— en
[`docs/fallos-encontrados.md`](docs/fallos-encontrados.md). Los tres que más me
gustaron:

**Un drop-in de SSH que no servía de nada.** `PasswordAuthentication no` escrito,
`sshd -t` validando sin quejas, servicio recargado… y se seguía pudiendo entrar
con contraseña. `sshd_config` se queda con el primer valor que lee, y Ubuntu trae
`50-cloud-init.conf` con `PasswordAuthentication yes`. Mi fichero se llamaba
`99-hardening.conf`: el 50 se lee antes.

**La regla contraria, dos fases después.** `fs.protected_fifos` se quedaba en 1
pese a pedir 2, porque `sysctl.d` aplica el último fichero y
`/usr/lib/sysctl.d/99-protect-links.conf` ordenaba después del mío.

| Mecanismo | Gana |
|---|---|
| `sshd_config` y sus drop-ins | el primer valor leído |
| `sysctl.d` | el último fichero aplicado |

Dos reglas opuestas conviviendo en el mismo sistema. No hay forma de deducirlo.

**Un `?` que convirtió comentarios en directivas.** Un `sed` con `^#?\s*CLAVE`
casaba también con las líneas de ejemplo comentadas de `/etc/login.defs`, y las
activó todas. Tres `UMASK` distintos, ninguno dando error.

Cuatro de los seis son problemas de precedencia u orden, y ninguno dio un mensaje
de error: todos los ficheros eran válidos y todos los servicios arrancaron sin
quejarse.

## Estructura

```
.
├── scripts/
│   ├── fase1-baseline.sh        línea de partida (no modifica nada)
│   ├── fase2-identidades.sh     contraseñas, umask, PAM
│   ├── fase3-ssh.sh             SSH + verificación con sshd -T
│   ├── fase4-firewall.sh        nftables + reversión automática
│   ├── fase5-kernel.sh          29 parámetros de sysctl
│   ├── fase6-auditoria.sh       auditd, fail2ban, AIDE, ClamAV
│   ├── fase7-medicion.sh        medición final y comparativa
│   ├── fase8-correccion.sh      corrección de regresiones
│   └── fase9-validacion.sh      carga + perímetro
├── reports/
│   ├── 01-baseline.dat                      índice 61
│   ├── 02-con-regresion.dat                 índice 82, con el puerto 25 abierto
│   ├── 02-con-regresion-comparativa.txt
│   ├── 03-post-correccion.dat               índice 82, sin avisos reales
│   └── 03-post-correccion-comparativa.txt
└── docs/
    ├── entorno.md               sistema, acceso y cómo reproducirlo
    ├── fallos-encontrados.md    los seis fallos, en detalle
    ├── falsos-positivos.md      los cinco hallazgos que no arreglé
    └── validacion-externa.md    carga, perímetro y lo que enseñó el escáner
```

Los tres informes `.dat` son la salida cruda de Lynis. Se pueden comparar con
`diff` o volver a procesar. Lo único que cambié fue sustituir la IP privada y la
MAC de la VM por valores de ejemplo (`192.168.0.10`, `00:0c:29:00:00:00`); ninguna
de las dos es enrutable ni expone nada, pero no tenía motivo para publicarlas.

## Reproducirlo

Requisitos, rutas, variables y el orden de ejecución están en
[`docs/entorno.md`](docs/entorno.md).

En resumen: Ubuntu Server 24.04 recién instalado, copiar `scripts/` y lanzar las
fases una a una, leyendo la verificación de cada una antes de seguir.

Conviene no encadenarlas en un solo script: tres de los seis fallos los detecté
leyendo la salida de una fase antes de lanzar la siguiente, y en una ejecución
desatendida habrían pasado desapercibidos.

Y es un laboratorio. Los scripts cambian SSH, el cortafuegos y el núcleo, así que
no los lanzaría sobre nada que importe sin leerlos antes y sin tener acceso por
consola.

## Pendiente

- Aviso legal bilingüe: el actual está en español y Lynis solo reconoce palabras
  en inglés. Un banner en los dos idiomas cumpliría ambas cosas.
- Particiones separadas (`/home`, `/tmp`, `/var`): se deciden al instalar, así que
  exigiría rehacer la máquina.
- Registro centralizado (`LOGG-2154`): hace falta un segundo servidor. Encaja con
  mi laboratorio de ELK.

## Licencia

MIT. Ver [`LICENSE`](LICENSE).
