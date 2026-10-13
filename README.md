# Bastionado de servidor Ubuntu 24.04

Endurecimiento por fases de un Ubuntu Server 24.04 LTS, medido con Lynis antes
y después. Ocho scripts, cada uno con copia de seguridad, verificación del
estado efectivo y script de reversión propio.

Después audité mi propio trabajo y descubrí que el bastionado había dejado un
servidor SMTP escuchando en todas las interfaces.

---

## Resultado

| Métrica | Línea de partida | Tras bastionar | **Tras corregir** |
|---|---|---|---|
| **Hardening Index** | 61 | 82 | **82** |
| Sugerencias | 46 | 19 | **17** |
| Avisos | 2 | 3 | **2** |
| Pruebas ejecutadas | 255 | 265 | 265 |

`Lynis 3.0.9` · `Ubuntu 24.04.5 LTS` · `núcleo 6.8.0-146-generic` · `arm64`

**22 hallazgos resueltos.** Los dos avisos que quedan son limitaciones de la
herramienta, documentadas y justificadas en
[`docs/falsos-positivos.md`](docs/falsos-positivos.md): no queda ningún aviso
real sin atender.

Fíjate en que el índice **no sube** entre la segunda y la tercera columna.
La corrección cerró un puerto 25 abierto a toda la red y no movió el número.
Si el objetivo hubiera sido el índice, ese hallazgo —el único realmente serio
que quedaba— se habría ignorado.

---

## Qué hace distinto a este laboratorio

Aplicar controles de bastionado es la parte fácil: hay guías de sobra. Lo que
este repositorio documenta es lo otro.

### Se verifica el estado efectivo, no el fichero escrito

El hilo conductor de todo el proyecto:

> **Escribir una directiva, que el fichero valide y que el servicio la cargue
> no significa que la configuración esté aplicada.**

Cada fase comprueba el sistema, no lo que acaba de escribir: `sshd -T` para
SSH, `sysctl -n` para el núcleo, `ss -tln` para los puertos, `systemctl
is-active` para los servicios.

Y aun así el fallo más grave no lo detectó ninguna de esas comprobaciones.
Lo detectó **intentar entrar con contraseña** después de haberla desactivado.

### Se auditó el propio bastionado

La fase 6 instaló AIDE. `aide-common` **recomienda** un agente de correo para
enviar su informe diario, y APT instala las recomendaciones por defecto:

```
Commandline: apt-get install -y -qq aide aide-common
Install: ... aide-common, bsd-mailx (automatic), postfix (automatic)
```

Postfix quedó habilitado al arranque, con `inet_interfaces = all`:

```
LISTEN  0.0.0.0:25
LISTEN  [::]:25
```

Instalar una herramienta de seguridad abrió un servicio de red que nadie pidió.
Lo único que impidió que quedara expuesto fue el cortafuegos de la fase 4.
La fase 8 lo corrige y, sobre todo, **inventaría los puertos a la escucha antes
y después y enseña el diff** — la comprobación que debería haber cerrado la
fase 6.

### Se distingue entre hallazgo real y limitación de la herramienta

De los cinco hallazgos que quedaron al final, **cuatro son falsos positivos** y
están demostrados uno por uno. Perseguirlos habría significado degradar una
configuración correcta: volver al puerto 22, escribir el aviso legal en inglés,
duplicar las reglas del cortafuegos en iptables.

Un informe que dice "quedan 17 hallazgos" no vale nada. Lo que vale es saber
cuáles son reales.

---

## Las ocho fases

| Fase | Qué hace | Hallazgos de Lynis |
|---|---|---|
| **1** · Línea de partida | Mide sin tocar nada. Inventario de puertos, servicios y cuentas | — |
| **2** · Identidades | Caducidad y robustez de contraseñas, `umask`, `pam_pwquality`, `libpam-tmpdir` | `AUTH-9230/9262/9282/9286/9328`, `DEB-0280` |
| **3** · SSH | Puerto 2222 vía `ssh.socket`, solo clave pública, sin acceso de `root`, cifrados modernos | `SSH-7408` (8 de 9) |
| **4** · Cortafuegos | nftables familia `inet`, política `drop`, anti-spoofing, ICMP limitado, descartes registrados. **Reversión automática a los 90 s** | `FIRE-4512`, `NETW-3200` ×4 |
| **5** · Núcleo y red | 29 parámetros de `sysctl` —cada uno con su motivo—, sin volcados de memoria, sin almacenamiento USB | `KRNL-5820`, `USB-1000` |
| **6** · Auditoría | `auditd`, `fail2ban`, AIDE, ClamAV, `sysstat`, `acct`, `debsums`, avisos legales | `ACCT-9622/9626/9628`, `DEB-0880/0811`, `FINT-4350`, `HRDN-7230`, `PKGS-7370/7394` |
| **7** · Medición | Repite la auditoría con la misma versión de Lynis y compara: resueltos / pendientes / nuevos | — |
| **8** · Corrección | Arregla las regresiones que introdujo la fase 6. Inventario de puertos antes/después | `MAIL-8818`, `MAIL-8820` |

Cada fase, sin excepción: copia de seguridad con marca de tiempo → aplicación →
**verificación del estado efectivo** → script de reversión.

---

## Los seis fallos que me encontré

Documentados al completo —síntoma, causa, cómo se detectó, arreglo y lección—
en [`docs/fallos-encontrados.md`](docs/fallos-encontrados.md). Los tres mejores:

**Un drop-in de SSH que no servía para nada.** `PasswordAuthentication no`
escrito, `sshd -t` validando sin quejas, servicio recargado… y se seguía
pudiendo entrar con contraseña. `sshd_config` se queda con el **primer** valor
que lee, y Ubuntu trae `50-cloud-init.conf` con `PasswordAuthentication yes`.
Nuestro fichero se llamaba `99-hardening.conf`: el 50 se lee antes.

**Y la regla contraria, dos fases después.** `fs.protected_fifos` se quedaba en
1 pese a pedir 2, porque `sysctl.d` aplica el **último** fichero y
`/usr/lib/sysctl.d/99-protect-links.conf` ordenaba después del nuestro.

| Mecanismo | Gana |
|---|---|
| `sshd_config` y sus drop-ins | el **primer** valor leído |
| `sysctl.d` | el **último** fichero aplicado |

Dos reglas opuestas conviviendo en el mismo sistema. No hay forma de deducirlo.

**Un `?` que convirtió comentarios en directivas.** Un `sed` con `^#?\s*CLAVE`
casaba también con las líneas de ejemplo comentadas de `/etc/login.defs`, y las
activó todas. Tres `UMASK` distintos, ninguno dando error.

Cuatro de los seis son problemas de precedencia u orden. **Ninguno produjo un
mensaje de error**: todos los ficheros eran válidos y todos los servicios
arrancaron sin quejarse.

---

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
│   └── fase8-correccion.sh      corrección de regresiones
├── reports/
│   ├── 01-baseline.dat                      índice 61
│   ├── 02-con-regresion.dat                 índice 82, con el puerto 25 abierto
│   ├── 02-con-regresion-comparativa.txt
│   ├── 03-post-correccion.dat               índice 82, sin avisos reales
│   └── 03-post-correccion-comparativa.txt
└── docs/
    ├── entorno.md               sistema, acceso y cómo reproducirlo
    ├── fallos-encontrados.md    los seis fallos, en detalle
    └── falsos-positivos.md      los cuatro hallazgos que no se arreglaron
```

Los tres informes `.dat` son la salida cruda de Lynis. Se pueden comparar con
`diff` o volver a procesar. La única modificación es la sustitución de la IP
privada y la MAC de la máquina virtual por valores de ejemplo
(`192.168.0.10`, `00:0c:29:00:00:00`); ni una ni otra son enrutables ni
exponen nada, pero no hay motivo para publicarlas.

---

## Reproducirlo

Requisitos, rutas, variables y el orden de ejecución están en
[`docs/entorno.md`](docs/entorno.md).

En resumen: Ubuntu Server 24.04 recién instalado, copiar `scripts/`, y lanzar
las fases **una a una**, leyendo la verificación de cada una antes de seguir.

> **No encadenes las fases en un solo script.** Tres de los seis fallos
> documentados se detectaron leyendo la salida de una fase antes de lanzar la
> siguiente. Desatendido, habrían pasado desapercibidos.

> **Es un laboratorio.** Los scripts cambian SSH, el cortafuegos y el núcleo.
> No los ejecutes sobre nada que te importe sin leerlos antes y sin tener
> acceso por consola.

---

## Pendiente

- **`FINT-4402`** — `Checksums = H` en AIDE. `H` no está definido en
  `/etc/aide/`, así que es un grupo interno. Falta confirmar a qué se expande
  leyendo la cabecera `@@db_spec` de la base de datos. Es el único hallazgo sin
  veredicto, y se deja abierto en vez de darlo por bueno.
- **Aviso legal bilingüe** — el actual está en español y Lynis solo reconoce
  palabras en inglés. Un banner en los dos idiomas cumpliría ambas cosas.
- **Particiones separadas** (`/home`, `/tmp`, `/var`) — se decide al instalar;
  exigiría rehacer la máquina.
- **Registro centralizado** (`LOGG-2154`) — hace falta un segundo servidor.
  Encaja con el laboratorio de ELK.

---

## Licencia

MIT. Ver [`LICENSE`](LICENSE).
