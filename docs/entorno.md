# Entorno del laboratorio

## Sistema auditado

| | |
|---|---|
| Sistema operativo | Ubuntu Server 24.04.5 LTS (Noble Numbat) |
| Núcleo | 6.8.0-146-generic |
| Arquitectura | arm64 |
| Instalación | desde cero, mínima, sin `openssh-server` inicial |
| Herramienta de auditoría | Lynis 3.0.9 (repositorio de la distribución) |

Máquina virtual (VMware Fusion) sobre macOS en Apple Silicon. El hipervisor es
indiferente: nada de lo que hay aquí depende de él.

La arquitectura arm64 sí importa en un punto: los paquetes vienen de
`ports.ubuntu.com` en vez de `archive.ubuntu.com`, cosa que se nota al leer la traza
de APT y al revisar `ubuntu.sources`.

## Cómo trabajé

```
   Mac (cliente)                        VM Ubuntu (sistema auditado)
   ─────────────                        ───────────────────────────
   ~/hardening-lab/scripts/  ──scp──▶   ~/faseN.sh
   ~/hardening-lab/reports/  ◀──scp──   /opt/hardening-lab/reports/
                             ◀─ssh──▶   puerto 2222, solo clave
```

Hice todo el trabajo por SSH desde el Mac, nunca desde la consola de la VM. No es un
detalle cosmético: obliga a que cada fase deje el acceso remoto funcionando. Un
bastionado que solo se puede aplicar con la consola delante no sirve para un servidor
real.

De ahí salen dos decisiones del laboratorio:

- La fase 3 verifica la configuración efectiva de SSH con `sshd -T` antes de recargar
  el servicio.
- La fase 4 aplica las reglas del cortafuegos con un temporizador de reversión
  automática de 90 segundos (`systemd-run --on-active=90`). Si las reglas dejan
  fuera, el sistema las retira solo y el acceso vuelve sin tocar nada.

## Acceso

Tras la fase 3:

- Puerto 2222 (gobernado por `ssh.socket`, no por `sshd_config`)
- Solo clave pública; autenticación por contraseña desactivada
- Acceso directo de `root` desactivado
- Alias en `~/.ssh/config` del Mac:

```
Host lab
    HostName <ip-de-la-vm>
    User jonathas
    Port 2222
    IdentityFile ~/.ssh/hardening-lab
```

Con eso, `ssh lab` y `scp lab:/ruta/fichero .` funcionan sin argumentos. (`scp` usa
`-P` mayúscula para el puerto, no `-p`. Me costó un rato darme cuenta.)

## Rutas

| Ruta | Contenido |
|---|---|
| `/opt/hardening-lab/reports/` | Informes de Lynis y comparativas |
| `/opt/hardening-lab/backups/` | Copia con marca de tiempo de cada fichero antes de modificarlo |
| `/opt/hardening-lab/revertir-faseN.sh` | Script de reversión generado por cada fase |
| `/opt/hardening-lab/faseN.log` | Registro completo de la ejecución de cada fase |

Cada fase guarda copia de lo que toca antes de tocarlo y genera su propio script de
reversión. Ninguna fase depende de otra para poder deshacerse.

## Reproducirlo

1. Ubuntu Server 24.04 LTS recién instalado, con `openssh-server`.
2. Copiar `scripts/` a la máquina.
3. Ejecutar las fases en orden, una a una, leyendo la salida de cada una antes de
   seguir:

```bash
sudo bash fase1-baseline.sh      # mide: no toca nada
sudo bash fase2-identidades.sh
sudo bash fase3-ssh.sh           # cambia el puerto a 2222: no cerrar la sesión
sudo bash fase4-firewall.sh      # 90 segundos para confirmar que el acceso sigue
sudo bash fase5-kernel.sh
sudo bash fase6-auditoria.sh
sudo bash fase7-medicion.sh      # vuelve a medir y compara
sudo bash fase8-correccion.sh    # corrige las regresiones de la fase 6
sudo bash fase7-medicion.sh      # y mide otra vez
sudo bash fase9-validacion.sh    # resiliencia bajo carga + escaneo externo
```

Conviene no encadenarlas en un solo script: tres de los seis fallos documentados en
[`fallos-encontrados.md`](fallos-encontrados.md) los detecté leyendo la verificación
de una fase antes de lanzar la siguiente, y en una ejecución desatendida habrían
pasado desapercibidos.

### Variables

| Variable | Fase | Por defecto | Para qué |
|---|---|---|---|
| `PUERTO_SSH` | 3, 4 | `2222` | Puerto de SSH |
| `ESPERA_CONFIRMACION` | 4 | `90` | Segundos antes de la reversión automática del cortafuegos |
| `MODO` | 8 | `restringir` | `restringir` deja Postfix en loopback; `eliminar` lo desinstala |

## Advertencia

Es un laboratorio. Los scripts cambian la configuración de SSH, el cortafuegos y el
núcleo. No conviene ejecutarlos sobre nada que importe sin leerlos antes y sin tener
forma de acceder por consola.
