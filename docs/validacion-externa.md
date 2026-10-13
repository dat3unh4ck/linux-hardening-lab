# Validación: resiliencia bajo carga y vista desde fuera

Las fases 1 a 8 comprueban el sistema **desde dentro**: `sshd -T`, `sysctl -n`,
`ss -tln`, `systemctl is-active`. Esa mirada tiene dos puntos ciegos, y la
fase 9 existe para cubrirlos.

1. **¿El endurecimiento ha degradado la estabilidad?** Limitar el núcleo,
   prohibir los volcados de memoria y poner topes en `limits.conf` tiene un
   coste. Si bajo carga real el sistema se vuelve inestable o pierde eventos de
   auditoría, el bastionado ha cambiado un riesgo por otro.
2. **¿Lo que se ve desde fuera coincide con lo que creemos tener?** `ss -tln`
   dice en qué puertos escucha el sistema. No dice cuáles son *alcanzables*:
   eso lo decide el cortafuegos, y solo se sabe mirando desde otra máquina.

---

## 1. Resiliencia bajo carga

`stress-ng` con 2 trabajadores de CPU y 2 de memoria de 878 MB cada uno,
durante 60 segundos, sobre una VM de 2 núcleos.

```
carga 0.36 → 2.55          (~127 % de saturación sobre 2 núcleos)
12 muestras cada 5 s       12 veces "todo en pie"

ssh=active  nftables=active  auditd=active  fail2ban=active
reglas nftables: 20 → 20
núcleo: sin OOM, sin oops, sin pánicos
auditd: 0 eventos perdidos
```

Tres decisiones de método que cambian lo que esta prueba vale:

**Se comprueban los servicios DURANTE la carga, no al terminar.** Si un
servicio cae y systemd lo reinicia, al final de la prueba estará `active` y la
caída no deja rastro visible. El muestreo cada cinco segundos es lo único que
la detectaría.

**Se lee el anillo del núcleo acotado a la ventana de la prueba**
(`dmesg --since`), buscando OOM killer, oops y pánicos. Ahí es donde aparece si
el endurecimiento del kernel rompe algo bajo presión.

**Se le pregunta a auditd cuántos eventos ha perdido.** Es el resultado que más
dudas me daba: auditd descartando eventos bajo carga es un fallo clásico y
silencioso — el sistema sigue en pie, los logs siguen apareciendo, y los que
faltan no los reclama nadie. Cero pérdidas es lo que hace que la trazabilidad
de la fase 6 sea real y no aparente.

La carga se dimensiona desde la memoria **disponible** en vez de fijar
`--vm-bytes 1G`. Pedir un gigabyte a una VM pequeña no mide resiliencia: invoca
al OOM killer y lo único que demuestra es que la máquina tenía poca RAM.

---

## 2. Vista desde fuera: un resultado inesperado

Escaneo desde el Mac, en la misma red local que la VM.

### Barrido rápido

```
sudo nmap -sS -Pn -p 1-10000 -T4 --reason --min-rate 2000 --max-retries 1 <ip>

All 10000 scanned ports are in ignored states.
Not shown: 10000 filtered tcp ports (no-response)
Nmap done: 1 IP address (1 host up) scanned in 10.73 seconds
```

**Ningún puerto abierto. Ni siquiera el 2222**, donde SSH estaba aceptando
conexiones en ese mismo momento.

### Sondeo único, noventa segundos después

```
sudo nmap -sS -Pn -p 2222 --reason <ip>

PORT     STATE SERVICE      REASON
2222/tcp open  EtherNetIP-1 syn-ack ttl 64

Nmap done: 1 IP address (1 host up) scanned in 0.54 seconds
```

Misma máquina, mismas reglas, resultado opuesto.

### La causa

La regla de SSH de la fase 4:

```nft
tcp dport 2222 ct state new limit rate 30/minute burst 10 packets accept
```

En nftables, cuando se supera el límite la regla **deja de coincidir** y el
paquete continúa bajando por la cadena hasta el descarte final. Un barrido a
2.000 paquetes por segundo vacía el cubo de 10 del `burst` de inmediato, y a
partir de ahí los SYN nuevos al 2222 se descartan en silencio.

La sesión SSH en curso no se entera porque viaja por `ct state established`,
que coincide con la primera regla de la cadena y nunca llega al limitador.

### Qué significa, y qué no

Ese efecto **no se diseñó**. La regla se puso para frenar la fuerza bruta; que
además esconda el servicio de los escáneres rápidos es un efecto secundario que
solo aparece mirando desde fuera.

Conviene no venderlo por más de lo que es:

- **No es seguridad por oscuridad.** Un atacante paciente lo encuentra:
  escanear despacio cuesta medio segundo, como se ve arriba.
- **Sí reduce el ruido automatizado**, que es la mayor parte de lo que llama a
  la puerta de un servidor expuesto a internet.
- **Tiene un coste operativo real**: el inventario de activos propio también se
  lo pierde. Un barrido de descubrimiento sobre esta red reportaría este host
  como una máquina sin servicios. Eso es un problema cuando el que escanea es
  el equipo que administra la máquina.

---

## 3. Sobre la propia herramienta de escaneo

Dos tropiezos del camino que valen tanto como el resultado.

**El primer escaneo iba a tardar dos horas.** Se lanzó sin `sudo`, y sin
privilegios nmap no puede fabricar paquetes en crudo: cae al escaneo por
conexión (`-sT`), que pide al sistema operativo una conexión completa a cada
puerto. Contra una política `drop`, cada intento espera el tiempo de espera del
núcleo. `--min-rate` no sirve de nada ahí, porque le pone un suelo de velocidad
a algo cuyo ritmo gobierna el sistema operativo, no nmap. Con `sudo` y `-sS`:
10 segundos.

**Un cortafuegos que descarta en silencio hace que escanearlo salga caro.**
nmap tiene control de congestión: cuando deja de recibir respuestas asume
pérdida de paquetes y reduce la cadencia. Contra `drop` ese silencio no es
congestión, es la política — pero nmap no puede distinguirlo y frena igual.
Es la diferencia práctica entre `drop` y `reject`, que suele explicarse en
abstracto y aquí se mide en horas frente a minutos.
