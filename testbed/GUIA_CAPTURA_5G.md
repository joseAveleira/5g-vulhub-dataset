# Guía de captura desde el core 5G (prueba de concepto)

Objetivo: demostrar, con datos reales, que el tráfico hacia los servicios vulnerables
**es observable desde el core 5G**, generando material útil para ataques y datasets.
Regla de oro: **solo se reporta lo que se captura de verdad. No se inventa nada.**
Con **una sola captura corta** ya basta para la prueba de concepto.

## 0. Pre-requisitos (testbed operativo)
- Firecell Labkit 40 (core OAI 5G SA) encendido y radio (USRP B210) activa.
- Cradlepoint R1900 con SIM registrada en el core; conectado por Ethernet al MiniPC.
- MiniPC Blackview con Docker Desktop y los contenedores levantados.
- Un equipo "cliente/atacante" conectado a la red 5G privada (puede ser otro UE con SIM).

## 1. Levantar y validar los servicios (MiniPC)
```
docker compose up -d
powershell -ExecutionPolicy Bypass -File .\test-contenedores.ps1
```
Guarda/copia la salida del script -> es la **Tabla de validación** del artículo
(servicio, puerto, comprobación HTTP/TCP, estado; total X/19 accesibles).

## 2. Identificar el punto de captura en el core
En el core/OAI, lista las interfaces antes de capturar:
```
ip a            # o:  tcpdump -D
```
Interfaces 5G de interés:
- **N2 (control):** señalización **NGAP sobre SCTP** (gNB <-> AMF).
- **N3 (usuario):** tráfico **tunelizado GTP-U**, normalmente **UDP 2152** (gNB <-> UPF).
- **N6 (salida):** tráfico de usuario **ya sin túnel** (UPF -> red de datos / MiniPC).

## 3. Arrancar tcpdump en el core (elige según lo que quieras mostrar)
```
# Señalización de control (NGAP/SCTP) en N2
tcpdump -i <if_n2> -w n2_ngap.pcap 'sctp'

# Tráfico de usuario tunelizado (GTP-U) en N3
tcpdump -i <if_n3> -w n3_gtpu.pcap 'udp port 2152'

# Tráfico de aplicación ya sin túnel en N6 (ajusta IP/puerto del servicio)
tcpdump -i <if_n6> -w n6_app.pcap 'host <IP_MiniPC_en_5G> and tcp port <puerto_servicio>'
```
(El Labkit incluye Wireshark; también puedes capturar con la GUI.)

## 4. Generar tráfico desde el cliente conectado a la 5G
Para cada servicio elegido, dos trazas claramente diferenciadas:
- **Benigna:** acceso normal (p. ej. abrir la web del servicio / `curl http://<IP>:<puerto>/`).
- **Maliciosa:** la interacción asociada al CVE (consulta el README del escenario en
  Vulhub para el PoC exacto; no hace falta detallar el payload en el artículo).

Anota la hora de inicio/fin de cada acción para poder etiquetar después.

## 5. Parar y guardar
`Ctrl+C` en tcpdump. Nombra los `.pcap` por servicio y escenario
(p. ej. `grafana_43798_malicioso_n3.pcap`). Repite con 2-3 servicios si da tiempo
(uno web + uno TCP como Redis/MySQL da variedad).

## 6. Qué traer para escribir los Resultados
Por cada captura, apunta:
- servicio, puerto, tipo (benigno/malicioso),
- punto/interfaz de captura (N2 / N3 / N6),
- protocolos observados (GTP-U, SCTP/NGAP, HTTP, TCP...),
- nº de paquetes, nº de flujos, tamaño del `.pcap`, duración,
- 1-2 pantallazos de Wireshark (que se vea el GTP-U y/o NGAP).

Con eso relleno las plantillas ya marcadas como PENDIENTE en `main.tex`
(`tab:validacion`, `tab:captura`, `fig:captura`).

## Aviso de fidelidad (para el etiquetado)
La publicación de los servicios mediante **mapeo de puertos** en el MiniPC introduce
**NAT** (cambia IP/puerto origen-destino). Tenlo en cuenta al etiquetar las trazas:
el puerto/dirección visto en el core puede no ser el del contenedor.
