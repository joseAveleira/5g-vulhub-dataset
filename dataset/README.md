# Dataset de prueba de concepto — Ataque 5G (Tomcat CVE-2017-12615)

Pequeño conjunto de datos etiquetado generado a partir de una **captura real tomada
desde el core de una red privada 5G SA** (OpenAirInterface / Firecell Labkit 40).
Demuestra que el tráfico de un servicio vulnerable, encaminado por la red 5G, es
**observable y reconstruible desde el core** y permite construir datasets etiquetados
para evaluar sistemas de detección de intrusiones (IDS).

> Regla de fidelidad: **solo se reporta lo que se captura de verdad.** El etiquetado se
> ancla en el contenido observado (la firma del ataque), no en marcas de tiempo externas.

## Escenario

- **Núcleo 5G:** OAI 5G SA (Firecell Labkit 40). Captura `linux-cooked`, 7616 tramas, 252 s, ~8,2 MB.
- **Ataque:** Apache Tomcat **CVE-2017-12615** — escritura arbitraria de un `.jsp` (método PUT)
  y ejecución remota de código (RCE). Secuencia observada: `PUT /shell.jsp/` → `201 Created`;
  `GET /shell.jsp` → `200`; `GET /shell.jsp?cmd=...` (`whoami`, `ls`, `dir`) → `200` con la
  salida de los comandos. Atacante automatizado con `python-requests`.
- **Planos 5G presentes:** plano de usuario en N3 (GTP-U, UDP 2152, gNB↔UPF) y plano de
  control en N2 (NGAP/SCTP, puerto 38412, AMF↔gNB).

## Ficheros

| Fichero | Contenido |
|---|---|
| `dataset_5g_tomcat_packets.csv` | Una fila por paquete (tras de-encapsular GTP-U): tiempo, tamaño, plano, 5-tupla interna, protocolo y **etiqueta**. |
| `dataset_5g_tomcat_flows.csv` | Una fila por flujo bidireccional (5-tupla interna): nº de paquetes, bytes, duración, tamaño medio y etiqueta. |

### Etiquetas

| Etiqueta | Plano (interfaz) | Descripción | Paquetes | Flujos |
|---|---|---|---:|---:|
| `attack_tomcat_rce` | usuario (N3) | Ataque CVE-2017-12615 (atacante ↔ servicio Tomcat en el UE 5G). | 196 | 9 |
| `benign_background` | usuario (N3) | Tráfico benigno de fondo del UE (QUIC/TLS/DNS hacia 34 destinos públicos). | 2350 | 63 |
| `control_ngap` | control (N2) | Señalización NGAP sobre SCTP. | 64 | 1 |

Quedan fuera del dataset 4976 fragmentos IP del túnel GTP-U (plano de usuario) y 30 tramas
internas del core (loopback). Total de la captura: 7616 tramas.

## Reproducción

```bash
# Requiere tshark (Wireshark) en el PATH y Python 3.8+
python generar_dataset_5g.py ataque_tomcat_5g_2.pcap   # genera los CSV en dataset/
python figura_timeline.py                              # genera images/captura_timeline_5g.png
```

Las direcciones/puertos del escenario son parametrizables al inicio de `generar_dataset_5g.py`.

## Cita

Trabajo presentado en las XLVII Jornadas de Automática (CEA), 2026.
Licencia de los artefactos: a definir por los autores.
