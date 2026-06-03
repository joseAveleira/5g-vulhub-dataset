# 5g-vulhub-dataset

Banco de pruebas y conjunto de datos etiquetado para la generación de tráfico de
ciberseguridad en redes privadas 5G. El repositorio acompaña a una prueba de
concepto en la que un ataque a un servicio vulnerable, encaminado por una red
5G SA, se captura y se analiza desde el núcleo de red (core 5G).

A partir de la captura se construye un pequeño conjunto de datos etiquetado que
distingue tráfico de ataque, tráfico benigno de fondo y señalización de control,
útil para evaluar sistemas de detección de intrusiones (IDS) y modelos de
aprendizaje automático.

## Contenido

```
.
├── ataque_tomcat_5g_2.pcap     Captura tomada desde el core 5G SA (OAI / Firecell Labkit 40)
├── generar_dataset_5g.py       De-encapsula GTP-U, etiqueta el tráfico y genera los CSV
├── figura_timeline.py          Genera la cronología del tráfico capturado
├── dataset/
│   ├── dataset_5g_tomcat_packets.csv   Una fila por paquete, con etiqueta
│   ├── dataset_5g_tomcat_flows.csv     Una fila por flujo, con etiqueta
│   └── README.md                       Esquema y descripción del dataset
├── figures/
│   └── captura_timeline_5g.png Cronología (benigno / ataque / control N2)
└── testbed/
    ├── docker-compose.yml      Despliegue de los servicios vulnerables (Docker-Vulhub)
    ├── test-contenedores.ps1   Validación del despliegue (HTTP/TCP)
    └── GUIA_CAPTURA_5G.md       Guía de captura desde el core 5G
```

## Escenario

La captura corresponde a un ataque real contra **Apache Tomcat (CVE-2017-12615)**:
el método HTTP PUT permite escribir un archivo `.jsp` (un *webshell*) que después
se ejecuta, dando lugar a ejecución remota de código (RCE). La secuencia observada
en la traza es:

1. `PUT /shell.jsp/` que recibe `201 Created` (escritura del webshell).
2. `GET /shell.jsp` que recibe `200 OK` (el webshell queda accesible).
3. Sucesivas peticiones `GET /shell.jsp?cmd=...` (`whoami`, `ls`, `dir ...`) cuyas
   respuestas devuelven la salida de los comandos, lo que confirma el RCE.

El ataque, automatizado con `python-requests`, se origina en la red de datos y
alcanza el servicio alojado en el equipo conectado como terminal 5G (UE). El
tráfico viaja:

- **Plano de usuario (interfaz N3):** tunelizado mediante **GTP-U sobre UDP 2152**,
  entre la estación base (gNB) y la función de plano de usuario (UPF).
- **Plano de control (interfaz N2):** señalización **NGAP sobre SCTP**
  (puerto de servicio 38412 del AMF), entre el AMF y el gNB.

Al de-encapsular el túnel GTP-U, todo el ataque de capa de aplicación es
observable y reconstruible desde el core.

## Cómo funciona el código

### `generar_dataset_5g.py`

1. Invoca `tshark` para volcar, por paquete, los campos de interés (tiempo,
   tamaño, capas IP externa e interna, TEID de GTP, puertos, protocolo).
2. Detecta el túnel GTP-U y separa la capa interna (de-encapsulada) de la externa
   (transporte N3).
3. Asigna una etiqueta a cada paquete:
   - `attack_tomcat_rce`: flujo del ataque (atacante ↔ servicio Tomcat en el UE).
   - `benign_background`: tráfico benigno del UE (QUIC, TLS, DNS).
   - `control_ngap`: señalización NGAP/SCTP del plano de control (N2).
   - `gtpu_n3_fragment`: fragmentos IP del túnel GTP-U (acarreo, no muestras).
   - `mgmt_oai`: tráfico interno del core (loopback), excluido del dataset.
4. Escribe dos ficheros: uno por paquete y otro agregado por flujo bidireccional
   (5-tupla interna), con número de paquetes, bytes, duración y tamaño medio.

El etiquetado se ancla en el contenido observado (la firma del ataque), no en
marcas de tiempo externas, de modo que es reproducible.

### `figura_timeline.py`

Lee el CSV por paquete y dibuja una cronología en tres carriles (tráfico benigno,
ataque y control N2), que muestra cómo las tres clases coexisten en una única
captura. Genera `figures/captura_timeline_5g.png`.

## Requisitos y uso

- `tshark` (Wireshark) accesible en el PATH.
- Python 3.8 o superior (solo biblioteca estándar para generar el dataset;
  `matplotlib` para la figura).

```
python generar_dataset_5g.py ataque_tomcat_5g_2.pcap   # genera los CSV en dataset/
python figura_timeline.py                              # genera figures/captura_timeline_5g.png
```

Las direcciones y puertos del escenario son parámetros configurables al inicio de
`generar_dataset_5g.py`, por si se reutiliza con otra captura.

## Notas

- **Direccionamiento y NAT.** El servicio se publica en el anfitrión mediante
  mapeo de puertos, por lo que en el core se observa en la dirección asignada al UE
  y sobre un puerto traducido (NAT). Conviene tenerlo en cuenta al etiquetar.
- **Alcance.** Es una prueba de concepto sobre un único servicio y una captura
  corta, no un conjunto de datos completo. La captura incluye, además del ataque,
  tráfico benigno de fondo real del propio equipo (actualizaciones del sistema,
  telemetría, CDN y DNS) y la señalización de control de la red 5G.

## Cita

Trabajo presentado en las XLVII Jornadas de Automática (CEA), 2026.

## Licencia

A definir por los autores.
