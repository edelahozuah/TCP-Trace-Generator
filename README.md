# TCP Trace Generator

[English](#english) | [Español](#español)

---

<a name="english"></a>
## English

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![DOI](https://zenodo.org/badge/DOI/ZENODO_DOI_PENDIENTE.svg)](https://doi.org/ZENODO_DOI_PENDIENTE)

### Overview
`tcp_trace_generator.py` is a Python script based on Scapy that simulates a TCP connection. It generates a PCAP file containing the captured traffic and a CSV log detailing the internal state of the simulation (cwnd, ssthresh, RTO, etc.).

It implements **TCP Reno** (Slow Start, Congestion Avoidance, Fast Retransmit, Fast Recovery) and supports **TCP Tahoe**. It also features a special **Classroom Mode** designed for educational purposes, which enforces discrete time slots and predictable behavior.

### Requirements
*   Python 3
*   Scapy (`pip install scapy`)

### Usage
```bash
python tcp_trace_generator.py [segments] [options]
```

### Installation and tests
The `Makefile` creates a virtual environment in `venv/`, installs the pinned dependencies and runs the test suite:
```bash
make install   # creates venv/ and installs requirements.txt
make test      # runs the unit tests in tests/ (unittest)
make clean     # removes venv/, test_output/ and generated files
```
The tests run the generator end to end and write their output to `test_output/`.

> **Note:** the test suite is currently under review (see the `v1.0-release` pull request); it does not pass on this version.

### Parameters

| Argument | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `segments` | int | **Required** | Total number of data segments to send from client to server. |
| `--loss` | str | `""` | Comma-separated list of segment indices (1-based) to simulate as lost (dropped). Ranges are supported (e.g., `5,8-10`). |
| `--output`, `-o` | str | `tcp_reno_gen.pcap` | Filename for the output PCAP capture file. |
| `--rto-log` | str | `rto_log.txt` | Filename for the output CSV log file tracking internal TCP state. |
| `--initial-rto` | float | `1.0` | Initial Retransmission Timeout (RTO) value in seconds (Standard mode only). |
| `--accept-out-of-order` | flag | `False` | If set, the server accepts and buffers out-of-order segments (SACK-like behavior). If not set, they are discarded. |
| `--client-isn` | int | Random | Initial Sequence Number (ISN) for the Client. |
| `--server-isn` | int | `0` | Initial Sequence Number (ISN) for the Server. |
| `--client-mss` | int | `1460` | Maximum Segment Size (MSS) for the Client (sender). |
| `--server-mss` | int | `1460` | Maximum Segment Size (MSS) for the Server. |
| `--ssthresh` | int | `64` | Initial Slow Start Threshold (in segments). |
| `--client-rwnd` | int | `65535` | Initial Receiver Window (rwnd) for the Client. |
| `--server-rwnd` | int | `65535` | Initial Receiver Window (rwnd) for the Server (Advertised Window). |
| `--tcp-variant` | str | `reno` | TCP Congestion Control variant: `reno` or `tahoe`. |
| `--classroom` | flag | `False` | Enables **Classroom Mode**: discrete time slots, fixed RTO, fixed latencies, formatted for teaching. |
| `--classroom-rto-slots`| int | `3` | (Classroom Mode only) The fixed RTO value expressed in number of time slots. |

### Operating Modes

#### 1. Standard Mode (Default)
Simulates a realistic TCP implementation, following standard RFCs (closest to Linux behavior).
*   **Continuous Time:** Events occur at precise floating-point timestamps based on processing and propagation delays. No artificial quantization.
*   **Dynamic RTO:**
    *   Calculated per RFC 6298 using RTT samples from the simulation.
    *   Update logic: `SRTT = 7/8 SRTT + 1/8 SampleRTT`, `RTTVAR = 3/4 RTTVAR + 1/4 |SampleRTT - SRTT|`.
    *   Formula: `RTO = SRTT + 4 * RTTVAR` (min 0.2s).
    *   **Karn's Algorithm:** RTT samples are ignored for retransmitted segments to prevent ambiguous measurements.
*   **ACK Generation Rules:**
    *   **Delayed ACK:** Standard mechanism. Waits for 2 full segments or `DELAYED_ACK_TIMEOUT` (0.2s).
    *   **Immediate ACK:** Sent immediately on Out-of-Order arrival (Duplicate ACKs) to trigger Fast Retransmit strategies.
*   **Concurrency:** Packets are processed with varying inter-arrival times; bursts are processed as fast as the "wire" allows.

#### 2. Classroom Mode (`--classroom`)
Designed to generate clean, predictable traces for ease of analysis in manual exercises.
*   **Discrete Time Slots:** The simulation runs in discrete steps of `Slot_Duration`. All events (transmission start, arrival) align to the grid.
    *   `Slot_Duration = RTT / 2`
*   **Strict Serialization:** Transmission of multiple packets is serialized across consecutive slots. A sender cannot "burst" multiple packets in the same time instant.
*   **Fixed Latency:** Propagation delay is fixed at `RTT / 4`.
*   **RTO Constraints:**
    *   The RTO is **Fixed** and does not adapt.
    *   Value: `classroom-rto-slots * Slot_Duration` (Default: 3 slots).
    *   The timer restarts strictly on every new acknowledgment.
*   **ACK Generation Rules:**
    *   **Delayed ACK:** Enabled. The receiver waits for 2 full segments or a timeout.
    *   **Timeout Alignment:** The Delayed ACK timer is set to exactly `1 Slot`.
    *   **Immediate ACK on Gap Fill:** Crucial for exercises. If an out-of-order segment arrives and "fills a gap" in the receive buffer, an **Immediate Cumulative ACK** is generated, bypassing the Delayed ACK timer. This ensures fast recovery responsiveness in the traces.
    *   **Determinism:** Arrival events are prioritized over Timer events when occurring in the same slot.

### Examples

#### 1. Basic Simulation (Standard Mode)
Send 20 segments with no loss.
```bash
python tcp_trace_generator.py 20
```

#### 2. Fast Retransmit Scenario
Send 20 segments, losing segment 10.
```bash
python tcp_trace_generator.py 20 --loss 10
```

#### 3. Classroom Exercise (Complex)
Classroom mode with discrete slots, fixed RTO (4 slots), custom ISNs, small MSS, and packet loss to demonstrate recovery.
```bash
python tcp_trace_generator.py 14 \
  --classroom \
  --classroom-rto-slots 4 \
  --loss 11 \
  --accept-out-of-order \
  --client-isn 1024 --server-isn 2047 \
  --client-mss 64 --server-mss 128 \
  --ssthresh 2
```

### Authors
Departamento de Automática, Universidad de Alcalá:
*   Enrique de la Hoz — [ORCID 0000-0003-4837-3837](https://orcid.org/0000-0003-4837-3837)
*   Sandra Machado Zurita — [ORCID 0000-0002-5746-3597](https://orcid.org/0000-0002-5746-3597)
*   Luis de la Cruz Piris — [ORCID 0000-0002-9570-2851](https://orcid.org/0000-0002-9570-2851)

### How to cite
If you use this tool, please cite it (APA, generated from [`CITATION.cff`](CITATION.cff)):

> de la Hoz, E., Machado Zurita, S., & de la Cruz Piris, L. (2026). *TCP Trace Generator* (Version 1.0.0) [Computer software]. Universidad de Alcalá. https://doi.org/ZENODO_DOI_PENDIENTE

### License
This project is released under the [MIT License](LICENSE).
Copyright (c) 2025 Enrique de la Hoz, Sandra Machado Zurita, Luis de la Cruz Piris.

---

<a name="español"></a>
## Español

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE) [![DOI](https://zenodo.org/badge/DOI/ZENODO_DOI_PENDIENTE.svg)](https://doi.org/ZENODO_DOI_PENDIENTE)

### Descripción General
`tcp_trace_generator.py` es un script de Python basado en Scapy que simula una conexión TCP completas. Genera un archivo PCAP con el tráfico capturado y un log CSV que detalla el estado interno de la simulación (cwnd, ssthresh, RTO, etc.).

Implementa los algoritmos **TCP Reno** (Slow Start, Congestion Avoidance, Fast Retransmit, Fast Recovery) y soporta **TCP Tahoe**. Además, incluye un **Modo Classroom (Docente)** diseñado para la enseñanza, que fuerza el uso de ranuras de tiempo discretas y comportamientos predecibles.

### Requisitos
*   Python 3
*   Scapy (`pip install scapy`)

### Uso
```bash
python tcp_trace_generator.py [segmentos] [opciones]
```

### Instalación y pruebas
El `Makefile` crea un entorno virtual en `venv/`, instala las dependencias fijadas y ejecuta la suite de pruebas:
```bash
make install   # crea venv/ e instala requirements.txt
make test      # ejecuta las pruebas unitarias de tests/ (unittest)
make clean     # elimina venv/, test_output/ y los ficheros generados
```
Las pruebas ejecutan el generador de principio a fin y escriben su salida en `test_output/`.

> **Nota:** la suite de pruebas está actualmente en revisión (véase el pull request `v1.0-release`); no pasa en esta versión.

### Parámetros

| Argumento | Tipo | Por defecto | Descripción |
| :--- | :--- | :--- | :--- |
| `segmentos` | int | **Requerido** | Número total de segmentos de datos a enviar del cliente al servidor. |
| `--loss` | str | `""` | Lista separada por comas de índices de segmentos (base-1) que se perderán. Soporta rangos (ej. `5,8-10`). |
| `--output`, `-o` | str | `tcp_reno_gen.pcap` | Nombre del archivo PCAP de salida. |
| `--rto-log` | str | `rto_log.txt` | Nombre del archivo de log CSV para trazar el estado interno de TCP. |
| `--initial-rto` | float | `1.0` | Valor inicial del Retransmission Timeout (RTO) en segundos (Solo modo estándar). |
| `--accept-out-of-order` | flag | `False` | Si se activa, el servidor acepta y almacena en buffer segmentos fuera de orden. Si no, los descarta. |
| `--client-isn` | int | Aleatorio | Número de Secuencia Inicial (ISN) del Cliente. |
| `--server-isn` | int | `0` | Número de Secuencia Inicial (ISN) del Servidor. |
| `--client-mss` | int | `1460` | Tamaño Máximo de Segmento (MSS) del Cliente (emisor). |
| `--server-mss` | int | `1460` | Tamaño Máximo de Segmento (MSS) del Servidor. |
| `--ssthresh` | int | `64` | Umbral inicial de Slow Start (en segmentos). |
| `--client-rwnd` | int | `65535` | Ventana de Recepción inicial (rwnd) del Cliente. |
| `--server-rwnd` | int | `65535` | Ventana de Recepción inicial (rwnd) del Servidor (Ventana Anunciada). |
| `--tcp-variant` | str | `reno` | Variante de TCP: `reno` o `tahoe`. |
| `--classroom` | flag | `False` | Activa el **Modo Classroom**: tiempo discreto, RTO fijo, latencias fijas, diseñado para ejercicios de clase. |
| `--classroom-rto-slots`| int | `3` | (Solo Modo Classroom) El valor fijo del RTO expresado en número de ranuras de tiempo. |

### Modos de Funcionamiento
#### 1. Modo Estándar (Por defecto)
Simula una implementación TCP realista, siguiendo los RFCs estándar (comportamiento cercano a Linux).
*   **Tiempo Continuo:** Los eventos ocurren en instantes precisos (floating-point) basados en retardos de procesamiento y propagación. Sin cuantificación artificial.
*   **RTO Dinámico:**
    *   Calculado según RFC 6298 usando las muestras de RTT de la simulación.
    *   Lógica: `SRTT = 7/8 SRTT + 1/8 MuestraRTT`, `RTTVAR = 3/4 RTTVAR + 1/4 |MuestraRTT - SRTT|`.
    *   Fórmula: `RTO = SRTT + 4 * RTTVAR` (mínimo 0.2s).
    *   **Algoritmo de Karn:** Las muestras de RTT se ignoran para segmentos retransmitidos para evitar mediciones ambiguas.
*   **Reglas de Generación de ACKs:**
    *   **ACK Retardado:** Mecanismo estándar. Espera confirmación de 2 segmentos o un timeout de `DELAYED_ACK_TIMEOUT` (0.2s).
    *   **ACK Inmediato:** Se envía inmediatamente al recibir segmentos fuera de orden (Duplicate ACK) para disparar el Fast Retransmit.
*   **Concurrencia:** Los paquetes se procesan con tiempos de llegada variables; las ráfagas ocurren tan rápido como la "red" lo permita.

#### 2. Modo Classroom (Docente) (`--classroom`)
Diseñado para generar trazas limpias y predecibles, ideales para realizar ejercicios a mano.
*   **Ranuras de Tiempo Discretas (Slots):** La simulación avanza en pasos fijos de `Duración_Slot`. Todos los eventos (inicio de tx, llegada) se alinean a la rejilla.
    *   `Duración_Slot = RTT / 2`
*   **Serialización Estricta:** La transmisión de múltiples paquetes se serializa en ranuras consecutivas. Un emisor no puede enviar una "ráfaga" instantánea.
*   **Latencia Fija:** El retardo de propagación (ida) se fija en `RTT / 4`.
*   **Restricciones de RTO:**
    *   El RTO es **Fijo** y no se adapta con medidas.
    *   Valor: `classroom-rto-slots * Duración_Slot` (Por defecto: 3 ranuras).
    *   El temporizador se reinicia estrictamente con cada nuevo asentimiento recibido.
*   **Reglas de Generación de ACKs:**
    *   **ACK Retardado:** Activado. El receptor espera 2 segmentos completos o un timeout.
    *   **Alineación del Timeout:** El temporizador de ACK retardado dura exactamente `1 Slot`.
    *   **ACK Inmediato por Relleno de Huecos:** Fundamental para ejercicios. Si llega un segmento desordenado que "rellena un hueco" en el buffer de recepción, se genera un **ACK Acumulativo Inmediato**, ignorando el temporizador. Esto facilita ver la recuperación rápida en la traza.
    *   **Determinismo:** Los eventos de llegada tienen prioridad sobre los temporizadores si ocurren en el mismo instante.

### Ejemplos

#### 1. Simulación Básica (Modo Estándar)
Enviar 20 segmentos sin pérdidas.
```bash
python tcp_trace_generator.py 20
```

#### 2. Escenario de Fast Retransmit
Enviar 20 segmentos, perdiendo el segmento 10.
```bash
python tcp_trace_generator.py 20 --loss 10
```

#### 3. Ejercicio de Clase (Complejo)
Modo docente con slots discretos, RTO fijo (4 slots), ISNs personalizados, MSS pequeños y pérdida de paquetes para ver la recuperación.
```bash
python tcp_trace_generator.py 14 \
  --classroom \
  --classroom-rto-slots 4 \
  --loss 11 \
  --accept-out-of-order \
  --client-isn 1024 --server-isn 2047 \
  --client-mss 64 --server-mss 128 \
  --ssthresh 2
```

### Autores
Departamento de Automática, Universidad de Alcalá:
*   Enrique de la Hoz — [ORCID 0000-0003-4837-3837](https://orcid.org/0000-0003-4837-3837)
*   Sandra Machado Zurita — [ORCID 0000-0002-5746-3597](https://orcid.org/0000-0002-5746-3597)
*   Luis de la Cruz Piris — [ORCID 0000-0002-9570-2851](https://orcid.org/0000-0002-9570-2851)

### Cómo citar
Si utilizas esta herramienta, cítala así (formato APA, generado a partir de [`CITATION.cff`](CITATION.cff)):

> de la Hoz, E., Machado Zurita, S., & de la Cruz Piris, L. (2026). *TCP Trace Generator* (Versión 1.0.0) [Software]. Universidad de Alcalá. https://doi.org/ZENODO_DOI_PENDIENTE

### Licencia
Este proyecto se distribuye bajo la [licencia MIT](LICENSE).
Copyright (c) 2025 Enrique de la Hoz, Sandra Machado Zurita, Luis de la Cruz Piris.
