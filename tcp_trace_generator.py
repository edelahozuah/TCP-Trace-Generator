import argparse
import heapq
import itertools
import math
import sys
import time
import random
import socket
from scapy.all import *
from scapy.utils import EDecimal

# Configuration Constants
MSS = 1460
RTT = 0.1  # Seconds
SRC_IP = "10.0.0.1"   # Default client address
DST_IP = "10.0.0.2"   # Default server address
SPORT = 12345         # Default client port
DPORT = 80            # Default server port
DELAYED_ACK_TIMEOUT = 0.2
MIN_RTO = 0.2
PROC_DELAY = 0.0001   # Processing delay before a host puts a segment on the wire (standard mode)
CLOSE_DELAY = RTT     # Time the client application waits after the last ACK before closing
SERVER_CLOSE_DELAY = 0.01  # Time between the server's ACK of the FIN and its own FIN (--close fin)
# RFC 6298 parameters used by the RTO estimator (standard mode)
RTO_ALPHA = 1.0 / 8
RTO_BETA = 1.0 / 4
RTO_K = 4
RTO_G = 0.1           # Clock granularity term of RTO = SRTT + max(G, K*RTTVAR)
SRC_MAC = "00:00:00:00:00:01"
DST_MAC = "00:00:00:00:00:02"

# Simulation Events
EVENT_SEND = 1
EVENT_ARRIVE_SERVER = 2
EVENT_ARRIVE_CLIENT = 3
EVENT_TIMEOUT = 4
EVENT_DELAYED_ACK = 5
EVENT_CLIENT_CLOSE = 6
EVENT_SERVER_CLOSE = 7

# Labels of the per-burst summary (--summary) in each language
SUMMARY_TEXTS = {
    'es': {'header': ['Rafaga', 'Tramas', 'Tiempo', 'Segmentos', 'Nuevos', 'Retransmitidos',
                      'EnVuelo', 'VC', 'Umbral', 'Modo'],
           'modes': {'SLOW_START': 'AL', 'CONGESTION_AVOIDANCE': 'EC', 'FAST_RECOVERY': 'RR'},
           'notes': ['Una fila por rafaga: segmentos de datos consecutivos del cliente sin ACK ni timeout entre ellos',
                     'Tramas: numeros de trama en el pcap (primera-ultima); Tiempo: instante de salida de la primera',
                     'Nuevos: segmentos enviados por primera vez; Retransmitidos: ya enviados antes',
                     'EnVuelo: (SND.NXT - SND.UNA) / MSS al salir el ultimo segmento de la rafaga',
                     'VC, Umbral y Modo: ventana de congestion (en segmentos), umbral y modo del emisor en ese instante',
                     'Modos: AL = arranque lento, EC = evitacion de congestion, RR = recuperacion rapida']},
    'en': {'header': ['Burst', 'Frames', 'Time', 'Segments', 'New', 'Retransmitted',
                      'InFlight', 'cwnd', 'ssthresh', 'Mode'],
           'modes': {'SLOW_START': 'SS', 'CONGESTION_AVOIDANCE': 'CA', 'FAST_RECOVERY': 'FR'},
           'notes': ['One row per burst: consecutive client data segments with no ACK or timeout in between',
                     'Frames: frame numbers in the pcap (first-last); Time: departure of the first one',
                     'New: segments sent for the first time; Retransmitted: already sent before',
                     'InFlight: (SND.NXT - SND.UNA) / MSS when the last segment of the burst leaves',
                     'cwnd, ssthresh and Mode: congestion window (segments), threshold and sender mode at that instant',
                     'Modes: SS = slow start, CA = congestion avoidance, FR = fast recovery']},
}


def parse_bandwidth(text):
    """Parse a bandwidth such as 1000000, 1M, 10Mbps, 512k or 1Gbit/s into bit/s."""
    s = str(text).strip().lower().replace(' ', '')
    for suffix in ('bit/s', 'bits/s', 'bps', 'b/s'):
        if s.endswith(suffix):
            s = s[:-len(suffix)]
            break
    mult = 1.0
    if s and s[-1] in 'kmg':
        mult = {'k': 1e3, 'm': 1e6, 'g': 1e9}[s[-1]]
        s = s[:-1]
    try:
        value = float(s) * mult
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid bandwidth: {text!r} (examples: 1000000, 1M, 10Mbps, 512k)")
    if value <= 0:
        raise argparse.ArgumentTypeError("bandwidth must be positive")
    return value

def parse_ssthresh(text, mss):
    """Initial ssthresh in segments: a plain number is segments (64); with a unit it is
    bytes (64K or 64KB = 65536 B, 65535B) and is converted to whole segments of `mss`."""
    s = str(text).strip().lower()
    if s.endswith('kb'):
        value, unit = s[:-2], 1024
    elif s.endswith('k'):
        value, unit = s[:-1], 1024
    elif s.endswith('b'):
        value, unit = s[:-1], 1
    else:
        value, unit = s, None
    try:
        n = int(value)
    except ValueError:
        raise ValueError(f"invalid ssthresh: {text!r} (examples: 64 segments, 64K, 65535B)")
    if n <= 0:
        raise ValueError("ssthresh must be positive")
    if unit is None:
        return n
    segments = n * unit // mss
    if segments < 1:
        raise ValueError(f"ssthresh {text!r} is smaller than one MSS ({mss} B)")
    return segments

class Event:
    _counter = itertools.count()  # FIFO tie-breaker for events with equal time and type

    def __init__(self, time, type, data):
        self.time = time
        self.type = type
        self.data = data
        self.order = next(Event._counter)

    def __lt__(self, other):
        if abs(self.time - other.time) < 1e-9:
            if self.type == other.type:
                return self.order < other.order
            return self.type < other.type
        return self.time < other.time

class TCPSimulation:
    def __init__(self, output_file, rto_log_file, total_segments, loss_list, initial_rto=1.0, accept_ooo=False, 
                 client_isn=None, server_isn=None, client_mss=1460, server_mss=1460, ssthresh=64,
                 client_rwnd=65535, server_rwnd=65535, tcp_variant='reno', classroom=False, classroom_rto_slots=3,
                 diagram_file=None, diagram_lang='es',
                 client_ip=SRC_IP, server_ip=DST_IP, client_port=SPORT, server_port=DPORT,
                 close='none', bandwidth=None, summary_file=None, rtt_log_file=None, start_time=None):
        self.output_file = output_file
        self.diagram_file = diagram_file
        self.diagram_lang = diagram_lang
        self.lang = diagram_lang
        self.rto_log_file = rto_log_file
        self.summary_file = summary_file
        self.rtt_log_file = rtt_log_file
        self.total_segments = total_segments
        self.loss_list = set(loss_list)
        self.accept_ooo = accept_ooo

        self.client_ip = client_ip
        self.server_ip = server_ip
        self.client_port = client_port
        self.server_port = server_port

        self.mss = client_mss
        self.server_mss = server_mss
        self.client_rwnd = client_rwnd
        self.server_rwnd = server_rwnd
        self.tcp_variant = tcp_variant.lower()

        self.classroom = classroom
        self.classroom_rto_slots = classroom_rto_slots
        self.slot_duration = RTT / 2.0

        # Link serialization (standard mode): each host has one link and the
        # frames it sends are serialized one after another at `bandwidth` bit/s.
        self.bandwidth = bandwidth
        self.link_free = {'client': 0.0, 'server': 0.0}

        # Connection close: 'none' (capture ends after the last ACK), 'fin'
        # (FIN, ACK, FIN, ACK) or 'fin3' (FIN, FIN+ACK, ACK)
        self.close_mode = close
        self.closing = False        # Client has sent (or scheduled) its FIN
        self.client_fin_seq = None  # Sequence number of the client's FIN
        self.server_fin_seq = None  # Sequence number of the server's FIN

        # Per-burst summary (--summary): one entry per data segment sent, with
        # the sender state when it left; consecutive entries with the same
        # burst id form a burst (see _write_summary)
        self.burst_id = 0
        self.summary_entries = []
        self._summary_seen = set()

        # Diagram data (classroom mode): every segment with its send time, the
        # sender's cwnd after each ACK, and the retransmission timer behind each
        # lost segment. Rendered by render_classroom_svg().
        self.diagram_segments = []   # {time, side, seq, ack, flags, window, mss, data, lost, retrans}
        self.diagram_cwnd = []       # {time, text, mode}
        self.diagram_timers = []     # {seq, send_time} for every lost segment
        self.diagram_timer_log = []  # (armed_at, expiry) for every (re)start of the RTO timer
        self.diagram_timeouts = []   # times at which the RTO timer actually expired
        self.timer_armed_at = 0.0
        self._diagram_sent_seqs = set()
        
        self.events = []
        self.packets = []
        self.current_time = 0.0
        # Absolute time of the SYN in whole seconds; every timestamp is rounded to
        # the microsecond relative to it, so the relative times (Wireshark's Time
        # column) never depend on when the script runs, and a fixed --start-time
        # makes the pcap reproducible byte for byte.
        self.base_timestamp = int(time.time()) if start_time is None else int(start_time)

        # RTO Log
        self.rto_log_handle = open(self.rto_log_file, "w")
        self.rto_log_handle.write("Time,Event,RTO,Cwnd,CwndCnt,Rwnd,Ssthresh,Mode,Seq,Ack\n")

        # Connection State
        if client_isn is not None:
            self.seq_start = client_isn
        else:
            self.seq_start = random.randint(500, 5000)

        if server_isn is not None:
            self.ack_start = server_isn
        else:
            self.ack_start = 0 # Default if not specified

        # Sequence number of the next byte the server would send (its SYN uses ack_start)
        self.server_seq = self.ack_start + 1

        # RTT / RTO log (--rtt-log): every RTT sample and RTO computation
        self.rtt_log_handle = None
        if self.rtt_log_file:
            self.rtt_log_handle = open(self.rtt_log_file, "w")
            self._write_rtt_log_header()
        
        # Sender State
        self.cwnd = 1 # In segments (Integer)
        self.cwnd_cnt = 0 # Counter for CA
        self.rwnd = server_rwnd # Initial Sender's view of Receiver Window (from Server)
        self.ssthresh = ssthresh # High initial value
        self.seq_base = self.seq_start # Una
        self.next_seq = self.seq_start
        self.dup_acks = 0
        self.state = 'SLOW_START'
        
        if self.classroom:
            # Fixed RTO in slots * slot_duration
            self.rto = float(self.classroom_rto_slots) * self.slot_duration
        else:
            self.rto = initial_rto # Initial RTO
            
        self.srtt = None
        self.rttvar = None
        
        self.timer_active = False
        self.timer_expiry = 0.0
        self.rto_timer_txn = 0 # Generation ID for RTO timer
        
        self.segments_sent_count = 0 # To track unique data segments sent
        self.data_map = {} # seq -> segment_index (1..N)
        self.sent_times = {} # seq -> timestamp (for RTT measurement)
        self.highest_sent = self.seq_start # First seq never sent yet (SND.NXT high-water mark)
        
        # Classroom state
        self.last_tx_time_client = -1.0
        self.last_tx_time_server = -1.0
        
        # Receiver State
        self.expected_seq = self.seq_start
        self.pending_ack_count = 0
        self.delayed_ack_timer_active = False
        self.ack_timer_txn = 0 # Generation ID for delayed ack timer
        self.receive_buffer = set() # To store buffered out-of-order seq numbers
        
        # Stats
        self.segments_acked = 0

        self._log_event("Initialization")
        if self.classroom:
            self._log_rtt("Fixed RTO (classroom)",
                          calc=f"RTO = {self.classroom_rto_slots} slots * {self.slot_duration:.4f} s = {self.rto:.4f} s")
        else:
            self._log_rtt("Initial RTO", calc=f"RTO = {self.rto:.4f} s (--initial-rto); no RTT sample yet")

    def schedule(self, delay, type, data):
        heapq.heappush(self.events, Event(self.current_time + delay, type, data))
        
    def run(self):
        # 1. Handshake
        self._establish_connection()
        
        # 2. Main Loop
        while (self.segments_acked < self.total_segments) or (self.events):
            if not self.events and self.segments_acked < self.total_segments:
                # Deadlock check? Should not happen if logic is correct
                if not self.timer_active and self.seq_base < self.seq_start + (self.total_segments * self.mss):
                     self._try_send()
                     if not self.events:
                         break
                else: 
                     break

            if not self.events:
                break
                
            ev = heapq.heappop(self.events)
            self.current_time = ev.time
            
            if ev.type == EVENT_SEND:
                # Actually put packet on wire (log it) and schedule arrival
                pkt = ev.data
                self._log_packet(pkt)
                
                # Check loss
                is_lost = False
                if TCP in pkt and len(pkt[TCP].payload) > 0:
                    seq = pkt[TCP].seq
                    if seq in self.data_map:
                        seg_idx = self.data_map[seq]
                        if seg_idx in self.loss_list:
                             is_lost = True
                             self.loss_list.remove(seg_idx) # Only drop once
                             print(f"[{self.current_time:.4f}] DROPPING Segment {seg_idx} (Seq {seq})")
                
                self._diagram_add(self.current_time, 'client', pkt, lost=is_lost)
                if len(pkt[TCP].payload) > 0:
                    self._summary_add(pkt)

                if not is_lost:
                    self.schedule(self._ser_time(pkt) + self._get_lat(), EVENT_ARRIVE_SERVER, pkt)

            elif ev.type == EVENT_ARRIVE_SERVER:
                self._handle_server_rx(ev.data)

            elif ev.type == EVENT_ARRIVE_CLIENT:
                self._log_packet(ev.data)
                self._handle_client_rx(ev.data)

            elif ev.type == EVENT_TIMEOUT:
                if self.timer_active and self.current_time >= self.timer_expiry:
                    # Verify generation
                    if ev.data == self.rto_timer_txn:
                        self._handle_timeout()

            elif ev.type == EVENT_DELAYED_ACK:
                if self.delayed_ack_timer_active:
                    # Verify generation to avoid zombie timers
                    if ev.data == self.ack_timer_txn:
                        self._send_ack()

            elif ev.type == EVENT_CLIENT_CLOSE:
                self._send_client_fin()

            elif ev.type == EVENT_SERVER_CLOSE:
                self._send_server_fin(with_ack=False)

        # Finish
        self.rto_log_handle.close()
        if self.rtt_log_handle:
            self.rtt_log_handle.close()
        wrpcap(self.output_file, self.packets)
        print(f"Simulation finished. pcap written to {self.output_file}")
        print(f"Log written to {self.rto_log_file}")
        if self.rtt_log_file:
            print(f"RTT/RTO log written to {self.rtt_log_file}")
        if self.summary_file:
            self._write_summary()
            print(f"Summary written to {self.summary_file}")
        if self.diagram_file:
            with open(self.diagram_file, "w", encoding="utf-8") as fh:
                fh.write(render_classroom_svg(self, self.diagram_lang))
            print(f"Diagram written to {self.diagram_file}")

    # ------------------------------------------------------------------
    # Packet construction
    # ------------------------------------------------------------------
    def _client_pkt(self, flags, seq, ack, payload=None, options=None):
        tcp = TCP(sport=self.client_port, dport=self.server_port, flags=flags, seq=seq, ack=ack,
                  window=self.client_rwnd, options=options or [])
        pkt = Ether(src=SRC_MAC, dst=DST_MAC) / IP(src=self.client_ip, dst=self.server_ip) / tcp
        return pkt / payload if payload else pkt

    def _server_pkt(self, flags, seq, ack, options=None):
        tcp = TCP(sport=self.server_port, dport=self.client_port, flags=flags, seq=seq, ack=ack,
                  window=self.server_rwnd, options=options or [])
        return Ether(src=DST_MAC, dst=SRC_MAC) / IP(src=self.server_ip, dst=self.client_ip) / tcp

    def _endpoints_text(self):
        return (f"client={self.client_ip}:{self.client_port} server={self.server_ip}:{self.server_port}")

    # ------------------------------------------------------------------
    # Per-burst summary (--summary)
    # ------------------------------------------------------------------
    def _summary_add(self, pkt):
        # Called when a client data segment is put on the wire (already in self.packets)
        seq = pkt[TCP].seq
        self.summary_entries.append({
            'burst': self.burst_id,
            'frame': len(self.packets),
            'time': self.current_time,
            'seq': seq,
            'retrans': seq in self._summary_seen,
            'in_flight': (self.next_seq - self.seq_base) // self.mss,
            'cwnd': self._cwnd_text(),
            'ssthresh': self.ssthresh,
            'mode': self.state,
        })
        self._summary_seen.add(seq)

    def _new_burst(self):
        self.burst_id += 1

    def _write_summary(self):
        T = SUMMARY_TEXTS[self.lang]
        rows = []
        for e in self.summary_entries:
            if rows and rows[-1]['burst'] == e['burst']:
                rows[-1]['entries'].append(e)
            else:
                rows.append({'burst': e['burst'], 'entries': [e]})
        with open(self.summary_file, "w", encoding="utf-8") as fh:
            fh.write(f"# {self._endpoints_text()} mss={self.mss}\n")
            for note in T['notes']:
                fh.write(f"# {note}\n")
            fh.write(','.join(T['header']) + '\n')
            for i, row in enumerate(rows, start=1):
                first, last = row['entries'][0], row['entries'][-1]
                frames = f"{first['frame']}-{last['frame']}" if last['frame'] != first['frame'] else str(first['frame'])
                retrans = sum(1 for e in row['entries'] if e['retrans'])
                new = len(row['entries']) - retrans
                fh.write(','.join(str(x) for x in [
                    i, frames, f"{first['time']:.4f}", len(row['entries']), new, retrans,
                    last['in_flight'], last['cwnd'],
                    last['ssthresh'], T['modes'].get(last['mode'], last['mode'])]) + '\n')

    # ------------------------------------------------------------------
    # RTT / RTO log (--rtt-log)
    # ------------------------------------------------------------------
    def _write_rtt_log_header(self):
        fh = self.rtt_log_handle
        fh.write(f"# {self._endpoints_text()}\n")
        fh.write("# Conventions (RFC 6298, standard mode):\n")
        fh.write("#  - Times are seconds since the client's SYN, as seen at the client (capture point).\n")
        fh.write("#  - One RTT sample per new (non-duplicate) ACK, measured on the oldest unacknowledged segment (SND.UNA):\n")
        fh.write("#    SampleRTT = arrival time of the ACK that covers it - time of its FIRST transmission.\n")
        fh.write("#  - Karn's algorithm: an ACK whose oldest segment was retransmitted yields no sample (row 'No sample (Karn)').\n")
        fh.write("#  - First sample: SRTT = SampleRTT, RTTVAR = SampleRTT / 2.\n")
        fh.write(f"#  - Then: RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - SampleRTT| with beta = {RTO_BETA}, "
                 f"SRTT = (1 - alpha) * SRTT + alpha * SampleRTT with alpha = {RTO_ALPHA} (RTTVAR first, using the old SRTT).\n")
        fh.write(f"#  - RTO = SRTT + max(G, K * RTTVAR) with G = {RTO_G} s and K = {RTO_K}; then RTO = max(RTO, {MIN_RTO} s).\n")
        fh.write("#  - On a retransmission timeout the RTO is doubled (exponential backoff); the next valid sample recomputes it.\n")
        fh.write("#  - In classroom mode the RTO is fixed (slots * slot duration) and no sample is taken.\n")
        fh.write("Time,Event,Seq,SentAt,SampleRTT,SRTT,RTTVAR,RTO,Calc\n")

    def _log_rtt(self, event, seq="", sent_at=None, sample=None, calc=""):
        if not self.rtt_log_handle:
            return
        fmt = lambda v: "" if v is None else f"{v:.4f}"
        self.rtt_log_handle.write(
            f"{self.current_time:.4f},{event},{seq},{fmt(sent_at)},{fmt(sample)},"
            f"{fmt(self.srtt)},{fmt(self.rttvar)},{self.rto:.4f},\"{calc}\"\n")

    def _update_rto(self, sample_rtt, seq, sent_at):
        # RFC 6298 Section 2: SRTT/RTTVAR update and RTO computation
        if self.srtt is None:
            self.srtt = sample_rtt
            self.rttvar = sample_rtt / 2.0
            calc = (f"first sample: SRTT = {sample_rtt:.4f}; RTTVAR = {sample_rtt:.4f}/2 = {self.rttvar:.4f}")
        else:
            old_srtt, old_rttvar = self.srtt, self.rttvar
            self.rttvar = (1 - RTO_BETA) * old_rttvar + RTO_BETA * abs(sample_rtt - old_srtt)
            self.srtt = (1 - RTO_ALPHA) * old_srtt + RTO_ALPHA * sample_rtt
            calc = (f"RTTVAR = {1 - RTO_BETA:g}*{old_rttvar:.4f} + {RTO_BETA:g}*|{old_srtt:.4f} - {sample_rtt:.4f}| = {self.rttvar:.4f}; "
                    f"SRTT = {1 - RTO_ALPHA:g}*{old_srtt:.4f} + {RTO_ALPHA:g}*{sample_rtt:.4f} = {self.srtt:.4f}")
        raw = self.srtt + max(RTO_G, RTO_K * self.rttvar)
        self.rto = max(MIN_RTO, raw)
        calc += (f"; RTO = {self.srtt:.4f} + max({RTO_G}, {RTO_K}*{self.rttvar:.4f}) = {raw:.4f}")
        if self.rto != raw:
            calc += f" -> max({MIN_RTO}, {raw:.4f}) = {self.rto:.4f}"
        self._log_rtt("RTT Sample", seq=seq, sent_at=sent_at, sample=sample_rtt, calc=calc)

    # ------------------------------------------------------------------
    # Connection close (--close fin | fin3)
    # ------------------------------------------------------------------
    def _schedule_close(self):
        # All data acknowledged: the client application closes after CLOSE_DELAY
        self.closing = True
        self.schedule(CLOSE_DELAY, EVENT_CLIENT_CLOSE, None)

    def _send_client_fin(self):
        self.client_fin_seq = self.next_seq
        fin = self._client_pkt("FA", self.client_fin_seq, self.server_seq)
        delay = self._calc_tx_delay('client', fin)
        self.schedule(delay, EVENT_SEND, fin)
        self._log_event("FIN Sent", seq=self.client_fin_seq)

    def _send_server_fin(self, with_ack):
        # with_ack=True: the FIN also acknowledges the client's FIN (--close fin3)
        self.server_fin_seq = self.server_seq
        fin = self._server_pkt("FA", self.server_fin_seq, self.expected_seq)
        self.server_seq += 1
        delay = self._calc_tx_delay('server', fin)
        self._diagram_add(self.current_time + delay, 'server', fin)
        self.schedule(delay + self._ser_time(fin) + self._get_lat(), EVENT_ARRIVE_CLIENT, fin)

    def _handle_server_fin_rx(self):
        # The FIN consumes one sequence number and is acknowledged at once
        self.expected_seq += 1
        self.delayed_ack_timer_active = False
        self.pending_ack_count = 0
        if self.close_mode == 'fin3':
            self._send_server_fin(with_ack=True)
        else:
            self._send_ack()
            self.schedule(SERVER_CLOSE_DELAY, EVENT_SERVER_CLOSE, None)

    def _handle_client_close_rx(self, pkt):
        tcp = pkt[TCP]
        if tcp.ack > self.seq_base:
            self.seq_base = tcp.ack
            self._log_event("FIN Acked", ack=tcp.ack)
        if 'F' in str(tcp.flags):
            self.server_fin_seq = tcp.seq
            last_ack = self._client_pkt("A", self.client_fin_seq + 1, tcp.seq + 1)
            delay = self._calc_tx_delay('client', last_ack)
            self.schedule(delay, EVENT_SEND, last_ack)
            self._log_event("FIN Received", seq=tcp.seq)

    # ------------------------------------------------------------------
    # Diagram bookkeeping (see render_classroom_svg)
    # ------------------------------------------------------------------
    def _diagram_add(self, send_time, side, pkt, lost=False):
        tcp = pkt[TCP]
        flags = str(tcp.flags)
        seq = tcp.seq
        retrans = side == 'client' and len(tcp.payload) > 0 and seq in self._diagram_sent_seqs
        if side == 'client' and len(tcp.payload) > 0:
            self._diagram_sent_seqs.add(seq)
        mss = None
        for opt in (tcp.options or []):
            if opt[0] == 'MSS':
                mss = opt[1]
        self.diagram_segments.append({
            'time': send_time, 'side': side, 'seq': seq, 'ack': tcp.ack,
            'syn': 'S' in flags, 'ack_flag': 'A' in flags, 'fin': 'F' in flags,
            'window': tcp.window, 'mss': mss, 'data': len(tcp.payload),
            'lost': lost, 'retrans': retrans,
        })
        if lost:
            self.diagram_timers.append({'seq': seq, 'send_time': send_time})

    def _cwnd_text(self):
        # Same notation as the classroom exercises: integer part plus the
        # fraction of the next segment earned in congestion avoidance.
        n = int(self.cwnd)
        if self.state == 'CONGESTION_AVOIDANCE' and self.cwnd_cnt > 0:
            return f"{n} + {self.cwnd_cnt}/{n}"
        return str(n)

    def _establish_connection(self):
        # 1. Client Sends SYN
        # We start at time 0.0
        self.current_time = 0.0
        
        syn = self._client_pkt("S", self.seq_start - 1, 0, options=[('MSS', self.mss)])
        delay_syn = self._calc_tx_delay('client', syn)
        tx_time_syn = self.current_time + delay_syn
        syn.time = self._stamp(tx_time_syn)
        self.packets.append(syn)

        # 2. Server Receives SYN
        arrival_server = tx_time_syn + self._ser_time(syn) + self._get_lat()

        # 3. Server Sends SYN-ACK
        # Advance current time to arrival at server to calculate server's response delay
        self.current_time = arrival_server
        syn_ack = self._server_pkt("SA", self.ack_start, self.seq_start, options=[('MSS', self.server_mss)])
        delay_synack = self._calc_tx_delay('server', syn_ack)
        tx_time_synack = self.current_time + delay_synack

        # 4. Client Receives SYN-ACK
        # The capture is taken at the client, so the SYN-ACK is stamped on
        # arrival there, like every other server segment (not when it is sent)
        arrival_client = tx_time_synack + self._ser_time(syn_ack) + self._get_lat()
        syn_ack.time = self._stamp(arrival_client)
        self.packets.append(syn_ack)

        # 5. Client Sends ACK
        # Advance current time to arrival at client
        self.current_time = arrival_client
        ack = self._client_pkt("A", self.seq_start, self.ack_start + 1)
        delay_ack = self._calc_tx_delay('client', ack)
        tx_time_ack = self.current_time + delay_ack
        ack.time = self._stamp(tx_time_ack)
        self.packets.append(ack)
        
        self._diagram_add(tx_time_syn, 'client', syn)
        self._diagram_add(tx_time_synack, 'server', syn_ack)
        self._diagram_add(tx_time_ack, 'client', ack)

        # 6. Prepare for Data Transmission
        # Data transmission resumes from when Client finished sending ACK
        self.current_time = tx_time_ack
        
        # Initial State
        self.seq_base = self.seq_start
        self.next_seq = self.seq_start
        self.highest_sent = self.seq_start
        self.expected_seq = self.seq_start
        
        # Prepare Data Map
        curr = self.seq_start
        for i in range(1, self.total_segments + 1):
            self.data_map[curr] = i
            curr += self.mss

        self._try_send()
        if self.sent_times:
            self.diagram_cwnd.insert(0, {'time': min(self.sent_times.values()), 'text': self._cwnd_text(), 'mode': self.state})



    def _stamp(self, t):
        # Capture timestamp for simulated time t (seconds since the SYN), exact to the microsecond
        return EDecimal(self.base_timestamp) + EDecimal(f"{t:.6f}")

    def _log_packet(self, pkt):
        pkt.time = self._stamp(self.current_time)
        self.packets.append(pkt)
        # Anything other than a client data segment (an ACK arriving, a FIN...)
        # separates two bursts in the per-burst summary
        if not (pkt[IP].src == self.client_ip and len(pkt[TCP].payload) > 0):
            self._new_burst()
    
    def _log_event(self, event_name, seq="", ack=""):
        # Time,Event,RTO,Cwnd,CwndCnt,Rwnd,Ssthresh,Mode,Seq,Ack
        self.rto_log_handle.write(f"{self.current_time:.4f},{event_name},{self.rto:.4f},{self.cwnd:.2f},{self.cwnd_cnt},{self.rwnd},{self.ssthresh},{self.state},{seq},{ack}\n")

    def _ser_time(self, pkt):
        # Serialization time of a frame on the sender's link (standard mode with --bandwidth)
        if self.classroom or not self.bandwidth or pkt is None:
            return 0.0
        return len(pkt) * 8.0 / self.bandwidth

    def _calc_tx_delay(self, source='client', pkt=None):
        # source: 'client' or 'server'
        if not self.classroom:
            # Processing delay, then wait until the host's link is free: frames
            # are serialized one after another (--bandwidth); without it the
            # link is always free and every frame leaves after PROC_DELAY.
            start = max(self.current_time + PROC_DELAY, self.link_free[source])
            self.link_free[source] = start + self._ser_time(pkt)
            return start - self.current_time
        else:
            # Determine last scheduled time for this source
            last_tx_time = self.last_tx_time_client if source == 'client' else self.last_tx_time_server
            
            # Snap current time to next slot boundary
            # Slot duration is RTT/2.
            # Grid: 0, 0.5*RTT, 1.0*RTT...
            epsilon = 1e-9
            slot_idx = math.ceil((self.current_time - epsilon) / self.slot_duration)
            grid_time = slot_idx * self.slot_duration
            
            # If current_time is effectively at boundary
            if grid_time < self.current_time:
                 grid_time += self.slot_duration
            
            # Enforce serialization: Must be at least (last_tx + slot_duration)
            # Exception: if last_tx is "long ago", we can start at grid_time.
            # "Long ago" means last_tx + slot_duration <= grid_time.
            
            min_valid_time = last_tx_time + self.slot_duration
            
            sched_time = max(grid_time, min_valid_time)
            
            # Update state
            if source == 'client':
                self.last_tx_time_client = sched_time
            else:
                self.last_tx_time_server = sched_time
            
            delay = sched_time - self.current_time
            return max(0.0, delay)

    def _get_lat(self):
         if self.classroom:
             return RTT / 4.0 # Fixed OWD
         else:
             return RTT / 2.0

    def _send_window(self):
        # RFC 5681 Section 3.1: the sender may transmit up to min(cwnd, rwnd) bytes
        # beyond the oldest unacknowledged segment.
        return min(int(self.cwnd) * self.mss, self.rwnd)

    def _cwnd_limited(self):
        # RFC 7661: cwnd should only grow while it is the factor limiting transmission,
        # i.e. when the receiver window is not the smaller of the two.
        return int(self.cwnd) * self.mss <= self.rwnd

    def _try_send(self):
        # Send while within min(cwnd, rwnd)
        while self.next_seq < self.seq_base + self._send_window():
            if self.next_seq >= self.seq_start + self.total_segments * self.mss:
                break # No more data (after a timeout next_seq is rewound, so count by sequence number)
            
            # Create Packet (Client Window)
            seg_idx = self.data_map.get(self.next_seq)
            if seg_idx is None: 
                break # Should not happen
                
            payload = "D" * self.mss # Dummy payload
            pkt = self._client_pkt("PA", self.next_seq, self.server_seq, payload)

            # Calculate delay (stateful update)
            delay = self._calc_tx_delay('client', pkt)
            
            # Record send time for RTT calc only for data sent for the first time
            # (Karn's algorithm: retransmissions never produce RTT samples)
            if self.next_seq >= self.highest_sent:
                # In classroom mode, mark actual send time (future)
                self.sent_times[self.next_seq] = self.current_time + delay
                self.highest_sent = self.next_seq + self.mss
            
            self.schedule(delay, EVENT_SEND, pkt) 
            
            if not self.timer_active:
                self._start_timer(delay)
            
            self.next_seq += self.mss
            self.segments_sent_count = max(self.segments_sent_count, seg_idx)
    
    def _start_timer(self, tx_delay=0.0):
        self.timer_active = True
        self.rto_timer_txn += 1
        
        # If classroom, tx_delay is significant.
        # Timer starts from "transmission start" -> expiry = current + delay + rto
        
        self.timer_armed_at = self.current_time + tx_delay
        self.timer_expiry = self.current_time + tx_delay + self.rto
        self.diagram_timer_log.append((self.timer_armed_at, self.timer_expiry))
        self.schedule(self.timer_expiry - self.current_time, EVENT_TIMEOUT, self.rto_timer_txn)

    def _stop_timer(self):
        self.timer_active = False

    def _handle_timeout(self):
        self.diagram_timeouts.append(self.current_time)
        print(f"[{self.current_time:.4f}] TIMEOUT! cwnd: {self.cwnd} -> 1, ssthresh: {self.ssthresh} -> {max(int(self.cwnd)//2, 2)}")
        self.ssthresh = max(int(self.cwnd) // 2, 2)
        self.cwnd = 1
        self.state = 'SLOW_START'
        self.dup_acks = 0
        
        # Reset timer
        if not self.classroom:
             old_rto = self.rto
             self.rto *= 2 # Exponential Backoff
             self._log_rtt("Backoff", seq=self.seq_base,
                           calc=f"timeout: RTO = 2 * {old_rto:.4f} = {self.rto:.4f}")
        else:
             self._log_rtt("Timeout", seq=self.seq_base, calc="fixed RTO (classroom), no backoff")

        # Invalidate RTT measurements for all outstanding segments
        keys_to_remove = [k for k in self.sent_times if k >= self.seq_base]
        for k in keys_to_remove:
            del self.sent_times[k]

        self._log_event("RTO Timeout", seq=self.seq_base)
        self._new_burst()
        self.diagram_cwnd.append({'time': self.current_time, 'text': self._cwnd_text(), 'mode': self.state})

        # RFC 6298 Section 5.4 / Linux: after a timeout every outstanding segment is
        # considered lost. Rewind next_seq so that _try_send retransmits from seq_base
        # as far as the (now reset) cwnd allows; the rest follows in slow start.
        self.next_seq = self.seq_base
        self.timer_active = False
        self._try_send()

    def _handle_server_rx(self, pkt):
        # Server Receive Logic
        if TCP in pkt and 'F' in str(pkt[TCP].flags):
            self._handle_server_fin_rx()
        elif TCP in pkt and len(pkt[TCP].payload) > 0:
            seq = pkt[TCP].seq
            
            # Constraint: Discard out of order UNLESS accept_ooo is set
            # Constraint: Discard out of order UNLESS accept_ooo is set
            if seq == self.expected_seq:
                self.expected_seq += self.mss
                # In-order packet
                self.pending_ack_count += 1
                
                # Check buffer for contiguous segments
                gap_filled = False
                if self.accept_ooo:
                    while self.expected_seq in self.receive_buffer:
                        self.receive_buffer.remove(self.expected_seq)
                        self.expected_seq += self.mss
                        gap_filled = True
                        self.pending_ack_count += 1
                
                # Decision: Send ACK or Schedule Timer
                # 1. If we have confirmed >= 2 segments (cumulative) -> Send
                # 2. If we filled a gap (Immediate ACK requirement) -> Send
                if self.pending_ack_count >= 2 or gap_filled:
                     self._send_ack()
                else:
                     if not self.delayed_ack_timer_active:
                        self.delayed_ack_timer_active = True
                        self.ack_timer_txn += 1
                        # Add small epsilon to ensure timer expires AFTER next segment arrival
                        timeout = (self.slot_duration + 1e-4) if self.classroom else DELAYED_ACK_TIMEOUT
                        self.schedule(timeout, EVENT_DELAYED_ACK, self.ack_timer_txn)
            else:
                if seq > self.expected_seq and self.accept_ooo:
                     self.receive_buffer.add(seq)
                
                # Out-of-order or gap: Immediate ACK (Duplicate)
                # Requirement: Immediate send, do not wait for delayed ack timer/slot
                self._send_ack()

    def _send_ack(self):
        self.pending_ack_count = 0
        self.delayed_ack_timer_active = False
        
        # The advertised window is kept constant: RFC 5681 Section 2 only counts an ACK as
        # a duplicate if the window is unchanged (Wireshark applies the same rule), so
        # shrinking it while buffering out-of-order data would hide the duplicate ACKs.
        
        # ACK (Server Window)
        ack_pkt = self._server_pkt("A", self.server_seq, self.expected_seq)

        delay = self._calc_tx_delay('server', ack_pkt)
        self._diagram_add(self.current_time + delay, 'server', ack_pkt)
        self.schedule(delay + self._ser_time(ack_pkt) + self._get_lat(), EVENT_ARRIVE_CLIENT, ack_pkt)
        # Note: _send_ack in original code scheduled ARRIVE_CLIENT directly.
        # Now we break it down: send delay + propagation.
        # Wait, in original code: schedule(RTT/2, EVENT_ARRIVE_CLIENT, ack_pkt)
        # Here: we schedule arrival.
        # Transmission happens at 'delay'. Propagation is '_get_lat()'.
        # Total delay from 'now' = delay + lat.

    def _handle_client_rx(self, pkt):
        if self.closing:
            self._handle_client_close_rx(pkt)
            return

        ack = pkt[TCP].ack
        # Every ACK carries the receiver's current advertised window
        self.rwnd = pkt[TCP].window

        if ack > self.seq_base:
            # NEW ACK

            # Message RTT calculation
            if not self.classroom:
                # RFC 6298: Update RTT using Karn's algorithm
                if self.seq_base in self.sent_times:
                    sent_at = self.sent_times[self.seq_base]
                    sample_rtt = self.current_time - sent_at
                    self._update_rto(sample_rtt, self.seq_base, sent_at)
                else:
                    self._log_rtt("No sample (Karn)", seq=self.seq_base,
                                  calc="oldest unacknowledged segment was retransmitted; RTO unchanged")

            # Clean up sent_times for acked segments
            # Technically we can remove everything < ack
            for s in list(self.sent_times.keys()):
                if s < ack:
                    del self.sent_times[s]
            
            bytes_acked = ack - self.seq_base
            segments_acked_count = bytes_acked // self.mss
            self.segments_acked += segments_acked_count
            
            self.seq_base = ack
            self.next_seq = max(self.next_seq, self.seq_base)
            self.dup_acks = 0
            # self.rto = 1.0 # Removed fixed reset
            
            prev_state = self.state
            cwnd_limited = self._cwnd_limited()
            
            # Update cwnd (only while cwnd, and not rwnd, is what limits the sender)
            if not cwnd_limited and self.state != 'FAST_RECOVERY':
                pass # rwnd is the bottleneck: leave cwnd untouched
            elif self.state == 'SLOW_START':
                self.cwnd += segments_acked_count
                if self.cwnd >= self.ssthresh:
                    self.state = 'CONGESTION_AVOIDANCE'
                    self.cwnd_cnt = 0
                    self._log_event("Mode Switch: SS -> CA")
            elif self.state == 'CONGESTION_AVOIDANCE':
                # Increase cwnd by 1 only when we receive cwnd ACKs
                # Linux approximation: use a counter
                # Handle cumulative ACKs: may increase multiple times or carry over remainder
                self.cwnd_cnt += segments_acked_count
                while self.cwnd_cnt >= self.cwnd:
                    self.cwnd_cnt -= int(self.cwnd)
                    self.cwnd += 1
            elif self.state == 'FAST_RECOVERY':
                # Full ACK received in Fast Recovery
                self.cwnd = self.ssthresh
                self.state = 'CONGESTION_AVOIDANCE'
                self.cwnd_cnt = 0
                self._log_event("Mode Switch: FR -> CA")
            
            self._log_event("ACK Received" if cwnd_limited else "ACK Received (rwnd-limited)", ack=ack)
            self.diagram_cwnd.append({'time': self.current_time, 'text': self._cwnd_text(), 'mode': self.state})
            
            self._stop_timer()
            if self.seq_base < self.next_seq: # Still data in flight?
                self._start_timer() # Restarts for the NEW oldest unacked

            self._try_send()

            if self.segments_acked >= self.total_segments and self.close_mode != 'none':
                self._schedule_close()

        elif ack == self.seq_base:
            # Duplicate ACK
            self.dup_acks += 1
            if self.state == 'FAST_RECOVERY':
                self.cwnd += 1
                self._log_event("DupACK in FR", ack=ack)
                self.diagram_cwnd.append({'time': self.current_time, 'text': self._cwnd_text(), 'mode': self.state})
                self._try_send()
            else:
                if self.dup_acks == 3:
                    # Fast Retransmit
                    # Common: Reduce ssthresh
                    self.ssthresh = max(int(self.cwnd) // 2, 2)
                    
                    if self.tcp_variant == 'tahoe':
                        print(f"[{self.current_time:.4f}] FAST RETRANSMIT (Tahoe) triggered!")
                        self.cwnd = 1
                        self.state = 'SLOW_START'
                        self.cwnd_cnt = 0
                        self._log_event("Fast Retransmit (Tahoe)", seq=self.seq_base)
                    else:
                        # Reno Default
                        print(f"[{self.current_time:.4f}] FAST RETRANSMIT (Reno) triggered!")
                        self.cwnd = self.ssthresh + 3
                        self.state = 'FAST_RECOVERY'
                        self._log_event("Fast Retransmit (Reno)", seq=self.seq_base)
                    
                    self.diagram_cwnd.append({'time': self.current_time, 'text': self._cwnd_text(), 'mode': self.state})
                    
                    # Karn's: Invalidate logic
                    if self.seq_base in self.sent_times:
                        del self.sent_times[self.seq_base]
                    
                    # Retransmit MISSING segment (seq_base)
                    payload = "D" * self.mss
                    pkt = self._client_pkt("PA", self.seq_base, self.server_seq, payload)

                    delay = self._calc_tx_delay('client', pkt)
                    self.schedule(delay, EVENT_SEND, pkt)
                    
                    # Restart timer to prevent immediate RTO (Double retransmit)
                    self._start_timer(delay)
                    
                    # For Tahoe, we might want to restart timer or similar, but sending triggers it?
                    # Reno enters Fast Recovery, timer continues for packet?
                    # Generally, Fast Retransmit doesn't necessarily stop the RTO timer, but success retransmission stops it.
                    # We leave it running.
 

# ----------------------------------------------------------------------
# Classroom diagram: two lifelines on a grid of ticks, one tick per slot,
# arrows leaving at the start of the sender's tick and arriving half a tick
# later. Same layout, labels and conventions as the "Secuencias TCP"
# exercises of the course web app, so the SVG shows what should be seen in
# the capture.
# ----------------------------------------------------------------------
DIAGRAM = {
    'tick_height': 36, 'y0': 56, 'num_width': 30, 'between': 150,
    'char': 6.3, 'label_min': 96, 'propagation': 0.5,
    'texts': {
        'es': {'names': {'client': 'Cliente', 'server': 'Servidor'}, 'cwnd': 'VC',
               'modes': {'SLOW_START': 'AL', 'CONGESTION_AVOIDANCE': 'EC', 'FAST_RECOVERY': 'RR'},
               'title': 'Diagrama de secuencia TCP por tics'},
        'en': {'names': {'client': 'Client', 'server': 'Server'}, 'cwnd': 'cwnd',
               'modes': {'SLOW_START': 'SS', 'CONGESTION_AVOIDANCE': 'CA', 'FAST_RECOVERY': 'FR'},
               'title': 'TCP tick-by-tick sequence diagram'},
    },
    # Light-theme colours of the web app (estilo-secuencias.css)
    'colours': {'text': '#1c1c1c', 'subtle': '#5a5a5a', 'line': '#e2e2e2',
                'accent': '#0046ad', 'error': '#b91c1c', 'paper': '#fff'},
}


def _svg_escape(text):
    return (str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;'))


def diagram_label(seg):
    parts = [f"SN={seg['seq']}"]
    if seg['ack_flag']:
        parts.append(f"AN={seg['ack']}")
    for flag, name in (('syn', 'SYN'), ('ack_flag', 'ACK'), ('fin', 'FIN')):
        if seg[flag]:
            parts.append(name)
    parts.append(f"W={seg['window']}")
    if seg['mss'] is not None:
        parts.append(f"MSS={seg['mss']}")
    if seg['data']:
        parts.append(f"D={seg['data']}")
    return ' '.join(parts)


def render_classroom_svg(sim, lang='es'):
    D = DIAGRAM
    T = D['texts'][lang]
    C = D['colours']
    H = D['tick_height']
    slot = sim.slot_duration

    def tick_of(t, arrival=False):
        # Sends are aligned to the grid; arrivals fall inside a tick.
        return (math.floor(t / slot + 1e-6) if arrival else int(round(t / slot))) + 1

    def expiry_tick(t):
        # The tick in which the retransmission would leave if the timer expired at t
        return math.ceil(t / slot - 1e-6) + 1

    def timer_in_force(t):
        # Last (re)start of the RTO timer at or before time t
        before = [x for x in sim.diagram_timer_log if x[0] <= t + 1e-9]
        return before[-1] if before else None

    arrows = []
    for seg in sim.diagram_segments:
        arrows.append({'tick': tick_of(seg['time']), 'side': seg['side'], 'label': diagram_label(seg),
                       'lost': seg['lost'], 'seq': seg['seq'], 'retrans': seg['retrans'], 'extra': ''})

    # cwnd where it changes, on the client side at the tick the ACK arrives
    extras = {}
    previous = None
    for cc in sim.diagram_cwnd:
        text = f"{T['cwnd']}={cc['text']} {T['modes'].get(cc['mode'], '')}".strip()
        if text != previous:
            extras[tick_of(cc['time'], arrival=True)] = text
            previous = text
    for tick, text in extras.items():
        owners = [a for a in arrows if a['side'] == 'client' and a['tick'] == tick]
        if owners:
            owners[0]['extra'] = text
        else:
            arrows.append({'tick': tick, 'side': 'client', 'label': '', 'extra': text,
                           'lost': False, 'seq': None, 'retrans': False, 'note_only': True})

    # One brace per lost segment, on the sender's side, from the tick in which
    # the timer covering the loss was (re)armed. If the timer expired before
    # the segment was retransmitted, the brace is solid up to that timeout
    # (new ACKs may have restarted the timer in between). Otherwise the
    # retransmission came first (fast retransmit, or slow start after another
    # timeout): the brace is dashed up to it and the label is the expiry of
    # the timer in force at that moment.
    braces = []
    seen = {}
    for tm in sim.diagram_timers:
        armed = timer_in_force(tm['send_time'])
        if armed is None:
            continue
        retx = [seg['time'] for seg in sim.diagram_segments if seg['side'] == 'client'
                and seg['seq'] == tm['seq'] and seg['retrans'] and seg['time'] > tm['send_time'] + 1e-9]
        if not retx:
            continue
        retx_time = min(retx)
        start = tick_of(armed[0], arrival=True)
        timeouts = [t for t in sim.diagram_timeouts if tm['send_time'] < t <= retx_time + 1e-9]
        if timeouts:
            end = expiry = expiry_tick(timeouts[0])
            stopped = False
        else:
            last = timer_in_force(retx_time - 1e-6)
            end = tick_of(retx_time)
            expiry = expiry_tick(last[1])
            stopped = end < expiry
        # Several losses recovered by the same timeout share one brace
        key = (end, expiry)
        if key in seen:
            seen[key]['start'] = min(seen[key]['start'], start)
            continue
        seen[key] = {'start': start, 'end': end, 'expiry': expiry, 'stopped': stopped}
        braces.append(seen[key])

    n_ticks = max([a['tick'] for a in arrows] + [b['end'] - 1 for b in braces] + [1])
    n_ticks = max(n_ticks, math.ceil(max(a['tick'] for a in arrows) + D['propagation'] - 1))

    width_label = {'client': D['label_min'], 'server': D['label_min']}
    for a in arrows:
        longest = max(len(a['label']), len(a['extra']))
        width_label[a['side']] = max(width_label[a['side']], math.ceil(longest * D['char']) + 12)
    x_of = {'client': D['num_width'] + width_label['client']}
    x_of['server'] = x_of['client'] + D['between']
    width = x_of['server'] + width_label['server'] + 6

    def y_of(t):
        return D['y0'] + (t - 1) * H

    y_end = y_of(n_ticks + 1)
    height = y_end + 12
    mono = "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    out = []
    out.append(f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
               f'font-family="system-ui, sans-serif">')
    out.append(f'<title>{_svg_escape(T["title"])}</title>')
    out.append('<defs><marker id="punta" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
               f'<path d="M0,0 L10,5 L0,10 z" fill="{C["accent"]}"/></marker></defs>')
    out.append(f'<rect x="0" y="0" width="{width}" height="{height}" fill="{C["paper"]}"/>')

    for t in range(1, n_ticks + 2):
        out.append(f'<line x1="4" y1="{y_of(t)}" x2="{width - 4}" y2="{y_of(t)}" stroke="{C["line"]}" stroke-width="1" stroke-dasharray="2 3"/>')
        if t <= n_ticks:
            out.append(f'<text x="{D["num_width"] / 2}" y="{y_of(t) + H / 2 + 4}" text-anchor="middle" font-size="10" '
                       f'font-family="{mono}" fill="{C["subtle"]}">{t}</text>')

    for side in ('client', 'server'):
        x = x_of[side]
        name = T['names'][side]
        box = max(64, len(name) * 7.5 + 18)
        out.append(f'<line x1="{x}" y1="{D["y0"] - 16}" x2="{x}" y2="{y_end + 6}" stroke="{C["subtle"]}" stroke-width="1.5"/>')
        out.append(f'<rect x="{x - box / 2}" y="6" width="{box}" height="28" rx="6" fill="{C["paper"]}" stroke="{C["line"]}"/>')
        out.append(f'<text x="{x}" y="24" text-anchor="middle" font-size="11" font-weight="700" fill="{C["text"]}">{_svg_escape(name)}</text>')

    for b in braces:
        x = x_of['client']
        dx = 9
        y1, y2 = y_of(b['start']), y_of(b['end'])
        dash = ' stroke-dasharray="4 3"' if b['stopped'] else ''
        out.append(f'<path d="M{x},{y1} h{dx} V{y2} h{-dx}" fill="none" stroke="{C["error"]}" stroke-width="1.6"{dash}/>')
        out.append(f'<text x="{x + dx + 3}" y="{y2 - 4}" font-size="9.5" font-weight="700" fill="{C["error"]}">&#9201; {b["expiry"]}</text>')

    occupied = {}
    for a in sorted(arrows, key=lambda a: (a['tick'], a['side'])):
        xe = x_of[a['side']]
        xr = x_of['server' if a['side'] == 'client' else 'client']
        y1 = y_of(a['tick'])
        y2 = y_of(a['tick'] + D['propagation'])
        x_label = xe - 6 if a['side'] == 'client' else xe + 6
        anchor = 'end' if a['side'] == 'client' else 'start'
        key = (a['tick'], a['side'])
        k = occupied[key] = occupied.get(key, 0) + 1
        y_label = y1 + 12 + (k - 1) * 22
        cls = 'segmento perdido' if a['lost'] else 'segmento'
        if a.get('note_only'):
            cls = 'anotacion'
        out.append(f'<g class="{cls}" data-tic="{a["tick"]}" data-lado="{a["side"]}">')
        if a.get('note_only'):
            pass
        elif a['lost']:
            xm, ym = (xe + xr) / 2, (y1 + y2) / 2
            out.append(f'<line x1="{xe}" y1="{y1}" x2="{xm}" y2="{ym}" stroke="{C["accent"]}" stroke-width="1.5"/>')
            out.append(f'<path d="M{xm - 6},{ym - 6} L{xm + 6},{ym + 6} M{xm - 6},{ym + 6} L{xm + 6},{ym - 6}" '
                       f'fill="none" stroke="{C["error"]}" stroke-width="2.2"/>')
        else:
            out.append(f'<line x1="{xe}" y1="{y1}" x2="{xr}" y2="{y2}" stroke="{C["accent"]}" stroke-width="1.5" marker-end="url(#punta)"/>')
        if a['label']:
            out.append(f'<text x="{x_label}" y="{y_label}" text-anchor="{anchor}" font-size="10" font-family="{mono}" '
                       f'fill="{C["text"]}">{_svg_escape(a["label"])}</text>')
        if a['extra']:
            y_extra = y_label + 11 if a['label'] else y_label
            out.append(f'<text x="{x_label}" y="{y_extra}" text-anchor="{anchor}" font-size="9.5" font-family="{mono}" '
                       f'fill="{C["accent"]}">{_svg_escape(a["extra"])}</text>')
        out.append('</g>')
    out.append('</svg>')
    return '\n'.join(out) + '\n'


def main():
    parser = argparse.ArgumentParser(description="TCP Trace Generator")
    parser.add_argument("segments", type=int, help="Number of segments to send")
    parser.add_argument("--loss", type=str, default="", help="Comma separated list of segment indices to lose (1-based)")
    parser.add_argument("--output", "-o", type=str, default="tcp_reno_gen.pcap", help="Output PCAP file")
    parser.add_argument("--rto-log", type=str, default="rto_log.txt", help="Output RTO log file")
    parser.add_argument("--initial-rto", type=float, default=1.0, help="Initial RTO value (seconds)")
    parser.add_argument("--accept-out-of-order", action="store_true", help="Accept (buffer) out-of-order segments instead of discarding them")
    parser.add_argument("--client-isn", type=int, default=None, help="Client Initial Sequence Number")
    parser.add_argument("--server-isn", type=int, default=None, help="Server Initial Sequence Number")
    parser.add_argument("--client-mss", type=int, default=1460, help="Client MSS")
    parser.add_argument("--server-mss", type=int, default=1460, help="Server MSS")
    parser.add_argument("--ssthresh", type=str, default="64", help="Initial Slow Start Threshold: segments (64, the default) or bytes with a unit, converted to whole client MSS (64K = 65536 B, 65535B)")
    parser.add_argument("--client-rwnd", type=int, default=65535, help="Client Initial RWND")
    parser.add_argument("--server-rwnd", type=int, default=65535, help="Server Initial RWND (Advertised Window)")
    parser.add_argument("--tcp-variant", type=str, default="reno", choices=["reno", "tahoe"], help="TCP Variant (reno or tahoe)")
    parser.add_argument("--classroom", action="store_true", help="Enable classroom mode (discrete slots, fixed RTO)")
    parser.add_argument("--classroom-rto-slots", type=int, default=3, help="RTO in slots for classroom mode (default: 3)")
    parser.add_argument("--diagram", type=str, default=None, metavar="FILE.svg", help="(Classroom mode only) Write a tick-by-tick sequence diagram of the exchanged segments as SVG")
    parser.add_argument("--diagram-lang", "--lang", dest="diagram_lang", type=str, default="es", choices=["es", "en"], help="Language of the diagram and summary labels: es (Cliente/Servidor, VC, AL/EC/RR) or en (Client/Server, cwnd, SS/CA/FR)")
    parser.add_argument("--client-ip", type=str, default=SRC_IP, help=f"Client (sender) IP address (default: {SRC_IP})")
    parser.add_argument("--server-ip", type=str, default=DST_IP, help=f"Server (receiver) IP address (default: {DST_IP})")
    parser.add_argument("--client-port", type=int, default=SPORT, help=f"Client TCP port (default: {SPORT})")
    parser.add_argument("--server-port", type=int, default=DPORT, help=f"Server TCP port (default: {DPORT})")
    parser.add_argument("--close", type=str, default="none", choices=["none", "fin", "fin3"], help="Connection close after the last ACK: none (default), fin (FIN, ACK, FIN, ACK) or fin3 (FIN, FIN+ACK, ACK)")
    parser.add_argument("--bandwidth", type=parse_bandwidth, default=None, metavar="BPS", help="(Standard mode only) Link bandwidth in bit/s, e.g. 1M, 10Mbps, 512k: frames of the same host are serialized one after another instead of leaving at the same instant")
    parser.add_argument("--summary", type=str, default=None, metavar="FILE.csv", help="Write a per-burst summary CSV: frames, new/retransmitted segments, segments in flight, cwnd, ssthresh and mode")
    parser.add_argument("--start-time", type=int, default=None, metavar="EPOCH", help="Absolute time of the SYN in Unix seconds (default: now); fix it to get the same pcap byte for byte on every run")
    parser.add_argument("--rtt-log", type=str, default=None, metavar="FILE.csv", help="Write a CSV with every RTT sample and RTO computation (RFC 6298), with the conventions stated in its header")

    args = parser.parse_args()

    if args.diagram and not args.classroom:
        parser.error("--diagram requires --classroom: the diagram is drawn in time slots (ticks)")

    if args.bandwidth and args.classroom:
        parser.error("--bandwidth does not apply to --classroom: in classroom mode every segment takes one slot")

    for name in ("client_ip", "server_ip"):
        try:
            socket.inet_pton(socket.AF_INET, getattr(args, name))
        except OSError:
            parser.error(f"--{name.replace('_', '-')}: invalid IPv4 address {getattr(args, name)!r}")
    if args.client_ip == args.server_ip:
        parser.error("--client-ip and --server-ip must differ")
    for name in ("client_port", "server_port"):
        if not 1 <= getattr(args, name) <= 65535:
            parser.error(f"--{name.replace('_', '-')} must be between 1 and 65535")

    if args.server_rwnd < args.client_mss:
        parser.error(f"--server-rwnd ({args.server_rwnd}) must be at least one client MSS "
                     f"({args.client_mss}); zero-window probing is not simulated")
    
    try:
        args.ssthresh = parse_ssthresh(args.ssthresh, args.client_mss)
    except ValueError as e:
        parser.error(f"--ssthresh: {e}")
    if args.start_time is not None and args.start_time < 0:
        parser.error("--start-time must be a non-negative number of seconds")

    loss_list = []
    if args.loss:
        parts = args.loss.split(',')
        for p in parts:
            if '-' in p:
                start, end = map(int, p.split('-'))
                loss_list.extend(range(start, end + 1))
            else:
                loss_list.append(int(p))
                
    sim = TCPSimulation(args.output, args.rto_log, args.segments, loss_list,
                        initial_rto=args.initial_rto, 
                        accept_ooo=args.accept_out_of_order,
                        client_isn=args.client_isn,
                        server_isn=args.server_isn,
                        client_mss=args.client_mss,
                        server_mss=args.server_mss,
                        ssthresh=args.ssthresh,
                        client_rwnd=args.client_rwnd,
                        server_rwnd=args.server_rwnd,
                        tcp_variant=args.tcp_variant,
                        classroom=args.classroom,
                        classroom_rto_slots=args.classroom_rto_slots,
                        diagram_file=args.diagram,
                        diagram_lang=args.diagram_lang,
                        client_ip=args.client_ip,
                        server_ip=args.server_ip,
                        client_port=args.client_port,
                        server_port=args.server_port,
                        close=args.close,
                        bandwidth=args.bandwidth,
                        summary_file=args.summary,
                        rtt_log_file=args.rtt_log,
                        start_time=args.start_time)
    sim.run()

if __name__ == "__main__":
    main()
