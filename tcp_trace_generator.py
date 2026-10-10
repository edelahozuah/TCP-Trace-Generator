import argparse
import heapq
import itertools
import sys
import time
import random
from scapy.all import *

# Configuration Constants
MSS = 1460
RTT = 0.1  # Seconds
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
SPORT = 12345
DPORT = 80
DELAYED_ACK_TIMEOUT = 0.2
MIN_RTO = 0.2
SRC_MAC = "00:00:00:00:00:01"
DST_MAC = "00:00:00:00:00:02"

# Simulation Events
EVENT_SEND = 1
EVENT_ARRIVE_SERVER = 2
EVENT_ARRIVE_CLIENT = 3
EVENT_TIMEOUT = 4
EVENT_DELAYED_ACK = 5

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
                 client_rwnd=65535, server_rwnd=65535, tcp_variant='reno', classroom=False, classroom_rto_slots=3):
        self.output_file = output_file
        self.rto_log_file = rto_log_file
        self.total_segments = total_segments
        self.loss_list = set(loss_list)
        self.accept_ooo = accept_ooo
        
        self.mss = client_mss
        self.server_mss = server_mss
        self.client_rwnd = client_rwnd
        self.server_rwnd = server_rwnd
        self.tcp_variant = tcp_variant.lower()
        
        self.classroom = classroom
        self.classroom_rto_slots = classroom_rto_slots
        self.slot_duration = RTT / 2.0
        
        self.events = []
        self.packets = []
        self.current_time = 0.0
        self.base_timestamp = time.time()

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
                
                if not is_lost:
                    self.schedule(self._get_lat(), EVENT_ARRIVE_SERVER, pkt)
                    
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
        
        # Finish
        self.rto_log_handle.close()
        wrpcap(self.output_file, self.packets)
        print(f"Simulation finished. pcap written to {self.output_file}")
        print(f"Log written to {self.rto_log_file}")

    def _establish_connection(self):
        # 1. Client Sends SYN
        # We start at time 0.0
        self.current_time = 0.0
        
        delay_syn = self._calc_tx_delay('client')
        tx_time_syn = self.current_time + delay_syn
        
        syn = Ether(src=SRC_MAC, dst=DST_MAC)/IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, flags="S", seq=self.seq_start-1, window=self.client_rwnd, options=[('MSS', self.mss)])
        syn.time = self.base_timestamp + tx_time_syn
        self.packets.append(syn)
        
        # 2. Server Receives SYN
        arrival_server = tx_time_syn + self._get_lat()
        
        # 3. Server Sends SYN-ACK
        # Advance current time to arrival at server to calculate server's response delay
        self.current_time = arrival_server
        delay_synack = self._calc_tx_delay('server')
        tx_time_synack = self.current_time + delay_synack
        
        syn_ack = Ether(src=DST_MAC, dst=SRC_MAC)/IP(src=DST_IP, dst=SRC_IP)/TCP(sport=DPORT, dport=SPORT, flags="SA", seq=self.ack_start, ack=self.seq_start, window=self.server_rwnd, options=[('MSS', self.server_mss)])
        syn_ack.time = self.base_timestamp + tx_time_synack
        self.packets.append(syn_ack)
        
        # 4. Client Receives SYN-ACK
        arrival_client = tx_time_synack + self._get_lat()
        
        # 5. Client Sends ACK
        # Advance current time to arrival at client
        self.current_time = arrival_client
        delay_ack = self._calc_tx_delay('client')
        tx_time_ack = self.current_time + delay_ack
        
        ack = Ether(src=SRC_MAC, dst=DST_MAC)/IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, flags="A", seq=self.seq_start, ack=self.ack_start+1, window=self.client_rwnd)
        ack.time = self.base_timestamp + tx_time_ack
        self.packets.append(ack)
        
        # 6. Prepare for Data Transmission
        # Data transmission resumes from when Client finished sending ACK
        self.current_time = tx_time_ack
        
        # Initial State
        self.seq_base = self.seq_start
        self.next_seq = self.seq_start
        self.expected_seq = self.seq_start
        
        # Prepare Data Map
        curr = self.seq_start
        for i in range(1, self.total_segments + 1):
            self.data_map[curr] = i
            curr += self.mss

        self._try_send()



    def _log_packet(self, pkt):
        pkt.time = self.base_timestamp + self.current_time
        self.packets.append(pkt)
    
    def _log_event(self, event_name, seq="", ack=""):
        # Time,Event,RTO,Cwnd,CwndCnt,Rwnd,Ssthresh,Mode,Seq,Ack
        self.rto_log_handle.write(f"{self.current_time:.4f},{event_name},{self.rto:.4f},{self.cwnd:.2f},{self.cwnd_cnt},{self.rwnd},{self.ssthresh},{self.state},{seq},{ack}\n")

    def _calc_tx_delay(self, source='client'):
        # source: 'client' or 'server'
        if not self.classroom:
            return 0.0001 # Tiny processing delay
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

    def _try_send(self):
        # Send while within cwnd
        while self.next_seq < self.seq_base + (int(self.cwnd) * self.mss):
            if self.segments_sent_count >= self.total_segments:
                break
            
            # Create Packet (Client Window)
            seg_idx = self.data_map.get(self.next_seq)
            if seg_idx is None: 
                break # Should not happen
                
            payload = "D" * self.mss # Dummy payload
            pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, flags="PA", seq=self.next_seq, ack=1, window=self.client_rwnd)/payload
            
            # Calculate delay (stateful update)
            delay = self._calc_tx_delay('client')
            
            # Record send time for RTT calc (if first time sending this seq)
            if self.next_seq not in self.sent_times:
                # In classroom mode, mark actual send time (future)
                self.sent_times[self.next_seq] = self.current_time + delay
            
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
        
        self.timer_expiry = self.current_time + tx_delay + self.rto
        self.schedule(self.timer_expiry - self.current_time, EVENT_TIMEOUT, self.rto_timer_txn)

    def _stop_timer(self):
        self.timer_active = False

    def _handle_timeout(self):
        print(f"[{self.current_time:.4f}] TIMEOUT! cwnd: {self.cwnd} -> 1, ssthresh: {self.ssthresh} -> {max(int(self.cwnd)//2, 2)}")
        self.ssthresh = max(int(self.cwnd) // 2, 2)
        self.cwnd = 1
        self.state = 'SLOW_START'
        self.dup_acks = 0
        
        # Reset timer
        if not self.classroom:
             self.rto *= 2 # Exponential Backoff
        else:
             pass # Fixed RTO in classroom
        
        # Invalidate RTT measurements for all outstanding segments
        keys_to_remove = [k for k in self.sent_times if k >= self.seq_base]
        for k in keys_to_remove:
            del self.sent_times[k]

        self._log_event("RTO Timeout", seq=self.seq_base)

        # Retransmit seq_base
        payload = "D" * self.mss
        pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, flags="PA", seq=self.seq_base, ack=1, window=self.client_rwnd)/payload
        
        delay = self._calc_tx_delay('client')
        self.schedule(delay, EVENT_SEND, pkt)
        
        self._start_timer(delay)
        
        # Do NOT reset next_seq. 

    def _handle_server_rx(self, pkt):
        # Server Receive Logic
        if TCP in pkt and len(pkt[TCP].payload) > 0:
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
        
        # Calculate Dynamic Window
        # Assume application reads in-order data immediately, but out-of-order data stays in buffer.
        buffered_bytes = len(self.receive_buffer) * self.server_mss
        current_server_rwnd = max(0, self.server_rwnd - buffered_bytes)
        
        # ACK (Server Window)
        ack_pkt = Ether(src=DST_MAC, dst=SRC_MAC)/IP(src=DST_IP, dst=SRC_IP)/TCP(sport=DPORT, dport=SPORT, flags="A", seq=1, ack=self.expected_seq, window=current_server_rwnd)
        
        delay = self._calc_tx_delay('server')
        self.schedule(delay + self._get_lat(), EVENT_ARRIVE_CLIENT, ack_pkt)
        # Note: _send_ack in original code scheduled ARRIVE_CLIENT directly.
        # Now we break it down: send delay + propagation.
        # Wait, in original code: schedule(RTT/2, EVENT_ARRIVE_CLIENT, ack_pkt)
        # Here: we schedule arrival.
        # Transmission happens at 'delay'. Propagation is '_get_lat()'.
        # Total delay from 'now' = delay + lat.

    def _handle_client_rx(self, pkt):
        ack = pkt[TCP].ack
        
        if ack > self.seq_base:
            # NEW ACK
            
            # Message RTT calculation
            if not self.classroom:
                # RFC 6298: Update RTT using Karn's algorithm
                if self.seq_base in self.sent_times:
                    sample_rtt = self.current_time - self.sent_times[self.seq_base]
                    
                    # Update Estimatations
                    if self.srtt is None:
                        # First measurement
                        self.srtt = sample_rtt
                        self.rttvar = sample_rtt / 2.0
                    else:
                        # Subsequent (Alpha=1/8, Beta=1/4)
                        self.rttvar = 0.75 * self.rttvar + 0.25 * abs(sample_rtt - self.srtt)
                        self.srtt = 0.875 * self.srtt + 0.125 * sample_rtt
                        
                    self.rto = self.srtt + max(0.1, 4 * self.rttvar) # G=0.1s granularity? Using 0.001?
                    # RFC: RTO = SRTT + max(G, K*RTTVAR)
                    # Ensure Min RTO
                    self.rto = max(MIN_RTO, self.rto)
            
            # Clean up sent_times for acked segments
            # Technically we can remove everything < ack
            for s in list(self.sent_times.keys()):
                if s < ack:
                    del self.sent_times[s]
            
            bytes_acked = ack - self.seq_base
            segments_acked_count = bytes_acked // self.mss
            self.segments_acked += segments_acked_count
            
            self.seq_base = ack
            self.dup_acks = 0
            # self.rto = 1.0 # Removed fixed reset
            
            prev_state = self.state
            
            # Update cwnd
            if self.state == 'SLOW_START':
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
            
            self._log_event("ACK Received", ack=ack)
            
            self._stop_timer()
            if self.seq_base < self.next_seq: # Still data in flight?
                self._start_timer() # Restarts for the NEW oldest unacked
            
            self._try_send()
            
        elif ack == self.seq_base:
            # Duplicate ACK
            self.dup_acks += 1
            if self.state == 'FAST_RECOVERY':
                self.cwnd += 1
                self._log_event("DupACK in FR", ack=ack)
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
                    
                    # Karn's: Invalidate logic
                    if self.seq_base in self.sent_times:
                        del self.sent_times[self.seq_base]
                    
                    # Retransmit MISSING segment (seq_base)
                    payload = "D" * self.mss
                    pkt = Ether(src=SRC_MAC, dst=DST_MAC)/IP(src=SRC_IP, dst=DST_IP)/TCP(sport=SPORT, dport=DPORT, flags="PA", seq=self.seq_base, ack=1, window=self.client_rwnd)/payload
                    
                    delay = self._calc_tx_delay('client')
                    self.schedule(delay, EVENT_SEND, pkt)
                    
                    # Restart timer to prevent immediate RTO (Double retransmit)
                    self._start_timer(delay)
                    
                    # For Tahoe, we might want to restart timer or similar, but sending triggers it?
                    # Reno enters Fast Recovery, timer continues for packet?
                    # Generally, Fast Retransmit doesn't necessarily stop the RTO timer, but success retransmission stops it.
                    # We leave it running.
 

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
    parser.add_argument("--ssthresh", type=int, default=64, help="Initial Slow Start Threshold (segments)")
    parser.add_argument("--client-rwnd", type=int, default=65535, help="Client Initial RWND")
    parser.add_argument("--server-rwnd", type=int, default=65535, help="Server Initial RWND (Advertised Window)")
    parser.add_argument("--tcp-variant", type=str, default="reno", choices=["reno", "tahoe"], help="TCP Variant (reno or tahoe)")
    parser.add_argument("--classroom", action="store_true", help="Enable classroom mode (discrete slots, fixed RTO)")
    parser.add_argument("--classroom-rto-slots", type=int, default=3, help="RTO in slots for classroom mode (default: 3)")

    args = parser.parse_args()
    
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
                        classroom_rto_slots=args.classroom_rto_slots)
    sim.run()

if __name__ == "__main__":
    main()
