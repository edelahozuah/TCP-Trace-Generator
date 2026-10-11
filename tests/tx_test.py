import sys
import unittest
import os
import subprocess
import shutil
import csv

from scapy.all import rdpcap, TCP

class TestTCPTraceGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Ensure we are in the root directory or can access the script
        cls.script_path = os.path.abspath("tcp_trace_generator.py")
        cls.output_dir = "test_output"
        if os.path.exists(cls.output_dir):
            shutil.rmtree(cls.output_dir)
        os.makedirs(cls.output_dir)

    @classmethod
    def tearDownClass(cls):
        # Optional: Clean up test output directory
        # shutil.rmtree(cls.output_dir)
        pass

    def run_script(self, args):
        cmd = [sys.executable, self.script_path] + args
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result

    def test_basic_execution(self):
        print("\nRunning Basic Execution Test...")
        pcap_file = os.path.join(self.output_dir, "basic.pcap")
        log_file = os.path.join(self.output_dir, "basic_log.txt")
        
        args = ["20", "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        self.assertTrue(os.path.exists(pcap_file), "PCAP file was not created")
        self.assertTrue(os.path.exists(log_file), "Log file was not created")
        self.assertGreater(os.path.getsize(pcap_file), 0, "PCAP file is empty")

    def test_loss_scenario(self):
        print("\nRunning Loss Scenario Test...")
        pcap_file = os.path.join(self.output_dir, "loss.pcap")
        log_file = os.path.join(self.output_dir, "loss_log.txt")
        
        args = ["20", "--loss", "10", "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        self.assertTrue(os.path.exists(pcap_file), "PCAP file was not created")
        self.assertGreater(os.path.getsize(pcap_file), 0, "PCAP file is empty")

    def test_classroom_mode(self):
        print("\nRunning Classroom Mode Test...")
        pcap_file = os.path.join(self.output_dir, "classroom.pcap")
        log_file = os.path.join(self.output_dir, "classroom_log.txt")
        
        args = [
            "14",
            "--classroom",
            "--classroom-rto-slots", "4",
            "--loss", "11",
            "--accept-out-of-order",
            "--client-isn", "1024",
            "--server-isn", "2047",
            "--client-mss", "64",
            "--server-mss", "128",
            "--ssthresh", "2",
            "-o", pcap_file,
            "--rto-log", log_file
        ]
        result = self.run_script(args)
        
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        self.assertTrue(os.path.exists(pcap_file), "PCAP file was not created")
        self.assertGreater(os.path.getsize(pcap_file), 0, "PCAP file is empty")

    # ---- Regression tests for RFC conformance (see README, "Validation") ----

    def read_log(self, log_file):
        with open(log_file, newline="") as fh:
            return list(csv.DictReader(fh))

    def test_single_loss_causes_at_most_one_timeout(self):
        """A single lost segment must not degenerate into a chain of RTOs with
        exponential backoff: after a timeout every outstanding segment is
        retransmitted in slow start (RFC 6298 Section 5.4)."""
        print("\nRunning Single Loss / RTO Chain Regression Test...")
        pcap_file = os.path.join(self.output_dir, "single_loss.pcap")
        log_file = os.path.join(self.output_dir, "single_loss_log.txt")
        segments, mss = 30, 1460

        args = [str(segments), "--loss", "8", "--client-isn", "1",
                "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")

        log = self.read_log(log_file)
        timeouts = [row for row in log if row["Event"] == "RTO Timeout"]
        self.assertLessEqual(len(timeouts), 1, f"Expected at most one RTO, got {len(timeouts)}")

        pkts = rdpcap(pcap_file)
        duration = float(pkts[-1].time) - float(pkts[0].time)
        self.assertLess(duration, 10.0, f"Transfer took {duration:.1f}s; RTO chain suspected")

        last_ack = max(p[TCP].ack for p in pkts if p[TCP].sport == 80)
        self.assertEqual(last_ack, 1 + segments * mss, "Not all data was acknowledged")

    def test_ack_field_follows_server_isn(self):
        """Client data segments must acknowledge server_isn + 1 and server ACKs
        must carry seq = server_isn + 1, whatever the configured server ISN."""
        print("\nRunning Server ISN Test...")
        pcap_file = os.path.join(self.output_dir, "server_isn.pcap")
        log_file = os.path.join(self.output_dir, "server_isn_log.txt")
        server_isn = 1000

        args = ["6", "--server-isn", str(server_isn), "--client-isn", "5000",
                "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")

        pkts = rdpcap(pcap_file)
        data = [p for p in pkts if p[TCP].sport == 12345 and len(p[TCP].payload) > 0]
        acks = [p for p in pkts if p[TCP].sport == 80 and "S" not in p[TCP].flags]
        self.assertTrue(data and acks)
        self.assertTrue(all(p[TCP].ack == server_isn + 1 for p in data), "Client data has wrong ACK number")
        self.assertTrue(all(p[TCP].seq == server_isn + 1 for p in acks), "Server ACK has wrong SEQ number")

    def test_duplicate_acks_keep_advertised_window(self):
        """With out-of-order buffering, duplicate ACKs must keep the advertised
        window unchanged (RFC 5681 Section 2), otherwise Wireshark classifies
        them as window updates instead of duplicate ACKs."""
        print("\nRunning Duplicate ACK Window Test...")
        pcap_file = os.path.join(self.output_dir, "dupack_window.pcap")
        log_file = os.path.join(self.output_dir, "dupack_window_log.txt")
        rwnd = 65535

        args = ["30", "--loss", "8", "--accept-out-of-order", "--server-rwnd", str(rwnd),
                "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")

        pkts = rdpcap(pcap_file)
        acks = [p for p in pkts if p[TCP].sport == 80 and "S" not in p[TCP].flags]
        self.assertTrue(all(p[TCP].window == rwnd for p in acks), "Advertised window changed")

        log = self.read_log(log_file)
        self.assertTrue(any(row["Event"].startswith("Fast Retransmit") for row in log))
        self.assertFalse(any(row["Event"] == "RTO Timeout" for row in log))

    def test_sender_respects_receiver_window(self):
        """The sender must never have more than rwnd bytes outstanding
        (RFC 5681 Section 3.1: send window = min(cwnd, rwnd))."""
        print("\nRunning Receiver Window Test...")
        pcap_file = os.path.join(self.output_dir, "rwnd.pcap")
        log_file = os.path.join(self.output_dir, "rwnd_log.txt")
        segments, mss, rwnd = 20, 1460, 2 * 1460

        args = [str(segments), "--server-rwnd", str(rwnd), "--client-isn", "1",
                "-o", pcap_file, "--rto-log", log_file]
        result = self.run_script(args)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")

        pkts = sorted(rdpcap(pcap_file), key=lambda p: float(p.time))
        last_ack = 1
        for p in pkts:
            if p[TCP].sport == 80:
                last_ack = max(last_ack, p[TCP].ack)
            elif len(p[TCP].payload) > 0:
                in_flight = p[TCP].seq + len(p[TCP].payload) - last_ack
                self.assertLessEqual(in_flight, rwnd,
                    f"{in_flight} bytes in flight exceed rwnd={rwnd} at seq {p[TCP].seq}")
        self.assertEqual(last_ack, 1 + segments * mss, "Not all data was acknowledged")

        log = self.read_log(log_file)
        self.assertTrue(any(row["Event"] == "ACK Received (rwnd-limited)" for row in log))
        self.assertLessEqual(max(float(row["Cwnd"]) for row in log), 4.0,
                             "cwnd kept growing while rwnd was the bottleneck")

    def test_server_rwnd_below_mss_is_rejected(self):
        print("\nRunning Receiver Window Validation Test...")
        result = self.run_script(["5", "--server-rwnd", "1000"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--server-rwnd", result.stderr)

if __name__ == '__main__':
    unittest.main()
