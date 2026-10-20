"""Runs tshark (Wireshark) on generated traces and checks the TCP analysis
labels Wireshark attaches to them: duplicate ACKs and a fast retransmission
in the Fast Retransmit scenario, plain retransmissions after a timeout in the
RTO scenario. Skipped when tshark is not installed."""
import csv
import os
import shutil
import subprocess
import sys
import unittest

MSS = 1460
TSHARK = shutil.which("tshark") or next(
    (p for p in ("/Applications/Wireshark.app/Contents/MacOS/tshark", "/usr/bin/tshark", "/usr/local/bin/tshark")
     if os.path.exists(p)), None)

FIELDS = ["frame.number", "ip.src", "tcp.srcport", "tcp.flags.str", "tcp.seq", "tcp.ack", "tcp.len",
          "tcp.analysis.fast_retransmission", "tcp.analysis.retransmission", "tcp.analysis.duplicate_ack_num",
          "tcp.analysis.rto", "tcp.analysis.out_of_order", "tcp.analysis.spurious_retransmission",
          "tcp.analysis.window_update", "tcp.analysis.zero_window"]


def tshark(pcap):
    cmd = [TSHARK, "-r", pcap, "-o", "tcp.relative_sequence_numbers:FALSE", "-o", "tcp.analyze_sequence_numbers:TRUE",
           "-T", "fields", "-E", "separator=|", "-E", "header=y"]
    for f in FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    lines = out.strip().splitlines()
    header = lines[0].split("|")
    return [dict(zip(header, line.split("|"))) for line in lines[1:]]


@unittest.skipUnless(TSHARK, "tshark not found")
class TestWiresharkLabels(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script_path = os.path.abspath("tcp_trace_generator.py")
        cls.output_dir = os.path.join("test_output", "tshark")
        os.makedirs(cls.output_dir, exist_ok=True)

    def generate(self, name, args):
        pcap = os.path.join(self.output_dir, name + ".pcap")
        log = os.path.join(self.output_dir, name + "_log.txt")
        result = subprocess.run([sys.executable, self.script_path] + args + ["-o", pcap, "--rto-log", log],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        with open(log) as fh:
            return tshark(pcap), list(csv.DictReader(fh))

    def test_fast_retransmit_labels(self):
        print("\nRunning Wireshark Fast Retransmit Labels Test...")
        isn = 2233445566
        frames, log = self.generate("fast_retransmit", [
            "40", "--loss", "8", "--accept-out-of-order", "--client-isn", str(isn), "--server-isn", "3344556677",
            "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1", "--close", "fin"])
        lost_seq = str(isn + 7 * MSS)

        dupacks = [f for f in frames if f["tcp.analysis.duplicate_ack_num"]]
        self.assertEqual([f["tcp.analysis.duplicate_ack_num"] for f in dupacks], [str(i) for i in range(1, 8)])
        self.assertTrue(all(f["ip.src"] == "10.0.0.1" and f["tcp.ack"] == lost_seq for f in dupacks))
        self.assertEqual([f["frame.number"] for f in dupacks], [str(n) for n in range(23, 30)])

        fast = [f for f in frames if f["tcp.analysis.fast_retransmission"]]
        self.assertEqual(len(fast), 1, "Exactly one Fast Retransmission expected")
        self.assertEqual((fast[0]["frame.number"], fast[0]["tcp.seq"], fast[0]["ip.src"]), ("30", lost_seq, "10.0.0.2"))
        self.assertEqual(int(fast[0]["frame.number"]), int(dupacks[-1]["frame.number"]) + 1)
        # The fast retransmission is the only retransmission; nothing is flagged by timeout
        self.assertEqual([f["frame.number"] for f in frames if f["tcp.analysis.retransmission"]], ["30"])
        self.assertFalse(any(f["tcp.analysis.rto"] for f in frames))
        for field in ("tcp.analysis.out_of_order", "tcp.analysis.spurious_retransmission",
                      "tcp.analysis.window_update", "tcp.analysis.zero_window"):
            self.assertFalse(any(f[field] for f in frames), f"Unexpected label {field}")
        self.assertFalse(any(r["Event"] == "RTO Timeout" for r in log))
        self.assertTrue(any(r["Event"] == "Fast Retransmit (Reno)" for r in log))

        # Orderly close, unlabelled, with the addresses of the exercise
        tail = frames[-4:]
        self.assertEqual([f["tcp.flags.str"].replace("·", "") for f in tail], ["AF", "A", "AF", "A"])
        self.assertEqual([f["ip.src"] for f in tail], ["10.0.0.2", "10.0.0.1", "10.0.0.1", "10.0.0.2"])
        self.assertTrue(all(f["tcp.srcport"] == "12345" for f in frames if f["ip.src"] == "10.0.0.2"))
        self.assertEqual(len(frames), 73)

    def test_rto_labels(self):
        print("\nRunning Wireshark RTO Labels Test...")
        isn = 1122334455
        frames, log = self.generate("rto", ["24", "--loss", "8-15", "--client-isn", str(isn),
                                            "--server-isn", "987654321", "--close", "fin"])
        retrans = [f for f in frames if f["tcp.analysis.retransmission"]]
        self.assertEqual([f["tcp.seq"] for f in retrans], [str(isn + i * MSS) for i in range(7, 15)],
                         "Segments 8 to 15 must be retransmitted once each, in order")
        self.assertFalse(any(f["tcp.analysis.fast_retransmission"] for f in frames))
        self.assertFalse(any(f["tcp.analysis.duplicate_ack_num"] for f in frames))
        self.assertFalse(any(f["tcp.analysis.spurious_retransmission"] for f in frames))

        # Wireshark's RTO of the first retransmission is the simulator's RTO at the timeout
        timeouts = [r for r in log if r["Event"] == "RTO Timeout"]
        self.assertEqual(len(timeouts), 1)
        before = [r for r in log if float(r["Time"]) < float(timeouts[0]["Time"])][-1]
        self.assertAlmostEqual(float(retrans[0]["tcp.analysis.rto"]), float(before["RTO"]), places=3)
        self.assertEqual(retrans[0]["tcp.seq"], timeouts[0]["Seq"])
        # After the timeout the sender restarts in slow start: 1, 2, 4 retransmissions per RTT
        self.assertEqual(float(timeouts[0]["Cwnd"]), 1.0)
        self.assertEqual(timeouts[0]["Ssthresh"], "4")


if __name__ == "__main__":
    unittest.main()
