"""Tests of the endpoint, close, bandwidth, summary and RTT-log options."""
import csv
import io
import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET

from scapy.all import rdpcap, IP, TCP

MSS = 1460
# Same scenario as docs/ejemplo-estandar.pcap: 40 segments, segment 8 lost, fast retransmit
V3 = ["40", "--loss", "8", "--accept-out-of-order", "--client-isn", "2233445566",
      "--server-isn", "3344556677", "--client-ip", "10.0.0.2", "--server-ip", "10.0.0.1", "--close", "fin"]


def read_csv(path):
    """Rows of a CSV written by the generator, skipping the '#' comment header."""
    with open(path, newline="", encoding="utf-8") as fh:
        lines = [line for line in fh if not line.startswith("#")]
    return list(csv.DictReader(io.StringIO("".join(lines))))


def comment_lines(path):
    with open(path, encoding="utf-8") as fh:
        return [line.rstrip("\n") for line in fh if line.startswith("#")]


class TestFeatures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script_path = os.path.abspath("tcp_trace_generator.py")
        cls.output_dir = os.path.join("test_output", "features")
        os.makedirs(cls.output_dir, exist_ok=True)

    def paths(self, name, *extra):
        base = os.path.join(self.output_dir, name)
        return [base + ".pcap", base + "_log.txt"] + [base + e for e in extra]

    def run_script(self, args):
        return subprocess.run([sys.executable, self.script_path] + args, capture_output=True, text=True)

    def generate(self, name, args, summary=False, rtt=False):
        pcap, log = self.paths(name)
        cmd = args + ["-o", pcap, "--rto-log", log]
        if summary:
            cmd += ["--summary", self.paths(name, "_summary.csv")[2]]
        if rtt:
            cmd += ["--rtt-log", self.paths(name, "_rtt.csv")[2]]
        result = self.run_script(cmd)
        self.assertEqual(result.returncode, 0, f"Script failed with error: {result.stderr}")
        return sorted(rdpcap(pcap), key=lambda p: float(p.time)), log

    # ---- (1) --client-ip / --server-ip / --client-port / --server-port ----

    def test_custom_endpoints_in_pcap_and_csv(self):
        print("\nRunning Custom Endpoints Test...")
        pkts, _ = self.generate("endpoints", ["6", "--client-ip", "192.0.2.1", "--server-ip", "192.0.2.2",
                                              "--client-port", "40000", "--server-port", "8080"],
                                summary=True, rtt=True)
        client = [p for p in pkts if p[IP].src == "192.0.2.1"]
        server = [p for p in pkts if p[IP].src == "192.0.2.2"]
        self.assertEqual(len(client) + len(server), len(pkts))
        self.assertTrue(all(p[IP].dst == "192.0.2.2" and p[TCP].sport == 40000 and p[TCP].dport == 8080 for p in client))
        self.assertTrue(all(p[IP].dst == "192.0.2.1" and p[TCP].sport == 8080 and p[TCP].dport == 40000 for p in server))
        self.assertTrue(any(len(p[TCP].payload) > 0 for p in client), "Client data expected")
        self.assertEqual(pkts[0][TCP].flags, "S")
        self.assertEqual(pkts[0][IP].src, "192.0.2.1")
        endpoints = "# client=192.0.2.1:40000 server=192.0.2.2:8080"
        for name in ("endpoints_summary.csv", "endpoints_rtt.csv"):
            path = os.path.join(self.output_dir, name)
            self.assertTrue(comment_lines(path)[0].startswith(endpoints), f"{name} does not state the endpoints")

    def test_default_endpoints_unchanged(self):
        pkts, _ = self.generate("endpoints_default", ["4"])
        self.assertEqual(pkts[0][IP].src, "10.0.0.1")
        self.assertEqual(pkts[0][IP].dst, "10.0.0.2")
        self.assertEqual((pkts[0][TCP].sport, pkts[0][TCP].dport), (12345, 80))

    def test_invalid_endpoints_are_rejected(self):
        for args, text in ((["--client-ip", "1.2.3"], "--client-ip"),
                           (["--server-ip", "not-an-ip"], "--server-ip"),
                           (["--client-ip", "10.0.0.5", "--server-ip", "10.0.0.5"], "must differ"),
                           (["--client-port", "0"], "--client-port"),
                           (["--server-port", "70000"], "--server-port")):
            result = self.run_script(["5"] + args)
            self.assertNotEqual(result.returncode, 0, args)
            self.assertIn(text, result.stderr)

    # ---- (2) --close ----

    def test_close_none_by_default(self):
        pkts, _ = self.generate("close_none", ["5"])
        self.assertFalse(any("F" in p[TCP].flags for p in pkts))

    def test_close_fin_four_way(self):
        print("\nRunning Close FIN (4-way) Test...")
        segments = 5
        pkts, log = self.generate("close_fin", [str(segments), "--close", "fin", "--client-isn", "1", "--server-isn", "100"])
        client_fin_seq = 1 + segments * MSS
        tail = pkts[-4:]
        self.assertEqual([str(p[TCP].flags) for p in tail], ["FA", "A", "FA", "A"])
        c_fin, s_ack, s_fin, c_ack = tail
        self.assertEqual((c_fin[IP].src, c_fin[TCP].seq, c_fin[TCP].ack), ("10.0.0.1", client_fin_seq, 101))
        self.assertEqual((s_ack[IP].src, s_ack[TCP].seq, s_ack[TCP].ack), ("10.0.0.2", 101, client_fin_seq + 1))
        self.assertEqual((s_fin[IP].src, s_fin[TCP].seq, s_fin[TCP].ack), ("10.0.0.2", 101, client_fin_seq + 1))
        self.assertEqual((c_ack[IP].src, c_ack[TCP].seq, c_ack[TCP].ack), ("10.0.0.1", client_fin_seq + 1, 102))
        times = [float(p.time) for p in tail]
        self.assertEqual(times, sorted(times))
        # The server's ACK cannot reach the client before one RTT after the FIN
        self.assertGreaterEqual(times[1] - times[0], 0.1 - 1e-6)
        self.assertEqual(sum(1 for p in pkts if "F" in p[TCP].flags), 2)
        with open(log) as fh:
            events = [row["Event"] for row in csv.DictReader(fh)]
        for event in ("FIN Sent", "FIN Acked", "FIN Received"):
            self.assertIn(event, events)

    def test_close_fin3_three_way(self):
        print("\nRunning Close FIN (3-way) Test...")
        segments = 4
        pkts, _ = self.generate("close_fin3", [str(segments), "--close", "fin3", "--client-isn", "1", "--server-isn", "100"])
        client_fin_seq = 1 + segments * MSS
        tail = pkts[-3:]
        self.assertEqual([str(p[TCP].flags) for p in tail], ["FA", "FA", "A"])
        c_fin, s_fin, c_ack = tail
        self.assertEqual((c_fin[TCP].seq, c_fin[TCP].ack), (client_fin_seq, 101))
        self.assertEqual((s_fin[IP].src, s_fin[TCP].seq, s_fin[TCP].ack), ("10.0.0.2", 101, client_fin_seq + 1))
        self.assertEqual((c_ack[TCP].seq, c_ack[TCP].ack), (client_fin_seq + 1, 102))
        self.assertEqual(sum(1 for p in pkts if "F" in p[TCP].flags), 2)

    def test_close_after_loss_acknowledges_everything(self):
        """The FIN must leave only after the last data segment has been acknowledged."""
        segments = 20
        pkts, _ = self.generate("close_loss", [str(segments), "--loss", "10", "--close", "fin", "--client-isn", "1"])
        fin = next(p for p in pkts if "F" in p[TCP].flags and p[IP].src == "10.0.0.1")
        before = [p for p in pkts if float(p.time) < float(fin.time) and p[IP].src == "10.0.0.2"]
        self.assertEqual(max(p[TCP].ack for p in before), 1 + segments * MSS)
        self.assertEqual(fin[TCP].seq, 1 + segments * MSS)

    # ---- (3) --bandwidth ----

    def test_bandwidth_serializes_client_frames(self):
        print("\nRunning Bandwidth Serialization Test...")
        bandwidth = 1e6
        pkts, _ = self.generate("bandwidth", ["12", "--bandwidth", "1M", "--client-isn", "1", "--close", "fin"])
        for side in ("10.0.0.1", "10.0.0.2"):
            frames = [p for p in pkts if p[IP].src == side]
            for a, b in zip(frames, frames[1:]):
                self.assertGreaterEqual(float(b.time) - float(a.time), len(a) * 8 / bandwidth - 1e-6,
                                        f"Frames at {float(a.time):.6f} and {float(b.time):.6f} overlap on the link")
        # Without --bandwidth a burst leaves at the same instant (previous behaviour)
        pkts, _ = self.generate("bandwidth_off", ["12", "--client-isn", "1"])
        data = [p for p in pkts if len(p[TCP].payload) > 0]
        self.assertEqual(float(data[3].time), float(data[4].time))  # third burst: segments 4 to 7

    def test_bandwidth_delays_delivery(self):
        """The first ACK arrives later when the segment takes time to serialize."""
        fast, _ = self.generate("bandwidth_fast", ["3", "--client-isn", "1"])
        slow, _ = self.generate("bandwidth_slow", ["3", "--client-isn", "1", "--bandwidth", "100k"])
        first_ack = lambda pkts: next(float(p.time) for p in pkts if p[IP].src == "10.0.0.2" and "S" not in p[TCP].flags)
        self.assertGreater(first_ack(slow) - first_ack(fast), 1514 * 8 / 100e3 - 1e-3)

    def test_bandwidth_validation(self):
        result = self.run_script(["5", "--bandwidth", "1M", "--classroom"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--classroom", result.stderr)
        result = self.run_script(["5", "--bandwidth", "fast"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid bandwidth", result.stderr)
        for text in ("1000000", "1M", "1Mbps", "1000k", "0.001G"):
            pcap = os.path.join(self.output_dir, "bw_units.pcap")
            result = self.run_script(["2", "--bandwidth", text, "-o", pcap, "--rto-log", pcap + ".txt"])
            self.assertEqual(result.returncode, 0, f"{text!r} rejected: {result.stderr}")

    # ---- (4) --summary ----

    def test_summary_per_burst(self):
        print("\nRunning Per-burst Summary Test...")
        pkts, _ = self.generate("summary", V3, summary=True)
        summary = os.path.join(self.output_dir, "summary_summary.csv")
        rows = read_csv(summary)
        self.assertEqual(rows[0].keys().__len__(), 10)
        self.assertEqual(list(rows[0].keys()), ["Rafaga", "Tramas", "Tiempo", "Segmentos", "Nuevos",
                                                "Retransmitidos", "EnVuelo", "VC", "Umbral", "Modo"])
        # Slow start: 1, 2, 4, 8 new segments per RTT
        self.assertEqual([r["Nuevos"] for r in rows[:4]], ["1", "2", "4", "8"])
        self.assertEqual([r["VC"] for r in rows[:4]], ["1", "2", "4", "8"])
        self.assertEqual(rows[3]["Tramas"], "15-22")
        self.assertEqual((rows[3]["Umbral"], rows[3]["Modo"]), ("64", "AL"))
        # Fast retransmit burst: the lost segment plus three new ones, in fast recovery
        fr = rows[4]
        self.assertEqual(fr["Tramas"], "30-33")
        self.assertEqual((fr["Segmentos"], fr["Nuevos"], fr["Retransmitidos"]), ("4", "3", "1"))
        self.assertEqual((fr["EnVuelo"], fr["VC"], fr["Umbral"], fr["Modo"]), ("11", "11", "4", "RR"))
        self.assertEqual(rows[5]["Modo"], "EC")
        self.assertIn("/", rows[5]["VC"])  # fractional cwnd in congestion avoidance, e.g. "4 + 2/4"
        # The frame numbers point at client data segments and every data segment is counted once
        total = 0
        for r in rows:
            first, _, last = r["Tramas"].partition("-")
            first, last = int(first), int(last or first)
            for n in range(first, last + 1):
                self.assertTrue(len(pkts[n - 1][TCP].payload) > 0 and pkts[n - 1][IP].src == "10.0.0.2", f"Frame {n}")
            total += int(r["Segmentos"])
        self.assertEqual(total, sum(1 for p in pkts if len(p[TCP].payload) > 0))
        self.assertEqual(sum(int(r["Nuevos"]) for r in rows), 40)
        self.assertEqual(sum(int(r["Retransmitidos"]) for r in rows), 1)
        self.assertTrue(comment_lines(summary)[0].startswith("# client=10.0.0.2:12345 server=10.0.0.1:80"))

    def test_summary_after_timeout(self):
        rows = None
        self.generate("summary_rto", ["24", "--loss", "8-15", "--client-isn", "1"], summary=True)
        rows = read_csv(os.path.join(self.output_dir, "summary_rto_summary.csv"))
        after = rows[4]
        self.assertEqual((after["Segmentos"], after["Nuevos"], after["Retransmitidos"]), ("1", "0", "1"))
        self.assertEqual((after["EnVuelo"], after["VC"], after["Umbral"], after["Modo"]), ("1", "1", "4", "AL"))

    def test_summary_english_labels(self):
        self.generate("summary_en", V3 + ["--diagram-lang", "en"], summary=True)
        rows = read_csv(os.path.join(self.output_dir, "summary_en_summary.csv"))
        self.assertEqual(list(rows[0].keys())[:2], ["Burst", "Frames"])
        self.assertEqual({r["Mode"] for r in rows}, {"SS", "FR", "CA"})

    # ---- (5) --rtt-log ----

    def test_rtt_log_samples_and_rto(self):
        print("\nRunning RTT/RTO Log Test...")
        _, log = self.generate("rtt", V3, rtt=True)
        rtt_log = os.path.join(self.output_dir, "rtt_rtt.csv")
        header = "\n".join(comment_lines(rtt_log))
        for text in ("RFC 6298", "Karn", "SRTT = SampleRTT, RTTVAR = SampleRTT / 2", "alpha = 0.125", "beta = 0.25",
                     "RTO = SRTT + max(G, K * RTTVAR)", "G = 0.1", "K = 4", "max(RTO, 0.2 s)", "doubled"):
            self.assertIn(text, header, f"Convention not stated: {text}")
        rows = read_csv(rtt_log)
        self.assertEqual(rows[0]["Event"], "Initial RTO")
        self.assertEqual(rows[0]["RTO"], "1.0000")
        first = rows[1]
        self.assertEqual(first["Event"], "RTT Sample")
        self.assertEqual(first["Seq"], "2233445566")
        self.assertEqual((first["SentAt"], first["Time"]), ("0.1004", "0.4005"))
        self.assertEqual((first["SampleRTT"], first["SRTT"], first["RTTVAR"], first["RTO"]),
                         ("0.3001", "0.3001", "0.1501", "0.9003"))
        self.assertIn("first sample", first["Calc"])
        second = rows[2]
        self.assertEqual((second["SampleRTT"], second["SRTT"], second["RTTVAR"], second["RTO"]),
                         ("0.1001", "0.2751", "0.1625", "0.9253"))
        self.assertIn("RTTVAR = 0.75*0.1501 + 0.25*|0.3001 - 0.1001| = 0.1625", second["Calc"])
        self.assertIn("SRTT = 0.875*0.3001 + 0.125*0.1001 = 0.2751", second["Calc"])
        self.assertIn("RTO = 0.2751 + max(0.1, 4*0.1625) = 0.9253", second["Calc"])
        karn = [r for r in rows if r["Event"] == "No sample (Karn)"]
        self.assertEqual(len(karn), 1)
        self.assertEqual(karn[0]["Seq"], str(2233445566 + 7 * MSS))
        self.assertEqual(karn[0]["RTO"], rows[rows.index(karn[0]) - 1]["RTO"])
        # Every RTO written in the RTT log is the RTO the state log shows at that time
        with open(log) as fh:
            state = {(r["Time"], r["RTO"]) for r in csv.DictReader(fh)}
        for r in rows[1:]:
            self.assertIn((r["Time"], r["RTO"]), state)
        # One row (sample or Karn) per new ACK in the state log
        samples = [r for r in rows if r["Event"] == "RTT Sample"]
        with open(log) as fh:
            new_acks = [r for r in csv.DictReader(fh) if r["Event"].startswith("ACK Received")]
        self.assertEqual(len(samples) + len(karn), len(new_acks))
        self.assertGreater(len(samples), 10)

    def test_rtt_log_backoff(self):
        self.generate("rtt_rto", ["24", "--loss", "8-15", "--client-isn", "1"], rtt=True)
        rows = read_csv(os.path.join(self.output_dir, "rtt_rto_rtt.csv"))
        backoff = [r for r in rows if r["Event"] == "Backoff"]
        self.assertEqual(len(backoff), 1)
        previous = rows[rows.index(backoff[0]) - 1]
        self.assertAlmostEqual(float(backoff[0]["RTO"]), 2 * float(previous["RTO"]), places=3)
        self.assertIn("RTO = 2 *", backoff[0]["Calc"])
        self.assertEqual(rows[rows.index(backoff[0]) + 1]["Event"], "No sample (Karn)")

    def test_rtt_log_classroom(self):
        self.generate("rtt_classroom", ["6", "--classroom", "--classroom-rto-slots", "4"], rtt=True)
        rows = read_csv(os.path.join(self.output_dir, "rtt_classroom_rtt.csv"))
        self.assertEqual([r["Event"] for r in rows], ["Fixed RTO (classroom)"])
        self.assertEqual(rows[0]["RTO"], "0.2000")

    # ---- Classroom mode keeps working with the new options ----

    def test_classroom_with_close_summary_and_diagram(self):
        print("\nRunning Classroom Compatibility Test...")
        svg = os.path.join(self.output_dir, "classroom_new.svg")
        pkts, _ = self.generate("classroom_new", ["14", "--classroom", "--classroom-rto-slots", "4", "--loss", "11",
                                                   "--accept-out-of-order", "--client-isn", "1024", "--server-isn", "2047",
                                                   "--client-mss", "64", "--server-mss", "128", "--ssthresh", "2",
                                                   "--close", "fin", "--diagram", svg], summary=True, rtt=True)
        slot = 0.05
        t0 = float(pkts[0].time)
        for p in pkts:
            if p[IP].src == "10.0.0.1":  # client transmissions are aligned to the slot grid
                t = float(p.time) - t0
                self.assertAlmostEqual(t / slot, round(t / slot), delta=1e-4, msg=f"Client frame at {t} off the grid")
        self.assertEqual([str(p[TCP].flags) for p in pkts[-4:]], ["FA", "A", "FA", "A"])
        texts = [t.text for t in ET.parse(svg).getroot().iter("{http://www.w3.org/2000/svg}text") if t.text]
        self.assertEqual(sum(1 for t in texts if " FIN " in t), 2)
        rows = read_csv(os.path.join(self.output_dir, "classroom_new_summary.csv"))
        self.assertEqual(sum(int(r["Nuevos"]) for r in rows), 14)
        self.assertEqual(sum(int(r["Retransmitidos"]) for r in rows), 1)


if __name__ == "__main__":
    unittest.main()
