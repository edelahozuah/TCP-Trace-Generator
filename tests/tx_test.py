import unittest
import os
import subprocess
import shutil

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

if __name__ == '__main__':
    unittest.main()
