import unittest
import scanner
import io as _io
import ipaddress


class ScannerCase(unittest.TestCase):
    def setUp(self) -> None:
        self.Static = scanner.Static()
        self.analyze_pool = scanner.AnalyzePool()

    def tearDown(self) -> None:
        pass

    def test_assign_ip(self) -> None:
        self.analyze_pool.set_ip("192.168.0.1")
        self.assertEqual(1, len(self.Static.ips))
        self.analyze_pool.set_ip("192.168.0.2")
        self.assertEqual(2, len(self.Static.ips))
        self.assertRaises(ipaddress.AddressValueError, self.analyze_pool.set_ip, "192.168.0.256")

    def test_assign_network(self) -> None:
        self.analyze_pool.set_network("192.168.0.0/24")
        self.assertEqual(254, len(self.Static.ips))
        self.assertRaises(ValueError, self.analyze_pool.set_network, "192.168.256.0/24")
        self.assertRaises(ValueError, self.analyze_pool.set_network, "192.168.0.0/33")

    def test_write_to_file(self):
        rv = self.analyze_pool.write_to_file()
        self.assertEqual(False, rv)

    def test_outputfile(self):
        rv = self.analyze_pool.set_outputfile('/tmp/test-fnc-lb')
        self.assertIsInstance(self.analyze_pool.outputfile, _io.TextIOWrapper)

    def test_methods(self):
        self.analyze_pool.set_methods([['ping', 'arping']])
        self.assertEqual(['ping', 'arping'], self.analyze_pool.methods)

    def test_empty_methods(self):
        self.analyze_pool.set_methods([])
        self.assertEqual(['ping'], self.analyze_pool.methods)
        

if __name__ == '__main__':
    unittest.main()
