import unittest
import ipscanner


class IPscannerTest(unittest.TestCase):
    def test_availableMethods(self):
        abstract = ipscanner.AbstractScanner('127.0.0.1', 'eth0')
        am = abstract.available_methods()
        self.assertGreater(len(am), 0)
