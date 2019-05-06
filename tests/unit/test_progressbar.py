import unittest
import scanner
import math


class ProgressbarCase(unittest.TestCase):
    def test_progress(self):
        maxitems = 10
        pb = scanner.ProgressBar(length=100, maxitems=maxitems)
        values = [0, 1, 2, 8, 9]
        for v in values:
            self.assertEqual(pb._get_percentage(v), math.floor((v*100)/10))

        values = [None, 'test', '', maxitems+1]
        for v in values:
            self.assertRaises(ValueError, pb._get_percentage, v)


if __name__ == '__main__':
    unittest.main()
