import unittest
from arp_recon.core import run

class TestCore(unittest.TestCase):
    def test_run(self):
        run()  # Tester la fonction run

if __name__ == '__main__':
    unittest.main()


# pour tous lancer : python3 -m unittest 
# python3 -m unittest test_core.py
# python3 -m unittest test_detector.py
# python3 -m unittest test_analyzer.py