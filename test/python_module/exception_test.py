import unittest
import sys
from binascii import hexlify

sys.path.append("../build/src/python_binding")

import libl15_core_pybind as l15

class ExceptionsTestCase(unittest.TestCase):
    def test_call_plugin_function(self):
        try:
            str = l15.Version()
            self.assertFalse(str == "")
        except:
            self.fail("Library cannot be loaded")

    def test_std_exception(self):
        network = "wrongNetwork"
        try:
            l15.CreateInscriptionBuilder(network)
            self.fail("exception was not thrown")
        except Exception as e:
            self.assertEqual("wrong chain mode: " + network, e.args[0])

    def test_l15_exception(self):
        try:
            builder = l15.CreateInscriptionBuilder("regtest")

            builder.UTXO("abcdefgh", 1, "1").\
                Data("text", hexlify("content".encode()).decode()).\
                FeeRate("0.00005").\
                Sign("34234234")

            self.fail("exception was not thrown")
        except Exception as e:
            self.assertEqual("No destination public key is provided", e.args[0])


if __name__ == '__main__':
    unittest.main()
