import unittest
import sys

sys.path.append("../build/src/python_binding")

import libl15_core_pybind as l15

class MyTestCase(unittest.TestCase):
    def test_call_plugin_function(self):
        try:
            str = l15.Version()
            self.assertFalse(str == "")
        except:
            self.fail("Library cannot be loaded")

    def test_exception(self):
        network = "wrong network"
        try:
            l15.CreateInscriptionBuilder(network)
            self.fail("exception was not thrown")
        except Exception as e:
            self.assertEqual(e.args[0], network)


if __name__ == '__main__':
    unittest.main()
