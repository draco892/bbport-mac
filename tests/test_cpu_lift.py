"""Safety boundaries of the deliberately restricted P0 leaf translator."""
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from lift import lift


class CpuLiftRejectionTests(unittest.TestCase):
    def test_rejects_code_outside_the_leaf_contract(self):
        cases = {
            'empty': '',
            'undefined return register': 'c3',
            'undefined arithmetic input': '4801f0c3',
            'missing return': '4889f8',
            'truncated prefix': '48',
            'truncated shift': '4889f848c1e0',
            'memory access': '488b07c3',
            'call': '4889f8e800000000c3',
            'branch': '4889f8eb00c3',
            'flags consumer': '4889f8480f44c6c3',
            'trailing code': '4889f8c390',
            'unsupported return prefix': '4889f848c3',
        }
        for description, code in cases.items():
            with self.subTest(description=description), self.assertRaises(ValueError):
                lift(bytes.fromhex(code), 'leaf')

    def test_rejects_symbol_injection(self):
        for name in ('leaf() {', 'a-b', 'é', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                lift(bytes.fromhex('4889f8c3'), name)


if __name__ == '__main__':
    unittest.main()
