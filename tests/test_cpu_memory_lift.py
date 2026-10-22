"""Reject unsafe/undefined paths before emitting the synthetic memory AOT code."""
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from memory_lift import lift_memory


class CpuMemoryLiftRejectionTests(unittest.TestCase):
    def test_rejects_code_outside_the_contract(self):
        cases = {
            'empty': '',
            'truncated prefix': '48',
            'truncated operand': '488b',
            'truncated displacement': '488b47',
            'truncated branch': '488b0774',
            'different base register': '488b06c3',
            'indexed address': '488b0437c3',
            'negative displacement': '488b47ffc3',
            'load over boundary': '488b4739c3',
            'store over boundary': '488b0748897739c3',
            'undefined store input': '488907c3',
            'undefined return register': 'c3',
            'undefined compare input': '4839f0c3',
            'undefined branch flags': '4889f07400c3',
            'arithmetic clobbers flags': '488b074839f04801f07400c3',
            'unsupported test predicate': '488b074885c07c00c3',
            'missing return': '488b07',
            'unreachable trailing bytes': '4889f0c34889f0c3',
            'branch out of function': '4889f0eb7fc3',
            'branch into instruction': '4889f0eb014889f0c3',
            'backward branch': '4889f0ebfbc3',
            'undefined RAX on one incoming path': '4885f674034889f0c3',
            'incompatible flags at join': '488b074885f674034839f07400c3',
            'calls': '488b07e800000000c3',
            'atomics': 'f0480107c3',
            'guest TLS': '64488b07c3',
            'byte high-register store is not RSI': '488b078837c3',
        }
        for description, code in cases.items():
            with self.subTest(description=description), self.assertRaises(ValueError):
                lift_memory(bytes.fromhex(code), 'fixture')

    def test_rejects_symbol_injection(self):
        for name in ('fixture() {', 'a-b', 'é', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                lift_memory(bytes.fromhex('488b07c3'), name)


if __name__ == '__main__':
    unittest.main()
