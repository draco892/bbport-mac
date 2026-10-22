"""Safety contracts for explicit stacks and statically resolved direct calls."""
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from stack_lift import analyze, assemble


class CpuStackLiftTests(unittest.TestCase):
    def test_rejects_invalid_stack_state(self):
        cases = {
            'uninitialized push': ('50c3', 'undefined rax'),
            'pop of return address': ('58c3', 'protected stack data'),
            'uninitialized local': ('4883ec10488b04244883c410c3', 'uninitialized stack read'),
            'deallocated local': ('4883ec10488934244883c4104883ec10488b0424c3', 'uninitialized stack read'),
            'red-zone store': ('48897424f8c3', 'outside allocated frame'),
            'return-address overwrite': ('48893424c3', 'outside allocated frame'),
            'unaligned stack operand': ('4883ec104889742401c3', 'outside allocated frame'),
            'uninitialized frame pointer': ('488b45f8c3', 'not a local frame pointer'),
            'frame pointer escape': ('5558c3', 'frame pointer escapes'),
            'lost RBX': ('4889f34889f0c3', 'restore RSP, RBX and RBP'),
            'lost RBP': ('554889e54889f04883c408c3', 'restore RSP, RBX and RBP'),
            'unbalanced RSP': ('4883ec084889f0c3', 'restore RSP, RBX and RBP'),
            'invalid LEAVE': ('c9c3', 'invalid LEAVE frame'),
            'saved RBP overwritten': ('554889e5488975004889f0c9c3', 'restore RSP, RBX and RBP'),
            'oversized frame': ('4883ec785356c3', 'local frame exceeds'),
            'negative adjustment': ('4883ec80c3', 'positive aligned imm8'),
            'zero adjustment': ('4883ec00c3', 'positive aligned imm8'),
            'truncated adjustment': ('4883ec', 'truncated stack adjustment'),
            'truncated displacement': ('488b4424', 'truncated stack displacement'),
            'truncated direct call': ('e80102', 'truncated direct call'),
            'missing return': ('4889f0', 'missing RET'),
            'unreachable bytes': ('4889f0c34889f0c3', 'unreachable code'),
            'indirect call': ('ffd0c3', 'unsupported encoding'),
            'conditional stack CFG': ('4889f07400c3', 'unsupported stack/call operation'),
        }
        for name, (code, reason) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, reason):
                analyze({'fixture': {'address': 0, 'code': bytes.fromhex(code)}})

    def test_local_frame_boundary_is_accepted(self):
        functions = {'fixture': {'address': 0, 'code': bytes.fromhex('4883ec78534889f05b4883c478c3')}}
        self.assertEqual(analyze(functions)['fixture']['required_stack'], 128)

    def test_rejects_bad_call_targets(self):
        for target in (0x1001, 0x2000):
            code = b'\x53\xe8' + (target - 6).to_bytes(4, 'little', signed=True) + b'\x5b\xc3'
            with self.subTest(target=target), self.assertRaisesRegex(ValueError, 'known function entry'):
                analyze({'caller': {'address': 0, 'code': code},
                         'callee': {'address': 0x1000, 'code': bytes.fromhex('4889f0c3')}})

    def test_rejects_unaligned_call(self):
        functions = assemble({'caller': {'address': 0, 'parts': [{'call': 'callee'}, 'c3']},
                              'callee': {'address': 256, 'parts': ['4889f0c3']}})
        with self.assertRaisesRegex(ValueError, '16-byte aligned before CALL'):
            analyze(functions)

    def test_rejects_recursive_call_graphs(self):
        specs = [
            {'a': {'address': 0, 'parts': ['53', {'call': 'a'}, '5bc3']}},
            {'a': {'address': 0, 'parts': ['53', {'call': 'b'}, '5bc3']},
             'b': {'address': 256, 'parts': ['53', {'call': 'a'}, '5bc3']}},
        ]
        for spec in specs:
            with self.subTest(functions=list(spec)), self.assertRaisesRegex(ValueError, 'recursive/cyclic'):
                analyze(assemble(spec))

    def test_rejects_excessive_nested_stack_use(self):
        spec = {f'f{i}': {'address': i * 256,
                         'parts': ['4883ec78', {'call': f'f{i + 1}'}, '4883c478c3']}
                for i in range(4)}
        spec['f4'] = {'address': 1024, 'parts': ['4889f0c3']}
        with self.assertRaisesRegex(ValueError, 'nested calls exceed'):
            analyze(assemble(spec))

    def test_rejects_overlapping_functions(self):
        for second in (0, 1):
            functions = {name: {'address': offset, 'code': bytes.fromhex('4889f0c3')}
                         for name, offset in [('a', 0), ('b', second)]}
            with self.subTest(address=second), self.assertRaisesRegex(ValueError, 'duplicate|overlapping'):
                analyze(functions)

    def test_rejects_invalid_callee_preservation(self):
        functions = assemble({'caller': {'address': 0, 'parts': ['53', {'call': 'callee'}, '5bc3']},
                              'callee': {'address': 256, 'parts': ['4889f34889f0c3']}})
        with self.assertRaisesRegex(ValueError, 'restore RSP, RBX and RBP'):
            analyze(functions)


if __name__ == '__main__':
    unittest.main()
