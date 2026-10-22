"""Static contracts for guest code registries and bounded indirect call graphs."""
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from indirect_lift import assemble_indirect, decode_indirect, lift_indirect
from stack_lift import analyze, lift_stack


def specification(operand='rax', targets=None):
    return {'caller': {'address': 0, 'parts': ['534889f0', {'indirect': operand,
            'targets': ['leaf'] if targets is None else targets}, '5bc3']},
            'leaf': {'address': 256, 'parts': ['4889f0c3']}}


class CpuIndirectLiftTests(unittest.TestCase):
    def test_rejects_missing_and_unused_call_contracts(self):
        functions, targets = assemble_indirect(specification())
        for contract in ({}, {**targets, ('leaf', 0): ('leaf',)}):
            with self.subTest(contract=contract), self.assertRaisesRegex(ValueError, 'target set|non-call site'):
                analyze(functions, indirect_targets=contract, decoder_extra=decode_indirect)

    def test_rejects_invalid_target_sets(self):
        for targets in ([], ['absent'], ['leaf', 'leaf'], [1], [[]]):
            with self.subTest(targets=targets), self.assertRaisesRegex(ValueError, 'invalid indirect target set'):
                lift_indirect(specification(targets=targets))

    def test_rejects_undefined_register_target(self):
        spec = specification()
        spec['caller']['parts'][0] = '53'
        with self.assertRaisesRegex(ValueError, 'undefined rax'):
            lift_indirect(spec)

    def test_rejects_unaligned_indirect_call(self):
        spec = specification()
        spec['caller']['parts'][0] = '4889f0'
        with self.assertRaisesRegex(ValueError, '16-byte aligned before CALL'):
            lift_indirect(spec)

    def test_rejects_indirect_cycles(self):
        with self.assertRaisesRegex(ValueError, 'recursive/cyclic'):
            lift_indirect(specification(targets=['caller']))
        spec = specification(targets=['leaf', 'caller'])
        with self.assertRaisesRegex(ValueError, 'recursive/cyclic'):
            lift_indirect(spec)

    def test_worst_case_target_stack_is_bounded(self):
        spec = specification(targets=['leaf', 'deep'])
        for i in range(4):
            spec[f'deep{i}' if i else 'deep'] = {
                'address': (i + 2) * 256,
                'parts': ['4883ec78', {'call': f'deep{i + 1}' if i < 3 else 'leaf'}, '4883c478c3']}
        with self.assertRaisesRegex(ValueError, 'nested calls exceed'):
            lift_indirect(spec)

    def test_rejects_invalid_memory_call_operands(self):
        for code in ('53ff5739c3', '53ff57ffc3', '53ff57'):
            functions = {'f': {'address': 0, 'code': bytes.fromhex(code)}}
            with self.subTest(code=code), self.assertRaisesRegex(ValueError, 'indirect memory'):
                analyze(functions, indirect_targets={}, decoder_extra=decode_indirect)

    def test_rejects_unsupported_fixture_operands(self):
        for operand in (-1, 57, 'r12', True):
            with self.subTest(operand=operand), self.assertRaisesRegex(ValueError, 'unsupported indirect fixture operand'):
                assemble_indirect(specification(operand))

    def test_rejects_guest_code_base_overflow(self):
        functions, targets = assemble_indirect(specification())
        for base in (-1, 1 << 64, (1 << 64) - 1):
            with self.subTest(base=base), self.assertRaisesRegex(ValueError, 'invalid guest code base'):
                lift_stack(functions, indirect_targets=targets, decoder_extra=decode_indirect, code_base=base)


if __name__ == '__main__':
    unittest.main()
