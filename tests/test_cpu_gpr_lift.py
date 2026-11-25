"""GPR/flag contract, literal answers, register decoding and oracle boundaries."""
import json
import sys
import unittest
from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from cpu_state import STATE, RFLAGS_INDEX, STATUS_INDEX
from gpr_lift import ARITHMETIC_FLAGS, decode, defined_flags, lift
from run_gpr import corpus, model, oracle_assembly


class GprLiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((ROOT / 'recompiler/gpr_fixtures.json').read_text())

    def test_all_fixtures_decode_and_lift(self):
        for name, code in self.fixtures.items():
            with self.subTest(name=name):
                decoded = decode(bytes.fromhex(code))
                self.assertTrue(decoded)
                ir = lift(bytes.fromhex(code), name)
                self.assertNotIn(' nsw ', ir)
                self.assertNotIn(' nuw ', ir)
                self.assertNotIn('inttoptr', ir)

    def test_all_register_copy_pairs_and_widths(self):
        for width in (32, 64):
            for dst in range(16):
                for src in range(16):
                    name = f'mov{width}_r{dst}_r{src}'
                    instruction, = decode(bytes.fromhex(self.fixtures[name]))
                    self.assertEqual((instruction.op, instruction.dst, instruction.src, instruction.width),
                                     ('mov', dst, src, width))

    def test_rejects_outside_the_contract(self):
        for code in ('', 'c3', '90c3', '4889c8', '48', '480f', '4889',
                     '488908c3', '488b01c3', '664889c8c3', '88e0c3',
                     '4801c8c390', '4801c8c3c3', '484801c8c3', '4a01c8c3',
                     '4801c8eb00c3', '4801c8e800000000c3', '48ffd0c3',
                     '4cffc0c3', '480f94c0c3', 'f04801c8c3', 'c3c3'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                lift(bytes.fromhex(code), 'fixture')

    def test_symbol_names_are_checked(self):
        for name in ('', 'é', 'f() {', 'x-y'):
            with self.assertRaises(ValueError):
                lift(bytes.fromhex('4889c8c3'), name)

    def test_literal_answers_agree_with_independent_math(self):
        records, _, known = corpus(0)
        self.assertEqual(len(known), 22)
        for index, name, expected in known:
            with self.subTest(name=name):
                self.assertEqual(model(bytes.fromhex(self.fixtures[name]), records[index]), expected)

    def test_logical_af_is_explicitly_undefined_until_overwritten(self):
        logical = bytes.fromhex('4831c8')
        move = bytes.fromhex('4889d8')
        inc = bytes.fromhex('48ffc0')
        self.assertEqual(defined_flags(logical + b'\xc3'), ARITHMETIC_FLAGS & ~16)
        self.assertEqual(defined_flags(logical + move + b'\xc3'), ARITHMETIC_FLAGS & ~16)
        self.assertEqual(defined_flags(logical + inc + b'\xc3'), ARITHMETIC_FLAGS)

    def test_compare_preserves_all_gprs_including_32_bit_upper_half(self):
        records, descriptions, known = corpus(0)
        for index, name, expected in known:
            if name.startswith(('cmp', 'test')):
                self.assertEqual(STATE.unpack(records[index])[:16], STATE.unpack(expected)[:16])

    def test_cmov32_zero_extends_even_when_false(self):
        ir = lift(bytes.fromhex(self.fixtures['cmov432_r0_r5']), 'cmov')
        self.assertIn('select i1', ir)
        self.assertIn('zext i32', ir)
        self.assertNotIn('store i32', ir.split('%status =')[0])

    def test_register_rsp_is_data_not_a_native_pointer(self):
        ir = lift(bytes.fromhex(self.fixtures['guest_rsp_arithmetic']), 'rsp')
        self.assertNotIn('inttoptr', ir)
        self.assertNotIn('alloca', ir)
        self.assertNotIn('call void', ir)

    def test_oracle_restores_native_stack_before_capturing_flags(self):
        code = bytes.fromhex(self.fixtures['guest_rsp_arithmetic'])
        assembly = oracle_assembly({'rsp': code})
        raw = assembly.index('.byte ')
        self.assertLess(raw, assembly.index('movq %rsp, %xmm13'))
        self.assertLess(assembly.index('movq %xmm14, %rsp'), assembly.index('pushfq', raw))
        self.assertNotIn('call ', assembly)
        self.assertEqual(assembly.count('\nret\n'), 1)

    def test_all_initial_flag_combinations_are_in_the_corpus(self):
        records, _, _ = corpus(0)
        observed = {STATE.unpack(record)[RFLAGS_INDEX] & ARITHMETIC_FLAGS for record in records}
        self.assertEqual(len(observed), 64)
        self.assertTrue(all(STATE.unpack(record)[STATUS_INDEX] == 0xa5a5a5a5 for record in records))


if __name__ == '__main__': unittest.main()
