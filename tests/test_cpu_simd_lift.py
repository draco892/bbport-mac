"""Fail-closed boundaries of the register-only SIMD/FP experiment."""
import json
import sys
import unittest

from paths import ROOT
sys.path.insert(0, str(ROOT / 'recompiler'))
from simd_lift import decode, lift


class SimdLiftTests(unittest.TestCase):
    def test_fixture_contracts_decode_and_emit(self):
        fixtures = json.loads((ROOT / 'recompiler/simd_fixtures.json').read_text())
        for name, code in fixtures.items():
            with self.subTest(name=name):
                instructions = decode(bytes.fromhex(code))
                self.assertTrue(instructions)
                self.assertIn('label %reject', lift(bytes.fromhex(code), name))

    def test_rejects_everything_outside_the_register_contract(self):
        invalid = ['', 'c3', '0f58c1', '0f58c1c390', '660f', '660f58',
                   '66660f58c1c3', '480f58c1c3', 'c5f858c1c3',
                   '0f5801c3', '0f58c2c3', '0f58d1c3', '660f70c1',
                   '660f72f0', '660f73e001c3', '660f72c001c3',
                   'f30f70c11bc3', '0f2ec1c3', '0fae17c3',
                   '0f58c1eb00c3', '0f58c1e800000000c3']
        for code in invalid:
            with self.subTest(code=code), self.assertRaises(ValueError):
                lift(bytes.fromhex(code), 'fixture')

    def test_rejects_symbol_injection(self):
        for name in ('', 'é', 'f() {', 'x-y'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                lift(bytes.fromhex('0f58c1c3'), name)

    def test_packed_shift_counts_do_not_use_x86_scalar_masking(self):
        # PSLLD counts >=32 give zero; PSRAD clamps to31. Never emit LLVM
        # shifts >= the lane width, which would introduce poison values.
        logical = lift(bytes.fromhex('660f72f020c3'), 'logical')
        arithmetic = lift(bytes.fromhex('660f72e0ffc3'), 'arithmetic')
        self.assertIn('zeroinitializer', logical)
        self.assertNotIn(' = shl ', logical)
        self.assertIn('ashr <4 x i32>', arithmetic)
        self.assertIn('<i32 31, i32 31, i32 31, i32 31>', arithmetic)

    def test_scalar_and_packed_lane_counts(self):
        scalar = lift(bytes.fromhex('f30f58c1c3'), 'scalar')
        packed = lift(bytes.fromhex('0f58c1c3'), 'packed')
        self.assertEqual(scalar.count('call i32 @bb_fp32'), 1)
        self.assertEqual(packed.count('call i32 @bb_fp32'), 4)
        self.assertNotIn(' = fadd ', scalar)


if __name__ == '__main__':
    unittest.main()
