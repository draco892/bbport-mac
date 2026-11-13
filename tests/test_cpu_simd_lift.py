"""Fail-closed boundaries of the register-only SIMD/FP experiment."""
import sys
import unittest

from paths import ROOT
sys.path.insert(0, str(ROOT / 'recompiler'))
from simd_lift import decode, lift
from run_simd import STATE, corpus, integer_model, load_fixtures
from cpu_state import MXCSR_INDEX, XMM_INDEX, OFFSETS, GPR_NAMES, xmm_offset


class SimdLiftTests(unittest.TestCase):
    def test_fixture_contracts_decode_and_emit(self):
        fixtures = load_fixtures()
        for name, code in fixtures.items():
            with self.subTest(name=name):
                instructions = decode(bytes.fromhex(code))
                self.assertTrue(instructions)
                self.assertIn('label %reject', lift(bytes.fromhex(code), name))

    def test_rejects_everything_outside_the_register_contract(self):
        invalid = ['', 'c3', '0f58c1', '0f58c1c390', '660f', '660f58',
                   '66660f58c1c3', '480f58c1c3', 'c5f858c1c3',
                   '0f5801c3', '66440f72f001c3', '41410f58c1c3', '660f70c1',
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

    def test_signed_input_for_unsigned_packing(self):
        ir = lift(bytes.fromhex('660f67c1c3'), 'pack')
        self.assertIn('icmp slt <8 x i16>', ir)
        self.assertIn('icmp sgt <8 x i16>', ir)
        self.assertNotIn('icmp ugt', ir)
        self.assertIn('trunc <8 x i16>', ir)

    def test_multiply_add_overflow_wraps(self):
        ir = lift(bytes.fromhex('660ff5c1c3'), 'madd')
        self.assertIn('sext <8 x i16>', ir)
        self.assertIn('add <4 x i32>', ir)
        self.assertNotIn('nsw', ir)
        self.assertNotIn('nuw', ir)

    def test_native_host_state_is_saved_before_inputs_and_restored_after_outputs(self):
        ir = lift(bytes.fromhex('660fecc1c3'), 'saturate')
        self.assertLess(ir.index('call i64 @bb_simd_host_save'), ir.index('%x0 = load'))
        self.assertGreater(ir.index('call void @bb_simd_host_restore'), ir.index('store i128 %'))
        self.assertGreater(ir.index('call void @bb_simd_host_restore'), ir.index('store i32 0'))

    def test_new_opcodes_keep_strict_operand_and_prefix_contract(self):
        for opcode in ('ec', 'dd', 'e9', 'd8', '60', '6d', '63', '67', 'd5', 'e5', 'e4', 'f5'):
            for prefix, modrm in (('', 'c1'), ('f3', 'c1'), ('66', '01'), ('6648', 'c1'), ('6642', 'c1')):
                code = prefix + '0f' + opcode + modrm + 'c3'
                with self.subTest(code=code), self.assertRaises(ValueError):
                    decode(bytes.fromhex(code))

    def test_literal_integer_answers_agree_with_independent_model(self):
        fixtures = load_fixtures()
        records, descriptions, known = corpus(0)
        integer_checks = 0
        for index, name, expected in known:
            if 'integer_known_answer' not in descriptions[index]:
                continue
            with self.subTest(name=name, mxcsr=STATE.unpack(records[index])[MXCSR_INDEX]):
                self.assertEqual(integer_model(bytes.fromhex(fixtures[name]), records[index]), expected)
            integer_checks += 1
        self.assertEqual(integer_checks, 640)

    def test_all_sixteen_register_pairs_and_rex_bits(self):
        fixtures = load_fixtures()
        for dst in range(16):
            for src in range(16):
                name = f'copy_xmm{dst}_xmm{src}'
                with self.subTest(dst=dst, src=src):
                    instruction, = decode(bytes.fromhex(fixtures[name]))
                    self.assertEqual((instruction.op, instruction.dst, instruction.src), ('mov', dst, src))

    def test_all_register_pairs_for_packed_and_scalar_fp(self):
        for prefix, width, scalar in ((b'', 32, False), (b'\x66', 64, False),
                                      (b'\xf3', 32, True), (b'\xf2', 64, True)):
            for dst in range(16):
                for src in range(16):
                    rex = 0x40 | ((dst >> 3) << 2) | (src >> 3)
                    code = prefix + bytes([rex, 0x0f, 0x58, 0xc0 | ((dst & 7) << 3) | (src & 7), 0xc3])
                    instruction, = decode(code)
                    self.assertEqual((instruction.dst, instruction.src, instruction.width, instruction.scalar),
                                     (dst, src, width, scalar))

    def test_common_layout_has_distinct_gpr_and_xmm_storage(self):
        self.assertEqual(len(GPR_NAMES), 16)
        self.assertEqual(len(set(GPR_NAMES)), 16)
        self.assertEqual(STATE.size, 416)
        # One distinct byte pattern per field, with no overlap at GPR15/XMM0
        # or XMM15/RIP; C's compiled layout is separately asserted by the harness.
        fields = list(range(53))
        data = STATE.pack(*fields)
        for register in range(16):
            self.assertEqual(int.from_bytes(data[register * 8:register * 8 + 8], 'little'), register)
            start = xmm_offset(register)
            self.assertEqual(int.from_bytes(data[start:start + 8], 'little'), 16 + register * 2)
        self.assertEqual(int.from_bytes(data[OFFSETS['rip']:OFFSETS['rip'] + 8], 'little'), 48)
        self.assertEqual(int.from_bytes(data[OFFSETS['reserved']:OFFSETS['reserved'] + 8], 'little'), 52)

    def test_extended_immediate_shift_does_not_extend_opcode_group(self):
        instruction, = decode(bytes.fromhex('66410f72f1ffc3'))
        self.assertEqual((instruction.op, instruction.dst, instruction.immediate), ('shl', 9, 255))
        for code in ('66450f72f101c3', '41660f72f101c3', '6641410f72f101c3', '66410f72f1'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                decode(bytes.fromhex(code))

    def test_llvm_uses_common_layout_and_preserves_untouched_fields(self):
        ir = lift(bytes.fromhex('66450f58c7c3'), 'high')
        self.assertIn(f'%p15 = getelementptr i8, ptr %state, i64 {xmm_offset(15)}', ir)
        self.assertIn('%mxptr = getelementptr i8, ptr %state, i64 400', ir)
        self.assertEqual(ir.count(' = load i128'), 16)
        self.assertEqual(ir.count('  store i128'), 16)

    def test_high_register_literal_answers_preserve_every_other_field(self):
        records, descriptions, known = corpus(0)
        for index, name, expected in known:
            if not name.endswith('_xmm8_15'):
                continue
            initial, result = STATE.unpack(records[index]), STATE.unpack(expected)
            touched = {MXCSR_INDEX, MXCSR_INDEX + 1, XMM_INDEX + 16, XMM_INDEX + 17,
                       XMM_INDEX + 30, XMM_INDEX + 31}
            for field in range(len(initial)):
                if field not in touched:
                    self.assertEqual(initial[field], result[field], (name, field))


if __name__ == '__main__':
    unittest.main()
