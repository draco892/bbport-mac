"""Common-state address decoding, precise faults and literal memory outcomes."""
import json
import struct
import sys
import unittest
from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from cpu_state import STATE, OFFSETS, STATUS_INDEX
from state_memory_lift import decode, lift, effective_address, MASK64
from run_state_memory import literal_cases, model, pack_input, BASES, reference_sources


class StateMemoryLiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = json.loads((ROOT / 'recompiler/state_memory_fixtures.json').read_text())

    def test_all_fixture_contracts_decode_and_emit(self):
        for name, code in self.fixtures.items():
            with self.subTest(name=name):
                raw = bytes.fromhex(code)
                self.assertTrue(any(insn.op != 'gpr' for insn in decode(raw)))
                ir = lift(raw, name)
                self.assertNotIn('inttoptr', ir)
                self.assertNotIn(' inbounds ', ir)
                self.assertNotIn(' nsw ', ir)
                self.assertNotIn(' nuw ', ir)

    def test_extended_sib_fields_are_independent(self):
        insn, = decode(bytes.fromhex('4f8b4ce5ffc3'))
        self.assertEqual((insn.reg, insn.base, insn.index, insn.scale, insn.displacement), (9, 13, 12, 8, -1))
        self.assertEqual((insn.width, insn.destination_width), (64, 64))

    def test_rsp_r12_and_no_base_sib_special_encodings(self):
        insn, = decode(bytes.fromhex('498b0424c3'))
        self.assertEqual((insn.base, insn.index), (12, None))
        insn, = decode(bytes.fromhex('4a8b04e500000000c3'))
        self.assertEqual((insn.base, insn.index, insn.scale), (None, 12, 8))

    def test_rex_byte_registers_do_not_alias_high_bytes(self):
        insn, = decode(bytes.fromhex('408a27c3'))
        self.assertEqual((insn.reg, insn.width), (4, 8))
        with self.assertRaises(ValueError): decode(bytes.fromhex('8a27c3'))

    def test_signed_displacements_and_wrap_are_integer_addresses(self):
        insn, = decode(bytes.fromhex('4f8b4ce5ffc3'))
        registers = [0] * 16
        registers[13], registers[12] = BASES[0] + 1, 1 << 61
        self.assertEqual(effective_address(insn, registers), BASES[0])
        registers[13], registers[12] = 0, 0
        self.assertEqual(effective_address(insn, registers), MASK64)

    def test_rejects_unsupported_forms_before_execution(self):
        invalid = ('', 'c3', '4889c0c3', '48', '488b', '488b04', '488b47',
                   '488b8401ffff', '488b0500000000c3', '67488b07c3',
                   '64488b07c3', 'f0488907c3', 'f3488b07c3', '66668b07c3',
                   '66488b07c3', '48488b07c3', '4a8b07c3', '488a07c3',
                   '8a27c3', '8827c3', '0f1007c3', '488b07480107c3',
                   '488b07eb00c3', '488b07e800000000c3', '488b07c390')
        for code in invalid:
            with self.subTest(code=code), self.assertRaises(ValueError):
                lift(bytes.fromhex(code), 'fixture')

    def test_symbol_names_are_checked(self):
        for name in ('', 'é', 'x-y', 'f() {'):
            with self.assertRaises(ValueError): lift(bytes.fromhex('488b07c3'), name)

    def test_gpr_arithmetic_and_memory_reuse_the_same_state(self):
        ir = lift(bytes.fromhex(self.fixtures['flags_across_load']), 'mixed')
        self.assertIn('call void @mixed_scalar_0(ptr %state)', ir)
        self.assertIn('load i32, ptr', ir)
        self.assertIn('getelementptr i8, ptr %state, i64 392', ir)
        self.assertIn('getelementptr i8, ptr %state, i64 64', ir)

    def test_host_pointer_is_formed_only_after_both_checks(self):
        ir = lift(bytes.fromhex('488b07c3'), 'load')
        access = ir.index('access0:')
        pointer = ir.index('getelementptr i8, ptr %m', access)
        self.assertLess(ir.index('bounds0:'), access)
        self.assertLess(ir.index('denied0:'), access)
        self.assertGreater(pointer, access)

    def test_all_literal_snapshots_match_independent_model(self):
        self.assertEqual(len(literal_cases()), 26)
        for record, name, expected in literal_cases():
            with self.subTest(name=name):
                self.assertEqual(model(bytes.fromhex(self.fixtures[name]), record), expected)

    def test_failure_priority_bounds_before_permissions(self):
        bank = [0] * 16
        bank[7] = BASES[0] - 1
        record = pack_input(bank, BASES[0], 64, 0, 0, b'\xa5' * 96, 0)
        actual = model(bytes.fromhex('488b07c3'), record)
        self.assertEqual(STATE.unpack(actual[:STATE.size])[STATUS_INDEX], 1)
        self.assertEqual(struct.unpack('<2Q', actual[416:432]), (BASES[0] - 1, 0))
        self.assertEqual(actual[432:], record[448:])

    def test_prior_store_survives_later_fault_without_failed_load_write(self):
        record, _, expected = next(c for c in literal_cases() if c[1] == 'store_then_fault')
        actual = model(bytes.fromhex(self.fixtures['store_then_fault']), record)
        self.assertEqual(actual, expected)
        self.assertEqual(actual[448], 0x88)  # region starts at432, data at448
        self.assertEqual(STATE.unpack(actual[:416])[8], STATE.unpack(record[:416])[8])

    def test_reference_uses_original_bytes_and_separate_checks(self):
        assembly, source = reference_sources({'load': bytes.fromhex('488b07c3')})
        self.assertIn('.byte 72,139,7', assembly)
        self.assertNotIn('.byte 72,137,192', assembly)
        self.assertLess(source.index('access_ok(s, m'), source.index('load_native_0(s);'))
        self.assertIn('UINT64_MAX - m->byte_size', source)
        self.assertIn('m->byte_size - (a - m->guest_base)', source)


if __name__ == '__main__': unittest.main()
