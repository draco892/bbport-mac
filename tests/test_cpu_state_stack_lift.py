"""Shared stack contracts, guest control addresses, precise faults and literals."""
import json
import struct
import sys
import unittest
from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from cpu_state import STATE, STATUS_INDEX, RIP_INDEX
from state_stack_lift import analyze, decode, lift, ROOT_RETURN, CODE_BASE
from state_memory_lift import lift as lift_memory
from gpr_lift import Instruction as ScalarInstruction, lift_instructions
from run_state_stack import (literal_cases, model, make_record, prepare, STACK_BASE,
                             whole_native_bridge, final_flags, reference_sources)


class StateStackLiftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = json.loads((ROOT / 'recompiler/state_stack_fixtures.json').read_text())
        cls.program = analyze(cls.spec)

    def test_every_function_decodes_and_module_lifts(self):
        ir, functions, decoded, calls, costs = lift(self.spec)
        self.assertEqual(set(functions), set(self.spec))
        self.assertTrue(all(cost <= 4096 for cost in costs.values()))
        self.assertNotIn('inttoptr', ir)
        self.assertNotIn(' inbounds ', ir)
        self.assertNotIn(' nsw ', ir)
        self.assertNotIn(' nuw ', ir)

    def test_all_sixteen_push_pop_registers(self):
        for reg in range(16):
            insns = self.program[1][f'push_pop_r{reg}']
            self.assertEqual([(i.op, i.reg) for i in insns[:2]], [('push', reg), ('pop', reg)])

    def test_rejects_code_outside_stack_contract(self):
        for code in ('', '41', 'c3c3', 'c390', 'c20000', '6650c3', '4850c3', '6a01c3',
                     '48c9c3', 'ffd8c3', 'ff3424c3', '8f0424c3', 'eb', '4883ec',
                     '4881ec000000', 'e8000000', '0f100424c3', '488b0500000000c3'):
            with self.subTest(code=code), self.assertRaises(ValueError): decode(bytes.fromhex(code))

    def test_direct_calls_must_target_exact_known_entries(self):
        for code in ('e8fcffffffc3', 'e800100000c3'):
            with self.assertRaises(ValueError): analyze({'bad': dict(address=0, parts=[code])})
        with self.assertRaises(ValueError): analyze({'bad': dict(address=0, parts=[{'call': 'missing'}, 'c3'])})

    def test_recursive_and_overlapping_modules_are_rejected(self):
        with self.assertRaises(ValueError): analyze({'recursive': dict(address=0, parts=[{'call': 'recursive'}, 'c3'])})
        with self.assertRaises(ValueError): analyze({'a': dict(address=0, parts=['5058c3']), 'b': dict(address=1, parts=['c3'])})
        with self.assertRaises(ValueError): analyze({'a': dict(address=0x10000, parts=['c3'])})
        with self.assertRaises(ValueError): analyze({'a': dict(address=True, parts=['c3'])})

    def test_depth_and_expanded_work_are_bounded(self):
        deep = {f'f{i}': dict(address=i * 128, parts=([{'call': f'f{i+1}'}] if i < 16 else []) + ['c3']) for i in range(17)}
        with self.assertRaises(ValueError): analyze(deep)
        explosive = {f'f{i}': dict(address=i * 128, parts=([{'call': f'f{i+1}'}] * 8 if i < 5 else []) + ['c3']) for i in range(6)}
        with self.assertRaises(ValueError): analyze(explosive)

    def test_stack_limit_is_explicit_without_changing_default_memory_limit(self):
        default = lift_memory(bytes.fromhex('488b0424c3'), 'default')
        stack = lift_memory(bytes.fromhex('488b0424c3'), 'stack', max_bytes=512)
        self.assertIn('icmp ule i64 %m', default)
        self.assertIn(', 64', default)
        self.assertIn(', 512', stack)
        for value in (0, -1, 1048577, True, '512'):
            with self.assertRaises(ValueError): lift_memory(bytes.fromhex('488b0424c3'), 'bad', max_bytes=value)

    def test_immediate_scalar_lowering_preserves_original_operation(self):
        ir = lift_instructions([ScalarInstruction('sub', 4, 0, 64, immediate=-1)], 'adjust')
        self.assertIn('sub i65', ir)
        self.assertIn('18446744073709551615', ir)
        with self.assertRaises(ValueError): lift_instructions([ScalarInstruction('cmov', 4, 0, 64, immediate=1)], 'bad')
        with self.assertRaises(ValueError): lift_instructions([ScalarInstruction('add', 16, 0, 64)], 'bad')

    def test_literal_full_snapshots(self):
        cases = literal_cases(self.program)
        self.assertEqual(len(cases), 40)
        for record, entry, expected in cases:
            with self.subTest(entry=entry): self.assertEqual(model(self.program, entry, record), expected)

    def test_push_rsp_stores_old_value_and_pop_rsp_replaces_increment(self):
        record, _, expected = next(c for c in literal_cases(self.program) if c[1] == 'push_pop_r4')
        actual = model(self.program, 'push_pop_r4', record)
        self.assertEqual(actual, expected)
        old_sp = STATE.unpack(record[:416])[4]
        self.assertEqual(STATE.unpack(actual[:416])[4], old_sp + 8)
        # Stack bytes start at544 in a snapshot; payload starts at560.
        self.assertEqual(int.from_bytes(actual[560 + 240:560 + 248], 'little'), old_sp)

    def test_failed_callee_preserves_committed_caller_state(self):
        record, _, expected = next(c for c in literal_cases(self.program) if c[1] == 'caller_fault')
        actual = model(self.program, 'caller_fault', record)
        state = STATE.unpack(actual[:416])
        self.assertEqual(actual, expected)
        self.assertEqual(state[4], STACK_BASE + 232)
        self.assertEqual(state[3], 3)
        self.assertEqual(state[RIP_INDEX], CODE_BASE + self.program[0]['callee_data_fault']['address'])

    def test_invalid_return_is_rejected_before_pop(self):
        record, _, expected = next(c for c in literal_cases(self.program) if c[1] == 'corrupt_return')
        state = STATE.unpack(expected[:416])
        self.assertEqual(state[STATUS_INDEX], 4)
        self.assertEqual(state[4], STATE.unpack(record[:416])[4])
        self.assertEqual(struct.unpack('<4Q', expected[416:448])[2], 0)

    def test_rip_advances_to_guest_return_address(self):
        record = make_record(3, 7, 248, 0)
        output = model(self.program, 'call_return_address', record)
        state = STATE.unpack(output[:416])
        self.assertEqual(state[0], CODE_BASE + self.program[0]['call_return_address']['address'] + 6)
        self.assertEqual(state[RIP_INDEX], ROOT_RETURN)

    def test_stack_argument_alias_is_resolved_by_guest_address(self):
        record = make_record(0x123456789abcdef0, 7, 248, 0)
        state = STATE.unpack(model(self.program, 'stack_alias_arg', record)[:416])
        self.assertEqual(state[0], 0x123456789abcdef0)
        self.assertEqual(state[8], STACK_BASE + 248)

    def test_native_whole_function_bridge_uses_guest_code_and_restores_host_sp(self):
        functions, decoded, calls, _ = self.program
        assembly = whole_native_bridge(functions, decoded, calls)
        self.assertIn('jmp *Ltarget_direct_call(%rip)', assembly)
        self.assertIn('_ss_native_capture:', assembly)
        self.assertIn('movq %xmm14, %rsp', assembly)
        self.assertIn(str(ROOT_RETURN), assembly)
        self.assertEqual(final_flags('negative_adjust8', decoded, calls), 0x8d5)

    def test_original_push_pop_and_leave_bytes_are_executed(self):
        functions, decoded, calls, _ = self.program
        assembly, source = reference_sources(functions, decoded, calls)
        self.assertIn('.byte 84', assembly)
        self.assertIn('.byte 92', assembly)
        self.assertIn('.byte 201', assembly)
        self.assertIn('s->status = 4', source)
        self.assertIn('UINT64_MAX - m->byte_size', source)

    def test_callee_flags_flow_to_caller_consumers(self):
        _, decoded, calls, _ = self.program
        self.assertEqual(final_flags('call_logic_flags', decoded, calls), 0x8c5)
        self.assertEqual(final_flags('call_carry_flags', decoded, calls), 0x8d5)


if __name__ == '__main__': unittest.main()
