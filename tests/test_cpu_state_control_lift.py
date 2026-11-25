"""Control-flow validation and literal results for the common CPU state."""
import struct
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from cpu_state import RIP_INDEX, STATE, STATUS_INDEX
from run_state_control import fixtures, inputs
from run_state_stack import CODE_BASE, STACK_BASE, model, prepare
from state_stack_lift import analyze, decode


class StateControlTests(unittest.TestCase):
    def setUp(self):
        self.spec = fixtures()
        self.program = analyze(self.spec)
        self.inputs = inputs(self.spec, 0)

    def test_branches_reject_non_boundaries(self):
        for code in ('eb01c3', 'ebffc3', 'ebfc90c3', '0f8401000000c3'):
            with self.subTest(code=code), self.assertRaises(ValueError):
                analyze({'root': {'address': 0, 'parts': [code]}})
        with self.assertRaises(ValueError):
            decode(bytes.fromhex('0f840000'))

    def test_indirect_sites_require_exact_metadata_and_acyclic_edges(self):
        for targets in (None, [], ['missing'], ['leaf_a', 'leaf_a'], ['nested_indirect']):
            spec = fixtures()
            if targets is None:
                del spec['register_call']['indirect_targets']
            else:
                spec['register_call']['indirect_targets']['2'] = targets
            with self.subTest(targets=targets), self.assertRaises(ValueError):
                analyze(spec)
        self.spec['host_reentry']['host_callbacks']['1'] = 'host_reentry'
        with self.assertRaises(ValueError):
            analyze(self.spec)

    def test_null_target_does_not_push_a_return_address(self):
        record = next(record for record in self.inputs if STATE.unpack_from(record)[8] == 0)
        entry = 'register_call'
        result = model(self.program, entry, record, self.spec)
        expected_pc = self.spec[entry]['address'] + 2
        cpu = STATE.unpack_from(result)
        self.assertEqual((cpu[STATUS_INDEX], cpu[RIP_INDEX], cpu[4]),
                         (5, CODE_BASE + expected_pc, STACK_BASE + 240))
        self.assertEqual(struct.unpack_from('<QQ', result, 432), (0, expected_pc))
        _, _, regions = prepare(record, entry, self.program[0])
        # The preceding PUSH R12 commits. The failed indirect CALL does not.
        self.assertEqual(result[560 + 232:560 + 240], regions[1][16 + 232:16 + 240])

    def test_callback_result_and_failure_continuation(self):
        cpu = STATE.unpack_from(model(self.program, 'host_reentry', self.inputs[0], self.spec))
        self.assertEqual((cpu[STATUS_INDEX], cpu[0], cpu[4]), (0, 20, STACK_BASE + 256))
        cpu = STATE.unpack_from(model(self.program, 'host_fault', self.inputs[0], self.spec))
        self.assertEqual((cpu[STATUS_INDEX], cpu[0], cpu[4], cpu[RIP_INDEX]),
                         (1, 3, STACK_BASE + 232, CODE_BASE + self.spec['leaf_fault']['address']))

    def test_shared_budget_stops_nested_loop_before_next_instruction(self):
        record = next(r for r in self.inputs if STATE.unpack_from(r)[0] == 4080)
        cpu = STATE.unpack_from(model(self.program, 'loop_call', record, self.spec))
        # Two prologue instructions, 584 full seven-instruction iterations,
        # then six instructions through DEC. The following JMP is pending.
        self.assertEqual((cpu[STATUS_INDEX], cpu[1], cpu[4], cpu[RIP_INDEX]),
                         (6, 4080 - 585, STACK_BASE + 240,
                          CODE_BASE + self.spec['loop_call']['address'] + 17))


if __name__ == '__main__':
    unittest.main()
