"""Validate host-import boundaries without weakening earlier guest-call contracts."""
import sys
import unittest

from paths import ROOT

sys.path.insert(0, str(ROOT / 'recompiler'))
from callback_lift import HOST_IMPORTS, lift_callbacks
from stack_lift import analyze, assemble, lift_stack


def specification():
    return {'callback': {'address': 0, 'parts': ['53', {'call_host': 'host_service'}, '5bc3']}}


def host_functions():
    functions = assemble({'callback': {'address': 0, 'parts': ['53', {'call': 'host_service'}, '5bc3']},
                          'host_service': {'address': 0x4000, 'parts': ['c3']}})
    del functions['host_service']
    return functions


class CpuCallbackLiftTests(unittest.TestCase):
    def test_host_call_counts_return_slot_in_stack_requirement(self):
        _, analyses, _, _ = lift_callbacks(specification())
        self.assertEqual(analyses['callback']['required_stack'], 16)

    def test_host_calls_require_controlled_error_state(self):
        with self.assertRaisesRegex(ValueError, 'controlled-error CPU state'):
            analyze(host_functions(), host_imports=HOST_IMPORTS)

    def test_unknown_host_token_is_rejected(self):
        spec = specification()
        spec['callback']['parts'][1] = {'call_host': 'not_registered'}
        with self.assertRaisesRegex(ValueError, 'unknown host import token'):
            lift_callbacks(spec)

    def test_import_is_not_an_indirect_guest_target(self):
        spec = specification()
        spec['callback']['parts'] = ['53', {'indirect': 'rbx', 'targets': ['host_service']}, '5bc3']
        with self.assertRaisesRegex(ValueError, 'invalid indirect target set'):
            lift_callbacks(spec)

    def test_host_call_alignment_is_checked(self):
        spec = specification()
        spec['callback']['parts'] = [{'call_host': 'host_service'}, 'c3']
        with self.assertRaisesRegex(ValueError, '16-byte aligned before CALL'):
            lift_callbacks(spec)

    def test_guest_and_host_names_must_not_conflict(self):
        with self.assertRaisesRegex(ValueError, 'conflicts with a host import'):
            lift_callbacks({'host_service': {'address': 0, 'parts': ['4889f0c3']}})

    def test_guest_and_host_ranges_must_not_overlap(self):
        spec = specification()
        spec['callback']['address'] = 0x4000
        with self.assertRaisesRegex(ValueError, 'overlapping host import thunk'):
            lift_callbacks(spec)

    def test_import_thunks_must_not_overlap_each_other(self):
        with self.assertRaisesRegex(ValueError, 'overlapping host import thunk'):
            analyze(host_functions(), indirect_targets={}, host_imports={'host_service': 0x4000, 'other': 0x4008})

    def test_unknown_and_interior_import_addresses_are_rejected(self):
        for imports in ({}, {'host_service': 0x4001}):
            with self.subTest(imports=imports), self.assertRaisesRegex(ValueError, 'known function entry'):
                analyze(host_functions(), indirect_targets={}, host_imports=imports)

    def test_invalid_import_addresses_are_rejected(self):
        for address in (-1, 1 << 31, True):
            with self.subTest(address=address), self.assertRaisesRegex(ValueError, 'invalid host import address'):
                analyze(host_functions(), indirect_targets={}, host_imports={'host_service': address})

    def test_code_base_bounds_include_the_import_thunk(self):
        with self.assertRaisesRegex(ValueError, 'invalid guest code base'):
            lift_stack(host_functions(), indirect_targets={}, host_imports=HOST_IMPORTS,
                       code_base=(1 << 64) - 0x4005)


if __name__ == '__main__':
    unittest.main()
