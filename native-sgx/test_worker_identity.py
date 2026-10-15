"""Check that privilege dropping resolves the actual pilot account."""
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

import run_trial


class WorkerIdentityTests(unittest.TestCase):
    def test_drop_uses_account_for_uid_and_checks_all_identity_fields(self):
        libc = MagicMock()
        libc.prctl.return_value = 0
        status = 'Uid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n'
        status += 'CapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n'
        with patch('run_trial.ctypes.CDLL', return_value=libc), \
             patch('run_trial.pwd.getpwuid', return_value=SimpleNamespace(pw_name='pilot-user')) as account, \
             patch('run_trial.os.initgroups') as groups, \
             patch('run_trial.os.setresgid') as gid, \
             patch('run_trial.os.setresuid') as uid, \
             patch.object(run_trial.Path, 'read_text', return_value=status):
            run_trial.drop_privileges()
        account.assert_called_once_with(1000)
        groups.assert_called_once_with('pilot-user', 1000)
        gid.assert_called_once_with(1000, 1000, 1000)
        uid.assert_called_once_with(1000, 1000, 1000)


if __name__ == '__main__':
    unittest.main()
