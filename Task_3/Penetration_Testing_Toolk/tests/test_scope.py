import unittest
from netaudit.core.scope import ScopeGuard, ScopeViolationError


class TestScopeGuard(unittest.TestCase):

    def test_single_ip_scope(self):
        guard = ScopeGuard(["192.168.1.100"])
        self.assertTrue(guard.is_in_scope("192.168.1.100"))
        self.assertFalse(guard.is_in_scope("192.168.1.101"))

    def test_cidr_scope(self):
        guard = ScopeGuard(["10.0.0.0/24"])
        self.assertTrue(guard.is_in_scope("10.0.0.1"))
        self.assertTrue(guard.is_in_scope("10.0.0.254"))
        self.assertFalse(guard.is_in_scope("10.0.1.1"))

    def test_validate_exception(self):
        guard = ScopeGuard(["127.0.0.1"])
        guard.validate("127.0.0.1")
        with self.assertRaises(ScopeViolationError):
            guard.validate("8.8.8.8")


if __name__ == "__main__":
    unittest.main()
