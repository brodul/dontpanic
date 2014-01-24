import os
import unittest

from . import __fixtures__


class TestCli(unittest.TestCase):
    """Test for the CLI interface."""

    def call_FUT(self, *arg):
        from ..cli import main
        return main(arg)

    def test_no_act_error(self):

        with self.assertRaises(SystemExit) as cm:
            self.call_FUT('')

        the_exception = cm.exception
        self.assertEqual(the_exception.code, 2)

    def test_nginx(self):
        nginx_conf = os.path.join(__fixtures__, "nginx")
        self.call_FUT('-n ', nginx_conf)
