import os
import subprocess
import sys
import unittest


class GeventRuntimeTests(unittest.TestCase):
    def test_production_entrypoint_patches_socket_without_socketio(self):
        env = os.environ.copy()
        env.pop('NTWA_ASYNC_MODE', None)
        result = subprocess.run(
            [sys.executable, '-c', 'import app\nfrom gevent import monkey\nassert monkey.is_module_patched("socket")\nassert not hasattr(app, "socketio")\n'],
            env=env, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == '__main__':
    unittest.main()
