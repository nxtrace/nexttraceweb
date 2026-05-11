import os
import subprocess
import sys
import unittest


class GeventRuntimeTests(unittest.TestCase):
    def test_default_socketio_mode_uses_gevent_and_patches_socket(self):
        env = os.environ.copy()
        env.pop("NTWA_SOCKETIO_ASYNC_MODE", None)

        script = (
            "import app\n"
            "from gevent import monkey\n"
            "assert app.SOCKETIO_ASYNC_MODE == 'gevent', app.SOCKETIO_ASYNC_MODE\n"
            "assert monkey.is_module_patched('socket')\n"
        )

        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)


if __name__ == "__main__":
    unittest.main()
