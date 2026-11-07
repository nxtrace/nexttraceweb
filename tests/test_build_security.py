import hashlib
import importlib.util
import io
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

spec = importlib.util.spec_from_file_location('download_nexttrace', Path(__file__).resolve().parents[1] / 'docker' / 'download_nexttrace.py')
download = importlib.util.module_from_spec(spec)
spec.loader.exec_module(download)


class DownloadSecurityTests(unittest.TestCase):
    def test_pinned_flavors_and_architectures_do_not_need_metadata_network(self):
        pins = json.loads(Path(download.__file__).with_name('nexttrace-checksums.json').read_text())['v1.7.6']
        with mock.patch.dict(os.environ, {'NEXTTRACE_SHA256': ''}):
            with mock.patch.object(download.urllib.request, 'urlopen') as network:
                for asset, expected in pins.items():
                    with self.subTest(asset=asset):
                        self.assertEqual(download.expected_digest('v1.7.6', asset), expected)
                network.assert_not_called()

    def test_invalid_explicit_digest_is_rejected_without_fallback(self):
        with mock.patch.dict(os.environ, {'NEXTTRACE_SHA256': 'invalid'}):
            with mock.patch.object(download.urllib.request, 'urlopen') as network:
                with self.assertRaises(SystemExit):
                    download.expected_digest('v1.7.6', 'ntr_linux_amd64')
                network.assert_not_called()

    def test_release_without_digest_is_rejected(self):
        metadata = io.BytesIO(json.dumps({'assets': [{'name': 'ntr_linux_amd64', 'digest': None}]}).encode())
        with mock.patch.dict(os.environ, {'NEXTTRACE_SHA256': ''}):
            with mock.patch.object(download.urllib.request, 'urlopen', return_value=metadata):
                with self.assertRaises(SystemExit):
                    download.expected_digest('v99-test', 'ntr_linux_amd64')

    def test_corrupt_binary_is_removed_and_never_made_executable(self):
        with tempfile.TemporaryDirectory(prefix='ntwa-download-test-') as folder:
            output = Path(folder) / 'nexttrace'
            environment = dict(TARGETOS='linux', TARGETARCH='amd64', NEXTTRACE_ASSET_PREFIX='ntr',
                               NEXTTRACE_RELEASE_TAG='v1.7.6', NEXTTRACE_SHA256=hashlib.sha256(b'expected').hexdigest())
            with mock.patch.dict(os.environ, environment):
                with mock.patch.object(download, 'open', side_effect=lambda *args: output.open(*args[1:]), create=True):
                    with mock.patch.object(download.urllib.request, 'urlopen', return_value=io.BytesIO(b'corrupted')):
                        with mock.patch.object(download.os, 'unlink') as unlink, mock.patch.object(download.os, 'chmod') as chmod:
                            with self.assertRaisesRegex(SystemExit, 'SHA256 mismatch'):
                                download.main()
                            unlink.assert_called_once_with('/usr/local/bin/nexttrace')
                            chmod.assert_not_called()
            self.assertFalse(output.stat().st_mode & stat.S_IXUSR)


if __name__ == '__main__':
    unittest.main()
