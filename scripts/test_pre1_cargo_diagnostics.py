import contextlib
import io
import json
from pathlib import Path
import tempfile
import os
import subprocess
import sys
import unittest
from unittest import mock
import pre1_cargo_diagnostics as diagnostic


class DiagnosticTests(unittest.TestCase):
    def test_start_event_precedes_launch_and_terminal_event_is_bound(self):
        output = io.StringIO()
        original = subprocess.Popen
        def spawn(*args, **kwargs):
            self.assertIn('"state": "started"', output.getvalue())
            return original(*args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stderr(output):
            with mock.patch.object(subprocess, 'Popen', side_effect=spawn):
                diagnostic.run([sys.executable, '-c', 'pass'], Path(directory), {})
        events = [json.loads(line.split(' ', 1)[1]) for line in output.getvalue().splitlines()
                  if line.startswith('IICP_BUILD_STEP_EVENT ')]
        self.assertEqual([row['state'] for row in events], ['started', 'success'])
        self.assertEqual(events[0]['step_id'], events[1]['step_id'])
        self.assertEqual(events[1]['exit_code'], 0)
        self.assertNotIn(sys.executable, json.dumps(events))

    def test_launch_failure_has_terminal_event_without_exception_secrets(self):
        output = io.StringIO()
        with mock.patch.object(subprocess, 'Popen', side_effect=FileNotFoundError('secret value')), contextlib.redirect_stderr(output):
            with self.assertRaises(FileNotFoundError):
                diagnostic.run(['cargo', 'test'], Path('.'), {})
        self.assertIn('"state": "failed"', output.getvalue())
        self.assertIn('"exit_code": null', output.getvalue())
        self.assertNotIn('secret value', output.getvalue())

    def test_buffered_pipe_uses_incremental_reads(self):
        stdout = io.BufferedReader(io.BytesIO(b'early context'))
        stdout.read = mock.Mock(side_effect=AssertionError('fill-buffer read used'))
        process = mock.Mock(stdout=stdout, stderr=io.BytesIO(), returncode=0)
        process.poll.return_value = 0
        output = io.StringIO()
        with mock.patch.object(subprocess, 'Popen', return_value=process), contextlib.redirect_stderr(output):
            diagnostic.run(['cargo', 'test'], Path('.'), {})
        self.assertIn('early context', output.getvalue())
        stdout.read.assert_not_called()

    def test_optional_step_emission_failure_is_nonfatal(self):
        with mock.patch('builtins.print', side_effect=OSError('closed telemetry pipe')):
            diagnostic.step_event('fixture', ['cargo', 'test'], 'started')

    def test_capture_survives_source_cleanup(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'Cargo.lock').write_text('[[package]]\nname="fixture-sys"\nversion="1.0.0"\n')
            p = root/'target-quality/debug/build/fixture-sys-abc/stderr'
            p.parent.mkdir(parents=True)
            p.write_text('error: native compiler unavailable\nCaused by:\nmissing SDK\npassword=never-expose\n')
            with contextlib.redirect_stderr(output):
                diagnostic.emit(root, root)
        self.assertIn('fixture-sys', output.getvalue())
        self.assertIn('missing SDK', output.getvalue())
        self.assertNotIn('never-expose', output.getvalue())

    def test_real_failing_build_script_is_diagnosable_after_cleanup(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'src').mkdir()
            (root/'src/lib.rs').write_text('pub fn example() {}')
            (root/'Cargo.toml').write_text('[package]\nname="fixture-sys"\nversion="1.0.0"\nedition="2021"\n')
            (root/'build.rs').write_text('fn main() { panic!("controlled compiler prerequisite unavailable"); }')
            env = dict(os.environ, CARGO_INCREMENTAL='0', CARGO_TARGET_DIR=str(root/'target-quality'))
            subprocess.run(['cargo', 'generate-lockfile', '--offline'], cwd=root, env=env, capture_output=True, check=True, timeout=60)
            with contextlib.redirect_stderr(output):
                with self.assertRaises(subprocess.CalledProcessError) as caught:
                    diagnostic.run(['cargo', 'test', '--locked', '--offline'], root, env)
                self.assertEqual(101, caught.exception.returncode)
                diagnostic.emit(root, root)
        self.assertIn('fixture-sys', output.getvalue())
        self.assertIn('controlled compiler prerequisite unavailable', output.getvalue())

    def test_success_and_large_output_are_bounded(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(output):
            diagnostic.run([sys.executable, '-c', "import sys; sys.stdout.write('x' * (9*1024*1024))"], Path(tmp), dict(os.environ))
        self.assertNotIn('error:', output.getvalue())
        self.assertIn('"exit_code": 0', output.getvalue())
        self.assertIn('"truncated": true', output.getvalue())
        self.assertLess(len(output.getvalue()), 3000)

    def test_reader_failure_cannot_pass(self):
        class Broken(io.BytesIO):
            def read(self, _size):
                raise OSError('controlled read failure')
        process = mock.Mock(stdout=Broken(), stderr=io.BytesIO(), returncode=0)
        process.poll.return_value = 0
        with mock.patch.object(subprocess, 'Popen', return_value=process), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaisesRegex(RuntimeError, 'capture failed'):
                diagnostic.run(['cargo', 'test'], Path('.'), {})

    def test_partial_output_survives_reader_error(self):
        class Partial(io.BytesIO):
            def __init__(self):
                super().__init__(); self.first = True
            def read(self, _size):
                if self.first:
                    self.first = False
                    return b'error: controlled compiler prerequisite unavailable\n'
                raise OSError('read failure')
        process = mock.Mock(stdout=Partial(), stderr=io.BytesIO(), returncode=0)
        process.poll.return_value = 0
        output = io.StringIO()
        with mock.patch.object(subprocess, 'Popen', return_value=process), contextlib.redirect_stderr(output):
            with self.assertRaises(RuntimeError):
                diagnostic.run(['cargo', 'test'], Path('.'), {})
        self.assertIn('controlled compiler prerequisite unavailable', output.getvalue())
        self.assertIn('"capture_complete": false', output.getvalue())

    def test_interruption_kills_owned_command(self):
        import time
        process = mock.Mock(stdout=io.BytesIO(), stderr=io.BytesIO())
        process.poll.return_value = None
        with mock.patch.object(subprocess, 'Popen', return_value=process), mock.patch.object(time, 'sleep', side_effect=KeyboardInterrupt), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(KeyboardInterrupt):
                diagnostic.run(['cargo', 'test'], Path('.'), {})
        process.kill.assert_called_once()
        process.wait.assert_called_once_with(timeout=5)

    def test_environment_and_paths_redacted(self):
        text = diagnostic.safe_line('error: sensitivevalue C:\\private\\input.c', {'CONFIG': 'sensitivevalue'})
        self.assertNotIn('sensitivevalue', text)
        self.assertNotIn('input.c', text)

    def test_missing_capture_does_not_mask_error(self):
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(output):
            diagnostic.emit(Path(tmp), Path(tmp))
        self.assertIn('capture unavailable', output.getvalue())

    def test_unsafe_alias_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); (root/'real').mkdir()
            (root/'alias').symlink_to(root/'real', target_is_directory=True)
            self.assertFalse(diagnostic.safe_path(root/'alias', root))


if __name__ == '__main__':
    unittest.main()
