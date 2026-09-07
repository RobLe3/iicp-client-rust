"""Content-free artifact command observation; no AWS or product execution."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest import mock
import pre1_artifact_common as common


class CommandObservationTests(unittest.TestCase):
    def events(self, stream):
        return [json.loads(line.split(" ", 1)[1]) for line in stream.getvalue().splitlines()]

    def test_start_before_execution_and_output_is_unchanged(self):
        stream = io.StringIO()
        def execute(*args, **kwargs):
            self.assertEqual(self.events(stream)[0]["state"], "started")
            return "version-result\n"
        with contextlib.redirect_stderr(stream), mock.patch.object(common.subprocess, "check_output", side_effect=execute):
            self.assertEqual(common.output(["python", "--version"], Path(".")), "version-result")
        events = self.events(stream)
        self.assertEqual([e["state"] for e in events], ["started", "success"])
        self.assertEqual(events[0]["step_id"], events[1]["step_id"])

    def test_failure_and_failed_launch_preserve_exception(self):
        for error in (subprocess.CalledProcessError(101, ["cargo"]), FileNotFoundError("PRIVATE_CANARY")):
            stream = io.StringIO()
            with contextlib.redirect_stderr(stream), mock.patch.object(common.subprocess, "run", side_effect=error):
                with self.assertRaises(type(error)) as got:
                    common.run(["cargo", "test", "PRIVATE_CANARY"], Path("."))
            self.assertIs(got.exception, error)
            events = self.events(stream)
            self.assertEqual(events[-1]["state"], "failed")
            self.assertEqual(events[-1]["exit_code"], getattr(error, "returncode", None))
            self.assertNotIn("PRIVATE_CANARY", stream.getvalue())

    def test_command_categories_and_offline_are_content_free(self):
        cases = [(["uv", "run", "pytest", "-q"], {}, ["python", "test"]),
                 (["node", "/private/npm-cli.js", "install", "PRIVATE_CANARY"], {"npm_config_offline": "true"}, ["npm", "install-offline"]),
                 (["cargo", "install", "--offline"], {}, ["cargo", "install-offline"]),
                 (["python", "-m", "pip", "install", "--no-index"], {}, ["python", "install-offline"]),
                 (["npm", "install"], {}, ["npm", "install-online"])]
        for argv, env, expected in cases:
            self.assertEqual(common.command_step(argv, env), expected)

    def test_optional_telemetry_failure_is_nonfatal(self):
        with mock.patch("builtins.print", side_effect=OSError("closed")), mock.patch.object(common.subprocess, "run") as run:
            common.run(["cargo", "test"], Path("."))
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
