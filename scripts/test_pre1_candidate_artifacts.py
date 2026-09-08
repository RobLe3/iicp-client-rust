from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_disposable_windows_path_prefix_is_short(self) -> None:
        import build_pre1_candidate_artifacts as builder
        from unittest import mock
        with mock.patch.object(builder.os, "name", "nt"):
            self.assertEqual(builder.run_directory_prefix(), "rc-")
        with mock.patch.object(builder.os, "name", "posix"):
            self.assertEqual(builder.run_directory_prefix(), "iicp-pre1-rust-client-")

    def test_description_is_content_free_and_complete(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "client-rust")
        self.assertEqual(len(value["artifact_identities"]), 2)
        self.assertTrue(value["requires_clean_source"])
        self.assertTrue(value["non_authorizing"])


from test_pre1_command_observation import CommandObservationTests


if __name__ == "__main__":
    unittest.main()
