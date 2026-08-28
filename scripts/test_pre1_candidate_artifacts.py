from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/build_pre1_candidate_artifacts.py"


class Pre1CandidateArtifactBuilderTest(unittest.TestCase):
    def test_description_is_content_free_and_complete(self) -> None:
        value = json.loads(
            subprocess.check_output([sys.executable, str(SCRIPT), "--describe"], text=True)
        )
        self.assertEqual(value["component"], "client-rust")
        self.assertEqual(len(value["artifact_identities"]), 2)
        self.assertTrue(value["requires_clean_source"])
        self.assertTrue(value["non_authorizing"])


if __name__ == "__main__":
    unittest.main()
