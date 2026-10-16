"""Hash-valid reproductions of independent GitHub review findings."""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "fixtures/ir_cases/response_case.json"


class ContradictoryUnreferencedEvidence(unittest.TestCase):
    def test_omitted_adverse_verification_cannot_leave_action_verified(self):
        with tempfile.TemporaryDirectory() as td:
            folder = Path(td) / "plans"
            shutil.copytree(ROOT / "fixtures/ir_simulations", folder)
            path = folder / "success.json"
            plan = json.loads(path.read_bytes())
            artifact = next(e for e in plan["evidence"] if e["id"] == "sim_verifications")
            source = folder / artifact["path"]
            rows = [json.loads(line) for line in source.read_text(encoding="utf-8").split("\n") if line]
            hidden = copy.deepcopy(next(r for r in rows if r["kind"] == "investigate_signins"))
            hidden.update(record_id="hidden_adverse", observed_state="unauthorized_access_present")
            rows.append(hidden)
            raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode("utf-8") for row in rows)
            source.write_bytes(raw)
            artifact.update(sha256=hashlib.sha256(raw).hexdigest(), byte_length=len(raw))
            path.write_text(json.dumps(plan), encoding="utf-8")
            result = subprocess.run([sys.executable, "-B", "-m", "ir_lab", "simulate",
                                     str(CASE), "--plan", str(path)], cwd=ROOT, capture_output=True)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertEqual(result.stdout, b"")
            self.assertNotIn(b"Traceback", result.stderr)
            self.assertIn(b"conflicting", result.stderr)


if __name__ == "__main__":
    unittest.main()
