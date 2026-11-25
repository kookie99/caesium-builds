"""Exercise the exact embedded Linux manifest verifier without compiling Caesium."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/build-windows.yml"
MATCH = re.search(r"^          python -I -B - <<'PY'\n(.*?)^          PY$",
                  WORKFLOW.read_text(encoding="utf-8"), flags=re.M | re.S)
if MATCH is None:
    raise RuntimeError("Cannot locate the exact production manifest verifier")
CODE = textwrap.dedent(MATCH.group(1))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        self.root = self.work / "verified"
        self.root.mkdir()
        self.exe = self.root / "Caesium-fixture-setup.exe"
        self.exe.write_bytes(b"not executable; never executed by manifest verifier")
        self.manifest = self.root / "build-manifest.json"
        self.rust_status = {"policy": "report", "vulnerabilities": 0,
                            "informational_warnings": 6, "exit_code": 0}
        self.payload = {
            "compiled_sha256": "1" * 64, "embedded_sha256": "2" * 64,
            "expected_embedded_sha256": "2" * 64, "comparison": "tauri-nsis-marker",
            "marker_offset": 300, "compiled_size": 512, "embedded_size": 512,
        }
        self.jsonfile("cargo-audit-status.json", self.rust_status)
        self.jsonfile("cargo-audit.json", {"vulnerabilities": {"count": 0, "list": []}})
        (self.root / "Cargo.lock.upstream").write_text("original fixture lock")
        (self.root / "Cargo.lock.effective").write_text("patched fixture lock")
        self.remediation = {"mode": "security-patched", "unrelated_package_changes": 0,
                            "upstream_sha256": digest(self.root / "Cargo.lock.upstream"),
                            "effective_sha256": digest(self.root / "Cargo.lock.effective"),
                            "changes": [{"name": "url", "from": "2.5.8", "to": "2.5.9", "advisory": "RUSTSEC-2026-0592"}]}
        self.jsonfile("rust-remediation.json", self.remediation)
        self.jsonfile("installer-payload-verification.json", self.payload)
        for label in ("full", "production"):
            self.jsonfile(f"npm-audit-final-{label}.json",
                          {"metadata": {"vulnerabilities": {"total": 0}}})
        for name in ("SHA256SUMS.txt", "INSTALLED-EXE-SHA256.txt",
                     "UPSTREAM-LICENSE.md", "source.txt", "effective-lockfile-hashes.json"):
            (self.root / name).write_text("fixture", encoding="utf-8")
        self.data = {
            "schema_version": 3, "app_version": "3.0.0-alpha.2",
            "source_repository": "Lymphatus/caesium-v3", "source_commit": "a" * 40,
            "workflow_commit": "b" * 40, "run_id": "123", "run_attempt": "1",
            "build_mode": "security-patched", "target": "x86_64-pc-windows-msvc",
            "installer": {"name": self.exe.name, "size_bytes": self.exe.stat().st_size,
                          "sha256": digest(self.exe)},
            "executable": {"name": "Caesium Image Compressor.exe",
                           "size_bytes": self.payload["embedded_size"],
                           "sha256": self.payload["embedded_sha256"],
                           "compiled_sha256": self.payload["compiled_sha256"],
                           "expected_embedded_sha256": self.payload["expected_embedded_sha256"],
                           "comparison": self.payload["comparison"],
                           "marker_offset": self.payload["marker_offset"],
                           "embedded_hash_verified": True},
            "npm_full_findings": 0, "npm_production_findings": 0,
            "rust_audit": copy.deepcopy(self.rust_status),
            "dependency_files": [{"name": "Cargo.lock", "sha256": self.remediation["effective_sha256"]}],
            "rust_tests": "passed", "signed_by_upstream": False,
        }
        self.env = os.environ.copy()
        self.env.update(EXPECTED_INSTALLER_SHA=digest(self.exe), EXPECTED_MODE="security-patched",
                        EXPECTED_SOURCE="a" * 40, EXPECTED_RUST_POLICY="report",
                        EXPECTED_ATTEMPT="1", GITHUB_SHA="b" * 40, GITHUB_RUN_ID="123")
        self.refresh_manifest()

    def jsonfile(self, name, data):
        (self.root / name).write_text(json.dumps(data), encoding="utf-8")

    def refresh_manifest(self, rebuild_support=True):
        if rebuild_support:
            self.data["supporting_files"] = [
                {"name": p.name, "size_bytes": p.stat().st_size, "sha256": digest(p)}
                for p in sorted(self.root.iterdir()) if p not in (self.exe, self.manifest)
            ]
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")
        self.env["EXPECTED_MANIFEST_SHA"] = digest(self.manifest)

    def run_case(self, should_pass):
        result = subprocess.run([sys.executable, "-I", "-B", "-c", CODE],
                                cwd=self.work, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, should_pass,
                         result.stdout + "\n" + result.stderr)

    def test_valid_patched_report_mode(self):
        self.run_case(True)

    def test_tampered_installer(self):
        self.exe.write_bytes(b"tampered")
        self.run_case(False)

    def test_tampered_manifest(self):
        self.manifest.write_text("{}", encoding="utf-8")
        self.run_case(False)

    def test_tampered_audit_report(self):
        self.jsonfile("cargo-audit.json", {"vulnerabilities": {"count": 99}})
        self.run_case(False)

    def test_missing_supporting_file(self):
        (self.root / "source.txt").unlink()
        self.run_case(False)

    def test_extra_file(self):
        (self.root / "unexpected.txt").write_text("extra", encoding="utf-8")
        self.run_case(False)

    def test_wrong_source(self):
        self.env["EXPECTED_SOURCE"] = "c" * 40
        self.run_case(False)

    def test_wrong_workflow_attempt(self):
        self.env["EXPECTED_ATTEMPT"] = "2"
        self.run_case(False)

    def test_patched_npm_findings_block(self):
        self.data["npm_full_findings"] = 1
        self.jsonfile("npm-audit-final-full.json",
                      {"metadata": {"vulnerabilities": {"total": 1}}})
        self.refresh_manifest()
        self.run_case(False)

    def test_rust_block_findings(self):
        self.rust_status.update(policy="block", vulnerabilities=1, exit_code=1)
        self.jsonfile("cargo-audit.json", {"vulnerabilities": {"count": 1, "list": [{"advisory": {"id": "RUSTSEC-TEST-OTHER"}}]}})
        self.data["rust_audit"] = copy.deepcopy(self.rust_status)
        self.env["EXPECTED_RUST_POLICY"] = "block"
        self.jsonfile("cargo-audit-status.json", self.rust_status)
        self.refresh_manifest()
        self.run_case(False)

    def test_reviewed_rust_vulnerability_remains(self):
        self.rust_status.update(vulnerabilities=1, exit_code=1)
        self.data["rust_audit"] = copy.deepcopy(self.rust_status)
        self.jsonfile("cargo-audit-status.json", self.rust_status)
        self.jsonfile("cargo-audit.json", {"vulnerabilities": {"count": 1, "list": [{"advisory": {"id": "RUSTSEC-2026-0592"}}]}})
        self.refresh_manifest()
        self.run_case(False)

    def test_unapproved_rust_patch(self):
        self.remediation["changes"][0]["to"] = "3.0.0"
        self.jsonfile("rust-remediation.json", self.remediation)
        self.refresh_manifest()
        self.run_case(False)

    def test_payload_manifest_inconsistent(self):
        self.data["executable"]["sha256"] = "3" * 64
        self.refresh_manifest()
        self.run_case(False)

    def test_upstream_findings_reported(self):
        self.data["build_mode"] = "upstream"
        self.env["EXPECTED_MODE"] = "upstream"
        (self.root / "Cargo.lock.effective").write_bytes((self.root / "Cargo.lock.upstream").read_bytes())
        self.remediation.update(mode="upstream", changes=[], effective_sha256=self.remediation["upstream_sha256"])
        self.data["dependency_files"][0]["sha256"] = self.remediation["effective_sha256"]
        self.jsonfile("rust-remediation.json", self.remediation)
        self.data["npm_full_findings"] = 12
        self.jsonfile("npm-audit-final-full.json",
                      {"metadata": {"vulnerabilities": {"total": 12}}})
        self.refresh_manifest()
        self.run_case(True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
