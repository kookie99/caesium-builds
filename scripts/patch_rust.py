"""Apply only reviewed Rust lockfile security patches; reject unrelated changes."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import tomllib
import unittest

TARGETS = {
    "cookie": ("0.18.2", "0.18.3", "RUSTSEC-2026-0594"),
    "url": ("2.5.8", "2.5.9", "RUSTSEC-2026-0592"),
}
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load(data):
    doc = tomllib.loads(data.decode("utf-8"))
    require(doc.get("version") in (3, 4), "Unsupported lockfile format")
    packages = {}
    for pkg in doc["package"]:
        key = (pkg["name"], pkg["version"], pkg.get("source", ""))
        require(key not in packages, f"Duplicate package identity: {key}")
        packages[key] = pkg
    return doc, packages


def planned(packages, mode):
    if mode == "upstream":
        return []
    changes = [(name, old, new, advisory) for name, (old, new, advisory) in TARGETS.items()
               if (name, old, REGISTRY) in packages]
    if ("url", "2.5.8", REGISTRY) in packages and ("form_urlencoded", "1.2.2", REGISTRY) in packages:
        # url 2.5.9 explicitly requires form_urlencoded >=1.2.3.
        changes.append(("form_urlencoded", "1.2.2", "1.2.3", "RUSTSEC-2026-0592"))
    return changes


def verify(before, after, mode):
    original, old_packages = load(before)
    effective, new_packages = load(after)
    changes = planned(old_packages, mode)
    if not changes:
        require(before == after, "Unrequested lockfile changes")
    require({k: v for k, v in original.items() if k != "package"} ==
            {k: v for k, v in effective.items() if k != "package"}, "Lock metadata changed")
    removed, added = set(old_packages) - set(new_packages), set(new_packages) - set(old_packages)
    require(removed == {(n, old, REGISTRY) for n, old, new, a in changes},
            f"Unexpected removed packages: {sorted(removed)}")
    require(added == {(n, new, REGISTRY) for n, old, new, a in changes},
            f"Unexpected added packages: {sorted(added)}")
    for key in set(old_packages) & set(new_packages):
        require(old_packages[key] == new_packages[key], f"Unrelated package changed: {key}")
    records = []
    for name, old, new, advisory in changes:
        p = old_packages[(name, old, REGISTRY)]
        q = new_packages[(name, new, REGISTRY)]
        require(p.get("dependencies", []) == q.get("dependencies", []),
                f"Dependency edges changed for {name}; review required")
        require({k: v for k, v in p.items() if k not in ("version", "checksum")} ==
                {k: v for k, v in q.items() if k not in ("version", "checksum")},
                f"Unexpected package metadata changes for {name}")
        require(len(q.get("checksum", "")) == 64 and
                all(c in "0123456789abcdef" for c in q["checksum"]) and
                q["checksum"] != p.get("checksum"), f"Invalid new checksum: {name}")
        records.append({"name": name, "from": old, "to": new, "advisory": advisory,
                        "checksum": q["checksum"]})
    return {"mode": mode, "upstream_sha256": digest(before),
            "effective_sha256": digest(after), "changes": records,
            "unrelated_package_changes": 0}


def preserve_reviewed_resolver_edge(before, resolved):
    """Restore the one observed unrelated Cargo resolver edge; reject all other drift."""
    _, old = load(before)
    _, new = load(resolved)
    key = ("cssparser-macros", "0.7.1", REGISTRY)
    if key not in old or key not in new or old[key] == new[key]:
        return resolved, False
    expected = dict(old[key])
    if expected.get("dependencies") != ["quote", "syn 3.0.9"]:
        return resolved, False
    expected["dependencies"] = ["quote", "syn 2.0.119"]
    if new[key] != expected:
        return resolved, False
    # Limit the restoration to the exact package table and one exact dependency.
    parts = resolved.split(b"[[package]]")
    matches = 0
    for index in range(1, len(parts)):
        block = parts[index]
        if (b'\nname = "cssparser-macros"\n' in block and
                b'\nversion = "0.7.1"\n' in block and
                b'\n "syn 2.0.119",\n' in block):
            parts[index] = block.replace(b'\n "syn 2.0.119",\n', b'\n "syn 3.0.9",\n', 1)
            matches += 1
    require(matches == 1, "Unable to restore the exact reviewed resolver edge")
    return b"[[package]]".join(parts), True


def patch(root, out, mode):
    root, out = root.resolve(), out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    lock = root / "Cargo.lock"
    before = lock.read_bytes()
    (out / "Cargo.lock.upstream").write_bytes(before)
    _, packages = load(before)
    with (out / "cargo-update.log").open("w", encoding="utf-8") as log:
        for name, old, new, advisory in planned(packages, mode):
            # The URL update resolves its required transitive dependency itself.
            if name == "form_urlencoded":
                continue
            args = ["cargo", "update", "--package", f"{name}@{old}", "--precise", new]
            print(" ".join(args), flush=True)
            log.write(" ".join(args) + "\n")
            log.flush()
            subprocess.run(args, cwd=root, stdout=log, stderr=subprocess.STDOUT, check=True)
    resolved = lock.read_bytes()
    (out / "Cargo.lock.resolved").write_bytes(resolved)
    after, restored = preserve_reviewed_resolver_edge(before, resolved) if mode == "security-patched" else (resolved, False)
    (out / "Cargo.lock.effective").write_bytes(after)
    report = verify(before, after, mode)
    if restored:
        lock.write_bytes(after)
    report["restored_unrelated_resolver_edge"] = restored
    # Ask Cargo itself to accept the precise lockfile without any further changes.
    with (out / "cargo-locked-validation.json").open("wb") as log, (out / "cargo-locked-validation-stderr.log").open("wb") as err:
        subprocess.run(["cargo", "metadata", "--locked", "--format-version", "1",
                        "--filter-platform", "x86_64-pc-windows-msvc"],
                       cwd=root, stdout=log, stderr=err, check=True)
    require(lock.read_bytes() == after, "Cargo changed the validated lockfile")
    (out / "rust-remediation.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    with (out / "cargo-lockfile-changes.patch").open("wb") as log:
        subprocess.run(["git", "diff", "--binary", "HEAD", "--", "Cargo.lock"],
                       cwd=root, stdout=log, check=True)
    # All tracked files except the lockfile must remain unchanged at this stage.
    subprocess.run(["git", "diff", "--exit-code", "HEAD", "--", ".", ":(exclude)Cargo.lock"],
                   cwd=root, check=True)
    print(json.dumps(report, indent=2))


def fixture(cookie="0.18.2", url="2.5.8", other="1.0.0", extra=""):
    items = [("cookie", cookie, "a" if cookie == "0.18.2" else "b"),
             ("url", url, "c" if url == "2.5.8" else "d"),
             ("other", other, "e")]
    return ("version = 4\n" + "".join(
        f'\n[[package]]\nname = "{n}"\nversion = "{v}"\nsource = "{REGISTRY}"\nchecksum = "{h * 64}"\n'
        for n, v, h in items) + extra).encode()


class PatchTests(unittest.TestCase):
    def test_required_transitive_update(self):
        extra = lambda version, checksum: f'\n[[package]]\nname = "form_urlencoded"\nversion = "{version}"\nsource = "{REGISTRY}"\nchecksum = "{checksum * 64}"\n'
        before = fixture(extra=extra("1.2.2", "a"))
        after = fixture("0.18.3", "2.5.9", extra=extra("1.2.3", "b"))
        self.assertEqual(len(verify(before, after, "security-patched")["changes"]), 3)
        with self.assertRaises(ValueError):
            verify(before, fixture("0.18.3", "2.5.9", extra=extra("1.2.4", "b")), "security-patched")

    def test_restore_only_known_edge(self):
        extra = f'\n[[package]]\nname = "cssparser-macros"\nversion = "0.7.1"\nsource = "{REGISTRY}"\nchecksum = "{"f" * 64}"\ndependencies = [\n "quote",\n "syn 3.0.9",\n]\n'
        before = fixture(extra=extra)
        expected = fixture("0.18.3", "2.5.9", extra=extra)
        resolved = expected.replace(b'syn 3.0.9', b'syn 2.0.119')
        repaired, restored = preserve_reviewed_resolver_edge(before, resolved)
        self.assertTrue(restored)
        self.assertEqual(repaired, expected)
        verify(before, repaired, "security-patched")
        other = resolved.replace(b'"quote"', b'"other"')
        repaired, restored = preserve_reviewed_resolver_edge(before, other)
        self.assertFalse(restored)
        with self.assertRaises(ValueError):
            verify(before, repaired, "security-patched")

    def test_two_patches(self):
        self.assertEqual(len(verify(fixture(), fixture("0.18.3", "2.5.9"), "security-patched")["changes"]), 2)

    def test_already_fixed(self):
        fixed = fixture("0.18.3", "2.5.9")
        self.assertEqual(verify(fixed, fixed, "security-patched")["changes"], [])

    def test_newer_not_downgraded(self):
        fixed = fixture("0.18.4", "2.5.10")
        self.assertEqual(verify(fixed, fixed, "security-patched")["changes"], [])

    def test_upstream_unchanged(self):
        self.assertEqual(verify(fixture(), fixture(), "upstream")["changes"], [])

    def test_upstream_change_rejected(self):
        with self.assertRaises(ValueError):
            verify(fixture(), fixture("0.18.3", "2.5.9"), "upstream")

    def test_unrelated_change_rejected(self):
        with self.assertRaises(ValueError):
            verify(fixture(), fixture("0.18.3", "2.5.9", "1.0.1"), "security-patched")

    def test_partial_fix_rejected(self):
        with self.assertRaises(ValueError):
            verify(fixture(), fixture("0.18.3", "2.5.8"), "security-patched")

    def test_unreviewed_version_rejected(self):
        with self.assertRaises(ValueError):
            verify(fixture(), fixture("0.18.4", "2.5.9"), "security-patched")

    def test_unrelated_checksum_rejected(self):
        with self.assertRaises(ValueError):
            verify(fixture(), fixture("0.18.3", "2.5.9").replace(b"e" * 64, b"f" * 64), "security-patched")

    def test_dependency_edge_change_rejected(self):
        after = fixture("0.18.3", "2.5.9").replace(b'name = "cookie"', b'name = "cookie"\ndependencies = ["other"]')
        with self.assertRaises(ValueError):
            verify(fixture(), after, "security-patched")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--root", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--mode", choices=("upstream", "security-patched"))
    args = parser.parse_args()
    if args.self_test:
        return 0 if unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(PatchTests)).wasSuccessful() else 1
    if args.root is None or args.out is None or args.mode is None:
        parser.error("--root, --out and --mode are required")
    patch(args.root, args.out, args.mode)
    return 0


if __name__ == "__main__":
    sys.exit(main())
