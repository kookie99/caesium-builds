"""Fail-closed verifier for unsigned Tauri NSIS application payloads."""
import argparse
import hashlib
import json
import struct
import sys
import unittest
from pathlib import Path

OLD = b"__TAURI_BUNDLE_TYPE_VAR_UNK"
NEW = b"__TAURI_BUNDLE_TYPE_VAR_NSS"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_x64_pe(data):
    require(len(data) >= 64 and data[:2] == b"MZ", "Missing DOS header")
    offset = struct.unpack_from("<I", data, 0x3C)[0]
    require(64 <= offset <= len(data) - 26, "Invalid PE header offset")
    require(data[offset:offset + 4] == b"PE\0\0", "Missing PE signature")
    require(struct.unpack_from("<H", data, offset + 4)[0] == 0x8664, "Not AMD64")
    optional_size = struct.unpack_from("<H", data, offset + 20)[0]
    require(optional_size >= 2 and offset + 24 + optional_size <= len(data),
            "Invalid PE optional header size")
    require(struct.unpack_from("<H", data, offset + 24)[0] == 0x20B, "Not PE32+")


def compare_payload(compiled, embedded):
    check_x64_pe(compiled)
    check_x64_pe(embedded)
    require(len(compiled) == len(embedded), "Executable size changed")
    expected = compiled
    offset = None
    method = "exact"
    if compiled != embedded:
        offset = compiled.find(OLD)
        require(offset >= 0, "Expected Tauri marker not found")
        expected = compiled[:offset] + NEW + compiled[offset + len(OLD):]
        method = "tauri-nsis-marker"
    require(expected == embedded, "Executable differs beyond first documented Tauri marker")
    return {
        "compiled_sha256": sha(compiled),
        "embedded_sha256": sha(embedded),
        "expected_embedded_sha256": sha(expected),
        "comparison": method,
        "marker_offset": offset,
        "compiled_size": len(compiled),
        "embedded_size": len(embedded),
    }


def fixture(body):
    header = bytearray(256)
    header[:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, 64)
    header[64:68] = b"PE\0\0"
    struct.pack_into("<H", header, 68, 0x8664)
    struct.pack_into("<H", header, 84, 112)
    struct.pack_into("<H", header, 88, 0x20B)
    return bytes(header) + body


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.raw = fixture(b"prefix" + OLD + b"middle" + OLD + b"suffix")
        self.patched = self.raw.replace(OLD, NEW, 1)

    def test_exact(self):
        self.assertEqual(compare_payload(self.raw, self.raw)["comparison"], "exact")

    def test_documented_patch(self):
        result = compare_payload(self.raw, self.patched)
        self.assertEqual(result["comparison"], "tauri-nsis-marker")
        self.assertEqual(result["marker_offset"], self.raw.index(OLD))
        self.assertEqual(result["embedded_sha256"], sha(self.patched))

    def test_second_marker_only_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(self.raw, self.raw[:self.raw.rfind(OLD)] + NEW + b"suffix")

    def test_all_markers_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(self.raw, self.raw.replace(OLD, NEW))

    def test_unrelated_change_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(self.raw, self.patched[:-1] + b"!")

    def test_length_change_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(self.raw, self.patched + b"x")

    def test_missing_marker_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(fixture(b"abc"), fixture(b"abd"))

    def test_non_pe_rejected(self):
        with self.assertRaises(ValueError):
            compare_payload(b"not executable", b"not executable")

    def test_x86_rejected(self):
        x86 = bytearray(self.raw)
        struct.pack_into("<H", x86, 68, 0x14C)
        with self.assertRaises(ValueError):
            compare_payload(bytes(x86), bytes(x86))

    def test_invalid_pe_offset_rejected(self):
        bad = bytearray(self.raw)
        struct.pack_into("<I", bad, 0x3C, 0xFFFFFFFF)
        with self.assertRaises(ValueError):
            compare_payload(bytes(bad), bytes(bad))

    def test_invalid_optional_header_rejected(self):
        bad = bytearray(self.raw)
        struct.pack_into("<H", bad, 88, 0x10B)
        with self.assertRaises(ValueError):
            compare_payload(bytes(bad), bytes(bad))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--compiled", type=Path)
    parser.add_argument("--embedded", type=Path)
    args = parser.parse_args()
    if args.self_test:
        result = unittest.TextTestRunner(verbosity=2).run(
            unittest.defaultTestLoader.loadTestsFromTestCase(PayloadTests))
        return 0 if result.wasSuccessful() else 1
    if args.compiled is None or args.embedded is None:
        parser.error("--compiled and --embedded are required")
    try:
        result = compare_payload(args.compiled.read_bytes(), args.embedded.read_bytes())
    except (ValueError, OSError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
