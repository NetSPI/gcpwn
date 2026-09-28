"""Object names from an API must land under the download directory -- unmangled.

Anyone with objects.create on a bucket the operator enumerates chooses the blob
name, so a raw join of that name onto the output directory lets the scan TARGET
write files on the OPERATOR's machine.

The containment fix must NOT come at the cost of the name: operators download loot
and need the real filename. Dots, leading dots, repeated dots, spaces and unicode
are all legal in Cloud Storage object names and must survive.
"""

from __future__ import annotations

import posixpath

import pytest

from gcpwn.core.output_paths import PARENT_SEGMENT_ESCAPE, resolve_within, safe_relative_path


class TestCannotEscape:
    @pytest.mark.parametrize(
        "hostile",
        [
            "../../../../../../home/user/.ssh/authorized_keys",
            "../.bashrc",
            "/etc/passwd",
            "//etc/passwd",
            "a/../../../b",
            "..",
            "../",
            "./../../x",
            "..\\..\\..\\windows\\system32\\calc.exe",
            "dir/../../../../escape.txt",
        ],
    )
    def test_never_escapes_the_output_root(self, hostile):
        result = safe_relative_path(hostile)
        assert not posixpath.isabs(result)
        assert ".." not in result.split("/")
        joined = posixpath.normpath(posixpath.join("/out/root", result))
        assert joined.startswith("/out/root/") or joined == "/out/root"

    def test_resolve_within_contains_every_hostile_name(self, tmp_path):
        root = tmp_path / "downloads" / "bucket"
        for hostile in ("../../../etc/passwd", "../../.ssh/authorized_keys", "/etc/shadow", ".."):
            destination = resolve_within(root, hostile)
            assert root.resolve() in destination.parents or destination == root.resolve()

    def test_resolve_within_survives_a_symlinked_output_dir(self, tmp_path):
        """A symlink inside the tree must not become an escape hatch."""
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        link.symlink_to(real)
        destination = resolve_within(link, "../../etc/passwd")
        assert real.resolve() in destination.parents or destination == real.resolve()


class TestPreservesTheRealName:
    """The fix must not mangle names an operator legitimately wants on disk."""

    @pytest.mark.parametrize(
        "name",
        [
            ".env",
            "...",
            "....",
            "report..v2.json",
            ".hidden/.config",
            "logs/2026/09/app.log",
            "backups/db-2026.09.25_full.tar.gz",
            "name with spaces.txt",
            "unicode-Ünïcødé-ファイル.txt",
            "weird!@#$%^&()chars.txt",
            "config.json",
        ],
    )
    def test_legitimate_names_survive_verbatim(self, name):
        assert safe_relative_path(name) == name

    def test_dotdot_is_escaped_not_dropped(self):
        """a/../b and a/b are DIFFERENT objects in GCS -- keep them distinct."""
        assert safe_relative_path("a/../b") == f"a/{PARENT_SEGMENT_ESCAPE}/b"
        assert safe_relative_path("a/../b") != safe_relative_path("a/b")

    def test_triple_dot_is_a_normal_name_not_traversal(self):
        assert safe_relative_path(".../file") == ".../file"

    def test_redundant_current_dir_segments_are_dropped(self):
        assert safe_relative_path("./a/./b") == "a/b"

    def test_empty_name_falls_back(self):
        assert safe_relative_path("") == "file"
        assert safe_relative_path("/", fallback="blob") == "blob"


class TestRoundTrip:
    def test_a_deep_legitimate_blob_lands_where_expected(self, tmp_path):
        root = tmp_path / "out"
        destination = resolve_within(root, "logs/2026/09/.env")
        assert destination == (root.resolve() / "logs" / "2026" / "09" / ".env")
