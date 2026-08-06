# =============================================================================
# test_rule_store.py — proves the local rule mirror writes only where it is
# supposed to, and only what can be restored.
#
# Part of: hubitat-claude test suite. Tests: src/hubitat_claude/rule_store.py.
# The tests run against a real temporary directory rather than a mocked
# filesystem, because the properties that matter here — where a path resolves
# to, what a symlink does, which files a sweep deletes — are properties of the
# filesystem and vanish under a mock.
# =============================================================================
"""Tests for the local rule mirror."""

import json
import tempfile
import unittest
from pathlib import Path

from hubitat_claude.rule_store import RuleStore, RuleStoreError, slugify

_SPEC = {
    "name": "Hallway ceiling on when front door opens",
    "enabled": True,
    "trigger": {
        "type": "attribute",
        "deviceId": "239",
        "attribute": "contact",
        "changesTo": "open",
    },
    "actions": [{"type": "command", "deviceId": "343", "command": "on"}],
}


class SlugTests(unittest.TestCase):
    def test_an_ordinary_name_becomes_a_readable_slug(self):
        """The common case has to stay legible, or the filenames are useless."""
        self.assertEqual(
            slugify("Hallway ceiling on when front door opens"),
            "hallway-ceiling-on-when-front-door-opens",
        )

    def test_path_separators_and_traversal_do_not_survive(self):
        """The slug reaches a filename, so a separator in it would be a path."""
        for hostile in ("../../etc/passwd", "a/b", "a\\b", "..", "a\x00b"):
            with self.subTest(name=hostile):
                slug = slugify(hostile)
                self.assertNotIn("/", slug)
                self.assertNotIn("\\", slug)
                self.assertNotIn("\x00", slug)
                self.assertNotIn("..", slug)

    def test_unicode_is_folded_rather_than_passed_through(self):
        """A homoglyph must not smuggle a separator past an ASCII-only check."""
        self.assertEqual(slugify("Café — Ünicode"), "cafe-unicode")


class WriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = RuleStore(Path(self.tmp.name) / "rules")

    def test_a_written_spec_is_exactly_what_create_rule_accepts(self):
        """Extra keys would make the file unrestorable, since the hub refuses them."""
        path = self.store.write("304", _SPEC)

        self.assertEqual(json.loads(path.read_text()), _SPEC)

    def test_the_filename_carries_the_id_and_the_slug(self):
        """The id is not in the file, so the filename is where it has to live."""
        path = self.store.write("304", _SPEC)

        self.assertEqual(path.name, "304-hallway-ceiling-on-when-front-door-opens.json")

    def test_a_hostile_rule_name_still_writes_inside_the_directory(self):
        """The name comes from the model, so it must not be able to choose a path."""
        path = self.store.write("304", {**_SPEC, "name": "../../../../tmp/owned"})

        self.assertEqual(path.parent, self.store.directory)
        self.assertTrue(path.name.startswith("304-"))

    def test_a_non_numeric_rule_id_is_refused(self):
        """The id is the other half of the filename and gets the same treatment."""
        with self.assertRaises(RuleStoreError):
            self.store.write("../escape", _SPEC)

    def test_renaming_a_rule_leaves_one_file_not_two(self):
        """A stale filename would make the folder show a rule that no longer exists."""
        self.store.write("304", _SPEC)
        self.store.write("304", {**_SPEC, "name": "Renamed rule"})

        names = sorted(p.name for p in self.store.directory.iterdir())
        self.assertEqual(names, ["304-renamed-rule.json"])

    def test_the_file_is_owner_only(self):
        """A rule maps the home: which sensor guards which door."""
        path = self.store.write("304", _SPEC)

        self.assertEqual(path.stat().st_mode & 0o777, 0o600)


class SyncTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = RuleStore(Path(self.tmp.name) / "rules")

    def test_sync_removes_copies_of_rules_the_hub_no_longer_has(self):
        """Reconciling hub-side deletions is the whole reason sync exists."""
        self.store.write("304", _SPEC)
        self.store.write("305", {**_SPEC, "name": "Second rule"})

        result = self.store.sync({"304": _SPEC})

        self.assertEqual(result["removed"], ["305-second-rule.json"])
        self.assertEqual(
            sorted(p.name for p in self.store.directory.iterdir()),
            ["304-hallway-ceiling-on-when-front-door-opens.json"],
        )

    def test_sync_leaves_files_it_does_not_own_alone(self):
        """An operator's own notes in the folder are not orphans to sweep up."""
        note = self.store.directory / "NOTES.md"
        note.write_text("mine")
        readme = self.store.directory / "README.md"
        readme.write_text("also mine")

        self.store.sync({})

        self.assertTrue(note.exists())
        self.assertTrue(readme.exists())

    def test_sync_does_not_follow_a_symlink_planted_in_the_directory(self):
        """Following one would delete or overwrite a file outside the folder."""
        outside = Path(self.tmp.name) / "outside.json"
        outside.write_text("do not touch")
        (self.store.directory / "999-linked.json").symlink_to(outside)

        self.store.sync({})

        self.assertTrue(outside.exists())
        self.assertEqual(outside.read_text(), "do not touch")


class RemoveTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = RuleStore(Path(self.tmp.name) / "rules")

    def test_removing_a_rule_takes_its_file(self):
        """A deleted rule leaving its copy behind is the drift this prevents."""
        self.store.write("304", _SPEC)

        removed = self.store.remove("304")

        self.assertEqual(removed, ["304-hallway-ceiling-on-when-front-door-opens.json"])
        self.assertEqual(list(self.store.directory.iterdir()), [])

    def test_removing_one_rule_leaves_another_with_a_similar_id(self):
        """A prefix match on '30' would take 304 and 305 together."""
        self.store.write("30", _SPEC)
        self.store.write("304", {**_SPEC, "name": "Other"})

        self.store.remove("30")

        self.assertEqual(sorted(p.name for p in self.store.directory.iterdir()), ["304-other.json"])


if __name__ == "__main__":
    unittest.main()
