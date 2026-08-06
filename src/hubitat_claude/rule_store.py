# =============================================================================
# rule_store.py — keeps local JSON copies of the rules running on the hub.
#
# Part of: hubitat-claude MCP server. Called by: server.py after any successful
# rule change, and by the sync_rules tool. Calls: the local filesystem only.
# Security: this is the one component that writes to disk, and the filename it
# writes is derived from a rule name the model chose — so the name is
# slugified to a fixed character set, never used raw, and every resolved path
# is proved to sit inside the configured directory before anything opens it.
# The directory is opt-in: unset the variable and this module never runs, so
# the server does not touch the filesystem unless an operator asked it to.
# =============================================================================
"""Mirror the hub's rules into a local directory of JSON files."""

import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

# Rule ids are hub-assigned installed-app ids: digits. Repeated here rather
# than imported so this module can be reasoned about on its own — it is the
# only thing standing between a rule id and a filesystem path.
_RULE_ID_PATTERN = re.compile(r"\A[0-9]{1,12}\Z")

# Files this module considers its own. Anything else in the directory is left
# alone: sync removes orphans, and an operator's own notes must not be one.
_OWNED_FILE_PATTERN = re.compile(r"\A[0-9]{1,12}-[a-z0-9-]*\.json\Z")

# Bounds the slug so a long rule name cannot produce a path near the operating
# system's filename limit.
_MAX_SLUG_CHARS = 60

# SECURITY: the rules describe which sensor guards which door and which light
# it drives. Owner-only, on a directory the process creates itself.
_DIR_MODE = 0o700
_FILE_MODE = 0o600


class RuleStoreError(Exception):
    """A rule copy could not be written, read, or removed."""


def slugify(name: str) -> str:
    """Reduce a rule name to a filename-safe slug.

    Args:
        name: The rule's name, as the model wrote it.

    Returns:
        Lowercase ASCII letters, digits, and single hyphens; empty when the
        name held nothing usable.
    """
    # SECURITY: an allowlist, not an escape. Every character outside
    # [a-z0-9] becomes a hyphen, so "..", "/", a NUL, and a Windows device
    # name all reduce to hyphens rather than surviving in any form. Unicode is
    # folded to ASCII first so a homoglyph cannot smuggle a separator through.
    folded = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    slug = re.sub(r"[^a-z0-9]+", "-", folded.lower()).strip("-")
    return slug[:_MAX_SLUG_CHARS].strip("-")


class RuleStore:
    """Writes and removes local copies of hub rules in one directory."""

    def __init__(self, directory: Path) -> None:
        """Bind the store to a directory, creating it if it does not exist.

        Args:
            directory: Where the copies live. Created owner-only if absent.

        Raises:
            RuleStoreError: The path exists and is not a directory, or it
                could not be created.
        """
        try:
            directory.mkdir(mode=_DIR_MODE, parents=True, exist_ok=True)
        except OSError as error:
            raise RuleStoreError(f"Could not create {directory}: {error}") from error
        if not directory.is_dir():
            raise RuleStoreError(f"{directory} exists but is not a directory.")
        # SECURITY: the resolved path is what every later containment check
        # compares against, so a symlinked directory is resolved once here
        # rather than re-evaluated per write.
        self._directory = directory.resolve()

    @property
    def directory(self) -> Path:
        """Return the resolved directory holding the copies."""
        return self._directory

    def _path_for(self, rule_id: str, name: str) -> Path:
        """Build the file path for one rule, proving it stays in the directory.

        Args:
            rule_id: The hub's rule id.
            name: The rule's name.

        Returns:
            The absolute path to write.

        Raises:
            RuleStoreError: The id is not numeric, or the path escapes the
                configured directory.
        """
        if not _RULE_ID_PATTERN.match(rule_id):
            raise RuleStoreError(f"Invalid rule id: {rule_id!r}")
        slug = slugify(name)
        candidate = self._directory / f"{rule_id}-{slug}.json"
        # SECURITY: belt and braces. The slug cannot contain a separator, so
        # this should never fire — which is exactly why it is here. A future
        # change to slugify that loosened the character set would be caught by
        # this check rather than by an incident.
        resolved = candidate.resolve()
        if resolved.parent != self._directory:
            raise RuleStoreError(f"Refused: {resolved} is outside {self._directory}.")
        return resolved

    def _owned_files(self) -> list[Path]:
        """Return the files in the directory this module considers its own.

        Returns:
            Every regular file matching the naming pattern. Symlinks are
            excluded, so a link planted in the directory is never followed.
        """
        found: list[Path] = []
        for entry in self._directory.iterdir():
            if entry.is_symlink() or not entry.is_file():
                continue
            if _OWNED_FILE_PATTERN.match(entry.name):
                found.append(entry)
        return found

    def write(self, rule_id: str, spec: dict[str, Any]) -> Path:
        """Write one rule's spec, replacing any earlier file for that id.

        Args:
            rule_id: The hub's rule id.
            spec: The rule spec exactly as the hub holds it.

        Returns:
            The path written.

        Raises:
            RuleStoreError: The id is invalid, or the file could not be written.
        """
        path = self._path_for(rule_id, str(spec.get("name", "")))
        # A renamed rule would otherwise leave its old filename behind next to
        # the new one, and the folder would grow a second copy of one rule.
        self.remove(rule_id, keep=path)
        try:
            # The spec is written exactly as create_rule accepts it — no id, no
            # fire count, no timestamp. The hub's validator refuses keys the
            # schema does not define, so anything extra here would make the
            # file unrestorable.
            body = json.dumps(spec, indent=2, sort_keys=True) + "\n"
            path.write_text(body, encoding="utf-8")
            os.chmod(path, _FILE_MODE)
        except (OSError, TypeError, ValueError) as error:
            raise RuleStoreError(f"Could not write {path.name}: {error}") from error
        return path

    def remove(self, rule_id: str, keep: Path | None = None) -> list[str]:
        """Remove every file this store holds for one rule id.

        Args:
            rule_id: The hub's rule id.
            keep: A path to leave in place, used when replacing a file.

        Returns:
            The names of the files removed.

        Raises:
            RuleStoreError: The id is not numeric.
        """
        if not _RULE_ID_PATTERN.match(rule_id):
            raise RuleStoreError(f"Invalid rule id: {rule_id!r}")
        removed: list[str] = []
        for path in self._owned_files():
            if path.name.split("-", 1)[0] != rule_id or path == keep:
                continue
            try:
                path.unlink()
                removed.append(path.name)
            except OSError as error:
                raise RuleStoreError(f"Could not remove {path.name}: {error}") from error
        return removed

    def sync(self, specs: dict[str, dict[str, Any]]) -> dict[str, list[str]]:
        """Make the directory match the hub exactly.

        Args:
            specs: Every rule the hub holds, keyed by rule id.

        Returns:
            A dict of `written` and `removed` filenames.

        Raises:
            RuleStoreError: A file could not be written or removed.
        """
        written = [self.write(rule_id, spec).name for rule_id, spec in sorted(specs.items())]
        # Orphans are files for rules the hub no longer has — a rule deleted on
        # the hub's own page, or one this server never saw removed. Reconciling
        # them is the whole reason sync exists: writes alone only keep the copies
        # current for changes that went through this server.
        kept = set(written)
        removed = []
        for path in self._owned_files():
            if path.name in kept:
                continue
            try:
                path.unlink()
                removed.append(path.name)
            except OSError as error:
                raise RuleStoreError(f"Could not remove {path.name}: {error}") from error
        return {"written": written, "removed": sorted(removed)}
