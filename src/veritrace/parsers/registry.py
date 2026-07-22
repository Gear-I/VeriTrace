"""VeriTrace Registry Parser — single-file module.

Parses offline Windows Registry hive files (e.g. ``NTUSER.DAT``,
``SYSTEM``, ``SOFTWARE``, ``SAM``, ``SECURITY``, ``AmCache.hve``) into
structured, immutable ``RegistryKey`` and ``RegistryValue`` objects for
use in cross-artifact consistency analysis within the VeriTrace digital
forensics framework.

This module is self-contained: exceptions, data models, value
extraction logic, and file-level orchestration all live here so the
parser can be dropped into a project as a single file.

Requires:
    python-registry (``pip install python-registry``)

Example:
    >>> from registry_parser import RegistryHiveParser
    >>> parser = RegistryHiveParser("NTUSER.DAT")
    >>> keys, values = parser.parse()
    >>> for key in keys:
    ...     print(key.path, key.last_written)
    >>> for value in values:
    ...     print(value.key_path, value.name, value.data)
    >>> for failure in parser.parse_failures:
    ...     print(failure.path, failure.reason)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from Registry.Registry import (
    Registry,
    RegistryKey as _RawRegistryKey,
    RegistryKeyNotFoundException,
    RegistryValue as _RawRegistryValue,
)

logger = logging.getLogger(__name__)

_EXPECTED_EXTENSIONS = frozenset(
    {".dat", ".hve", ".log", ""}
)  # Hive files often have no extension (SYSTEM, SOFTWARE, SAM, SECURITY).


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class RegistryParsingError(Exception):
    """Base exception for all errors raised by the registry parsing subsystem.

    All other exceptions in this module inherit from this class, so
    calling code that wants to catch any registry-related failure can
    catch ``RegistryParsingError`` alone.
    """


class RegistryFileError(RegistryParsingError):
    """Raised for file-level failures that prevent parsing from starting.

    Examples include a missing file, an unreadable file, or a file
    whose binary structure is so damaged that not even the hive
    header/root key can be read.
    """


class KeyExtractionError(RegistryParsingError):
    """Raised when a single registry key cannot be converted to a RegistryKey.

    Scoped to a single key so that :class:`RegistryHiveParser` can
    catch it, log it, and continue walking the rest of the key tree
    rather than aborting the entire parse.
    """


class ValueExtractionError(RegistryParsingError):
    """Raised when a single registry value cannot be converted to a RegistryValue.

    Scoped to a single value so that a corrupt or malformed value
    under an otherwise-healthy key does not prevent extraction of
    that key's other values, or of sibling/child keys.
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RegistryKey:
    """A single parsed registry key.

    Attributes:
        path: The full path of the key within the hive, e.g.
            ``"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run"``.
        name: The key's own name (the last path component).
        last_written: The UTC timestamp the key was last modified.
            Registry key timestamps are a well-known forensic
            indicator — e.g. unexpectedly recent LastWrite times on
            keys that should be static can indicate tampering.
        subkey_count: The number of immediate child subkeys.
        value_count: The number of values stored directly under this
            key.
    """

    path: str
    name: str
    last_written: datetime | None
    subkey_count: int
    value_count: int


@dataclass(frozen=True, slots=True)
class RegistryValue:
    """A single parsed registry value.

    Attributes:
        key_path: The full path of the key this value belongs to.
        name: The value's name. The default/unnamed value of a key is
            represented as an empty string, matching Windows
            Registry Editor convention.
        value_type: The numeric REG_* type constant (e.g. 1 for
            REG_SZ, 4 for REG_DWORD).
        value_type_str: The human-readable type name (e.g.
            ``"RegSZ"``, ``"RegDWord"``).
        data: The decoded value data (``str``, ``int``, ``bytes``, or
            a ``list[str]`` for REG_MULTI_SZ), as interpreted by the
            underlying parsing library.
        raw_data: The raw, unparsed bytes backing this value, as
            hex-encoded text. Retained for evidentiary/audit purposes
            so any interpreted ``data`` field can be independently
            re-verified against the original bytes.
        raw_data_bytes: The raw, unparsed bytes backing this value,
            retained alongside the hex string for programmatic
            re-parsing or hashing without needing to decode hex first.
    """

    key_path: str
    name: str
    value_type: int
    value_type_str: str
    data: object
    raw_data: str = field(repr=False)
    raw_data_bytes: bytes = field(repr=False)


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """Details about a single key or value that failed extraction.

    Retaining failure details (rather than merely counting failures)
    supports anti-forensic detection: a cluster of corrupt cells at a
    particular subtree, or a suspicious gap in an otherwise-populated
    key, can itself be an indicator of registry tampering (e.g. tools
    that corrupt or partially wipe specific keys/values to hide
    evidence of persistence, execution, or configuration changes).

    Attributes:
        path: The key or value path that failed to parse, if it could
            be determined before the failure occurred.
        reason: A human-readable description of why extraction failed.
    """

    path: str | None
    reason: str


# --------------------------------------------------------------------------
# Value extraction
# --------------------------------------------------------------------------


class RegistryValueExtractor:
    """Extracts :class:`RegistryValue` instances from raw hive value objects.

    This class is stateless: it holds no per-hive or per-value state
    between calls, so a single instance may safely be reused across
    an entire hive walk (or across multiple hives).

    Example:
        >>> extractor = RegistryValueExtractor()
        >>> value = extractor.extract(raw_value, key_path="Software\\\\Test")
    """

    def extract(self, raw_value: _RawRegistryValue, key_path: str) -> RegistryValue:
        """Convert a single raw hive value into a :class:`RegistryValue`.

        Args:
            raw_value: A value object as yielded by
                ``python-registry``'s ``RegistryKey.values()``.
            key_path: The full path of the key this value belongs to,
                used for logging, error reporting, and populating
                :attr:`RegistryValue.key_path`.

        Returns:
            The populated :class:`RegistryValue`.

        Raises:
            ValueExtractionError: If the value's name, type, or data
                cannot be read from the underlying hive structure.
        """
        try:
            name = raw_value.name()
            value_type = raw_value.value_type()
            value_type_str = raw_value.value_type_str()
        except Exception as exc:  # noqa: BLE001 - underlying parser surprise
            raise ValueExtractionError(
                f"Key '{key_path}': failed to read value metadata ({exc})"
            ) from exc

        try:
            data = raw_value.value()
        except Exception as exc:  # noqa: BLE001 - underlying parser surprise
            raise ValueExtractionError(
                f"Key '{key_path}', value '{name}': failed to decode value data ({exc})"
            ) from exc

        try:
            raw_bytes = raw_value.raw_data()
        except Exception as exc:  # noqa: BLE001 - underlying parser surprise
            raise ValueExtractionError(
                f"Key '{key_path}', value '{name}': failed to read raw bytes ({exc})"
            ) from exc

        logger.debug(
            "Extracted value '%s' (%s) under key '%s'", name, value_type_str, key_path
        )

        return RegistryValue(
            key_path=key_path,
            name=name,
            value_type=value_type,
            value_type_str=value_type_str,
            data=data,
            raw_data=raw_bytes.hex(),
            raw_data_bytes=raw_bytes,
        )


# --------------------------------------------------------------------------
# File-level orchestration
# --------------------------------------------------------------------------


class RegistryHiveParser:
    """Parses a Windows registry hive file into keys and values.

    The parser walks the key tree recursively starting from either
    the hive root or an optional scoped root path, and is resilient
    to per-key and per-value corruption: if an individual key or
    value cannot be read or converted, the failure is logged and
    recorded in :attr:`parse_failures`, and traversal continues with
    the remaining siblings/subkeys. This is a deliberate design
    choice for forensic use: aborting on the first bad key would make
    it impossible to distinguish "a tool bug" from "an anti-forensic
    artifact," and would discard all keys/values that parsed
    successfully.

    Attributes:
        file_path: The path to the hive file being parsed.
        parse_failures: Details of any keys or values that failed to
            parse, populated after calling :meth:`parse`.

    Example:
        >>> parser = RegistryHiveParser("NTUSER.DAT")
        >>> keys, values = parser.parse()
        >>> len(parser.parse_failures)
        0

        >>> # Scope the walk to a specific subtree:
        >>> parser = RegistryHiveParser("NTUSER.DAT")
        >>> keys, values = parser.parse(root_path="Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run")
    """

    def __init__(
        self,
        file_path: str | Path,
        value_extractor: RegistryValueExtractor | None = None,
    ) -> None:
        """Initialize the parser for a given hive file.

        Args:
            file_path: Path to the registry hive file to parse.
            value_extractor: A :class:`RegistryValueExtractor` instance
                to use for converting raw values into
                :class:`RegistryValue` objects. Defaults to a new
                instance if not provided. Accepting this as a
                constructor parameter allows a mock/stub extractor to
                be injected in unit tests.
        """
        self.file_path = Path(file_path)
        self._value_extractor = (
            value_extractor if value_extractor is not None else RegistryValueExtractor()
        )
        self.parse_failures: list[ParseFailure] = []

    def parse(self, root_path: str | None = None) -> tuple[list[RegistryKey], list[RegistryValue]]:
        """Parse the configured hive file into keys and values.

        Args:
            root_path: An optional key path (relative to the hive
                root, using backslashes, e.g.
                ``"Software\\\\Microsoft"``) to scope the walk to a
                specific subtree instead of walking the entire hive.
                If ``None`` (the default), the full hive is walked
                starting from its root.

        Returns:
            A tuple of ``(keys, values)``: a list of successfully
            extracted :class:`RegistryKey` objects and a list of
            successfully extracted :class:`RegistryValue` objects, in
            the order encountered during a depth-first walk. Keys or
            values that fail to parse are omitted from these lists
            but are recorded in :attr:`parse_failures`.

        Raises:
            RegistryFileError: If the file does not exist, cannot be
                opened, or its structure is too damaged to read a
                root/starting key (or the requested ``root_path``
                does not exist in the hive).
        """
        self._validate_file_path()
        self.parse_failures = []
        keys: list[RegistryKey] = []
        values: list[RegistryValue] = []

        logger.info("Starting registry hive parse: %s", self.file_path)

        try:
            with self.file_path.open("rb") as hive_file:
                registry = Registry(hive_file)
                start_key = self._resolve_start_key(registry, root_path)
                self._walk(start_key, keys, values)
        except RegistryFileError:
            raise
        except Exception as exc:  # noqa: BLE001 - any low-level parser failure
            raise RegistryFileError(
                f"Failed to open or read hive file '{self.file_path}': {exc}"
            ) from exc

        logger.info(
            "Completed registry hive parse: %s (%d keys, %d values, %d failures)",
            self.file_path,
            len(keys),
            len(values),
            len(self.parse_failures),
        )
        return keys, values

    def _resolve_start_key(
        self, registry: Registry, root_path: str | None
    ) -> _RawRegistryKey:
        """Resolve the key the walk should start from.

        Args:
            registry: The opened ``python-registry`` ``Registry``
                instance.
            root_path: An optional key path to scope the walk to, or
                ``None`` to start from the hive root.

        Returns:
            The raw starting key object to begin the walk from.

        Raises:
            RegistryFileError: If the hive root cannot be read, or
                ``root_path`` does not exist in the hive.
        """
        try:
            root_key = registry.root()
        except Exception as exc:  # noqa: BLE001 - underlying parser failure
            raise RegistryFileError(
                f"Failed to read root key of hive '{self.file_path}': {exc}"
            ) from exc

        if root_path is None:
            return root_key

        try:
            return root_key.find_key(root_path)
        except RegistryKeyNotFoundException as exc:
            raise RegistryFileError(
                f"Root path '{root_path}' not found in hive '{self.file_path}'"
            ) from exc

    def _walk(
        self,
        raw_key: _RawRegistryKey,
        keys: list[RegistryKey],
        values: list[RegistryValue],
    ) -> None:
        """Recursively walk a key and its subkeys, accumulating results.

        Failures encountered while reading this key's own metadata,
        its values, or a given subkey are caught, logged, and
        recorded in :attr:`parse_failures` rather than propagated, so
        that one damaged key or value does not halt traversal of the
        rest of the tree.

        Args:
            raw_key: The raw key object (as yielded by
                ``python-registry``) to process.
            keys: The accumulator list to append successfully
                extracted :class:`RegistryKey` objects to.
            values: The accumulator list to append successfully
                extracted :class:`RegistryValue` objects to.
        """
        key_path: str | None = None
        try:
            key_path = raw_key.path()
            key = self._extract_key(raw_key, key_path)
            keys.append(key)
        except KeyExtractionError as exc:
            logger.warning("Skipping key '%s': %s", key_path, exc)
            self.parse_failures.append(ParseFailure(path=key_path, reason=str(exc)))
            return
        except Exception as exc:  # noqa: BLE001 - isolate any unexpected per-key error
            logger.warning("Skipping key '%s' due to unexpected error: %s", key_path, exc)
            self.parse_failures.append(ParseFailure(path=key_path, reason=str(exc)))
            return

        self._extract_values(raw_key, key_path, values)

        try:
            subkeys = list(raw_key.subkeys())
        except Exception as exc:  # noqa: BLE001 - underlying parser failure
            logger.warning(
                "Failed to enumerate subkeys of '%s': %s", key_path, exc
            )
            self.parse_failures.append(
                ParseFailure(path=key_path, reason=f"Failed to enumerate subkeys: {exc}")
            )
            return

        for raw_subkey in subkeys:
            self._walk(raw_subkey, keys, values)

    def _extract_key(self, raw_key: _RawRegistryKey, key_path: str) -> RegistryKey:
        """Convert a single raw key object into a :class:`RegistryKey`.

        Args:
            raw_key: The raw key object to convert.
            key_path: The already-resolved full path of the key.

        Returns:
            The populated :class:`RegistryKey`.

        Raises:
            KeyExtractionError: If the key's name, timestamp, or
                subkey/value counts cannot be read.
        """
        try:
            name = raw_key.name()
            last_written = self._normalize_timestamp(raw_key.timestamp())
            subkey_count = raw_key.subkeys_number()
            value_count = raw_key.values_number()
        except Exception as exc:  # noqa: BLE001 - underlying parser surprise
            raise KeyExtractionError(
                f"Key '{key_path}': failed to read key metadata ({exc})"
            ) from exc

        return RegistryKey(
            path=key_path,
            name=name,
            last_written=last_written,
            subkey_count=subkey_count,
            value_count=value_count,
        )

    def _extract_values(
        self,
        raw_key: _RawRegistryKey,
        key_path: str,
        values: list[RegistryValue],
    ) -> None:
        """Extract all values under a key, isolating per-value failures.

        Args:
            raw_key: The raw key object whose values should be
                extracted.
            key_path: The already-resolved full path of the key, used
                for logging and error reporting.
            values: The accumulator list to append successfully
                extracted :class:`RegistryValue` objects to.
        """
        try:
            raw_values = list(raw_key.values())
        except Exception as exc:  # noqa: BLE001 - underlying parser failure
            logger.warning("Failed to enumerate values of '%s': %s", key_path, exc)
            self.parse_failures.append(
                ParseFailure(path=key_path, reason=f"Failed to enumerate values: {exc}")
            )
            return

        for raw_value in raw_values:
            try:
                value = self._value_extractor.extract(raw_value, key_path)
                values.append(value)
            except ValueExtractionError as exc:
                logger.warning("Skipping value under '%s': %s", key_path, exc)
                self.parse_failures.append(ParseFailure(path=key_path, reason=str(exc)))
            except Exception as exc:  # noqa: BLE001 - isolate unexpected per-value error
                logger.warning(
                    "Skipping value under '%s' due to unexpected error: %s", key_path, exc
                )
                self.parse_failures.append(ParseFailure(path=key_path, reason=str(exc)))

    @staticmethod
    def _normalize_timestamp(raw_timestamp: datetime | None) -> datetime | None:
        """Normalize a raw key timestamp to timezone-aware UTC.

        Args:
            raw_timestamp: The timestamp as returned by
                ``python-registry`` (naive UTC ``datetime`` or
                ``None``).

        Returns:
            A timezone-aware UTC :class:`~datetime.datetime`, or
            ``None`` if no timestamp was available.
        """
        if raw_timestamp is None:
            return None
        if raw_timestamp.tzinfo is None:
            return raw_timestamp.replace(tzinfo=timezone.utc)
        return raw_timestamp.astimezone(timezone.utc)

    def _validate_file_path(self) -> None:
        """Validate that the configured file path is a readable hive file.

        Raises:
            RegistryFileError: If the path does not exist or is not a
                file. Unlike EVTX files, registry hives commonly have
                no file extension at all (e.g. ``SYSTEM``,
                ``SOFTWARE``, ``SAM``), so extension is not used as a
                strict validation gate here.
        """
        if not self.file_path.exists():
            raise RegistryFileError(f"File not found: {self.file_path}")
        if not self.file_path.is_file():
            raise RegistryFileError(f"Path is not a file: {self.file_path}")


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _main() -> None:
    """Run the parser as a script: ``python registry_parser.py <hive-file> [root_path]``."""
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) not in (2, 3):
        print(f"Usage: python {sys.argv[0]} <path-to-hive-file> [root_path]")
        raise SystemExit(1)

    hive_path = sys.argv[1]
    root_path = sys.argv[2] if len(sys.argv) == 3 else None

    parser = RegistryHiveParser(hive_path)
    try:
        keys, values = parser.parse(root_path=root_path)
    except RegistryFileError as exc:
        logger.error("Parsing failed: %s", exc)
        raise SystemExit(1) from exc

    for key in keys:
        logger.info(
            "KEY %s | LastWritten=%s | Subkeys=%d | Values=%d",
            key.path,
            key.last_written,
            key.subkey_count,
            key.value_count,
        )
    for value in values:
        logger.info(
            "VALUE %s\\%s | %s | %r",
            value.key_path,
            value.name or "(default)",
            value.value_type_str,
            value.data,
        )

    if parser.parse_failures:
        logger.warning("%d key(s)/value(s) failed to parse.", len(parser.parse_failures))


if __name__ == "__main__":
    _main()