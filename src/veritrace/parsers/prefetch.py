"""VeriTrace Prefetch Parser — single-file module.

Parses Windows Prefetch (``.pf``) files into structured, immutable
``PrefetchRecord`` objects for use in cross-artifact consistency
analysis within the VeriTrace digital forensics framework.

Prefetch files are one of the strongest "did this program actually
run" artifacts on Windows: each ``.pf`` file records an executable's
name, run count, up to eight most-recent run timestamps, the files
and DLLs it referenced, and the volumes it ran from. Cross-referencing
this against EVTX process-creation events (Security 4688,
Sysmon Event ID 1) or registry persistence keys is a classic
anti-forensic detection pattern: a program with Prefetch evidence of
execution but no corresponding EVTX event (or vice versa) is a strong
signal worth investigating.

This module is self-contained: exceptions, data models, extraction
logic, and file-level orchestration all live here so the parser can
be dropped into a project as a single file.

Requires:
    libscca-python (``pip install libscca-python``), which provides
    the ``pyscca`` module used here.

Example:
    >>> from prefetch import PrefetchParser
    >>> parser = PrefetchParser("CALC.EXE-3EA9C6F2.pf")
    >>> record = parser.parse()
    >>> print(record.executable_name, record.run_count, record.last_run_times)

Command-line usage:
    Single file:
        python prefetch.py CALC.EXE-3EA9C6F2.pf

    Folder of files (parses every .pf file found):
        python prefetch.py "C:\\Windows\\Prefetch"
"""

from __future__ import annotations

import logging
import re
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pyscca

logger = logging.getLogger(__name__)

_EXPECTED_EXTENSION = ".pf"

# Prefetch filenames follow the pattern EXECUTABLE.EXE-HHHHHHHH.pf, where
# HHHHHHHH is the 8-hex-digit prefetch hash. Used to cross-check the
# filename against the hash embedded in the file's own binary structure.
_PREFETCH_FILENAME_PATTERN = re.compile(r"^(?P<name>.+)-(?P<hash>[0-9A-Fa-f]{8})\.pf$")

# Modern Prefetch format versions (Windows 8 and later) store up to this
# many most-recent run timestamps.
_MAX_LAST_RUN_TIMES = 8


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class PrefetchParsingError(Exception):
    """Base exception for all errors raised by the Prefetch parsing subsystem.

    All other exceptions in this module inherit from this class, so
    calling code that wants to catch any Prefetch-related failure can
    catch ``PrefetchParsingError`` alone.
    """


class PrefetchFileError(PrefetchParsingError):
    """Raised for file-level failures that prevent parsing from starting.

    Examples include a missing file, an unreadable file, an incorrect
    file extension, or a file that does not have a valid Prefetch
    (SCCA) signature.
    """


class FieldExtractionError(PrefetchParsingError):
    """Raised when a specific field group cannot be extracted from a Prefetch file.

    Scoped to a specific field group (e.g. volume information, or
    referenced filenames) so that :class:`PrefetchExtractor` can
    capture a partial record with the failure noted, rather than
    discarding an otherwise-readable file entirely because one
    sub-structure was damaged.
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class VolumeInfo:
    """Information about a volume an executable was run from.

    Attributes:
        device_path: The volume's device path (e.g.
            ``"\\\\DEVICE\\\\HARDDISKVOLUME2"``).
        serial_number: The volume's serial number, as a hex string.
            A volume serial number that doesn't match the system
            being investigated can indicate a copied/staged artifact.
        creation_time: The UTC timestamp the volume was created (i.e.
            formatted/created), or ``None`` if unavailable.
    """

    device_path: str | None
    serial_number: str | None
    creation_time: datetime | None


@dataclass(frozen=True, slots=True)
class PrefetchRecord:  # pylint: disable=too-many-instance-attributes
    """A single parsed Windows Prefetch (.pf) file.

    Note:
        Each field below is a distinct, independently meaningful
        forensic attribute of a Prefetch file; the field count
        reflects the SCCA schema itself, not incidental class
        complexity, so ``too-many-instance-attributes`` is
        intentionally suppressed for this dataclass.

    Attributes:
        source_path: Path to the ``.pf`` file this record was parsed
            from.
        executable_name: The name of the executable this Prefetch
            file tracks (e.g. ``"CALC.EXE"``), as recorded inside the
            file itself.
        prefetch_hash: The prefetch hash embedded in the file, as an
            8-character uppercase hex string, or ``None`` if
            unavailable.
        filename_hash_matches: Whether the hash encoded in the
            ``.pf`` filename matches the hash embedded in the file's
            own binary structure. ``None`` if the filename doesn't
            match the expected ``NAME-HHHHHHHH.pf`` pattern or the
            embedded hash is unavailable, in which case no comparison
            could be made. A mismatch is a strong anti-forensic
            indicator: it suggests the file was renamed or its
            contents were tampered with after creation.
        format_version: The Prefetch file format version (identifies
            which Windows version generated the file).
        run_count: The number of times the executable has been run,
            as tracked by this Prefetch file.
        last_run_times: Up to eight most-recent run timestamps (UTC),
            most recent first, as recorded by the file. Older
            Prefetch format versions may only have one.
        referenced_filenames: Files and DLLs referenced during the
            executable's startup, as recorded by the file. Useful for
            identifying loaded libraries, accessed configuration
            files, or supporting evidence of execution context.
        volumes: Volume information for each volume the executable
            was run from.
    """

    source_path: str
    executable_name: str | None
    prefetch_hash: str | None
    filename_hash_matches: bool | None
    format_version: int | None
    run_count: int | None
    last_run_times: tuple[datetime, ...]
    referenced_filenames: tuple[str, ...]
    volumes: tuple[VolumeInfo, ...]


@dataclass(frozen=True, slots=True)
class ParseFailure:
    """Details about a field group that failed extraction within a Prefetch file.

    Retaining failure details supports anti-forensic detection: a
    Prefetch file that opens but has a damaged sub-structure (e.g.
    volume information) can indicate partial corruption or tampering,
    distinct from a file that is entirely unreadable.

    Attributes:
        field_group: The name of the field group that failed to
            extract (e.g. ``"volumes"``, ``"referenced_filenames"``).
        reason: A human-readable description of why extraction failed.
    """

    field_group: str
    reason: str


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


class PrefetchExtractor:  # pylint: disable=too-few-public-methods
    """Extracts a :class:`PrefetchRecord` from an open ``pyscca.file``.

    Note:
        This class exposes a single public entry point (``extract``)
        backed by several private helper methods — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

    This class is stateless: it holds no state between calls, so a
    single instance may safely be reused across multiple Prefetch
    files. It has no dependency on file I/O itself — the caller is
    responsible for opening and closing the ``pyscca.file`` object —
    which makes it straightforward to unit test with mocked file
    objects instead of real ``.pf`` binary fixtures.

    Example:
        >>> extractor = PrefetchExtractor()
        >>> record = extractor.extract(opened_scca_file, source_path="CALC.EXE-3EA9C6F2.pf")
    """

    def extract(
        self, scca_file: pyscca.file, source_path: str
    ) -> tuple[PrefetchRecord, list[ParseFailure]]:
        """Convert an open Prefetch file object into a :class:`PrefetchRecord`.

        Extraction is resilient at the field-group level: if a
        specific group of fields (e.g. volume information) cannot be
        read, that group is omitted and the failure is returned
        alongside the record rather than aborting extraction of the
        rest of the file.

        Args:
            scca_file: An already-opened ``pyscca.file`` instance.
            source_path: The path of the ``.pf`` file being
                extracted, used to populate
                :attr:`PrefetchRecord.source_path` and for filename
                hash cross-checking.

        Returns:
            A tuple of ``(record, failures)``: the populated
            :class:`PrefetchRecord` (with any unreadable field groups
            left at their default/empty value) and a list of
            :class:`ParseFailure` describing any field groups that
            could not be read.
        """
        failures: list[ParseFailure] = []

        executable_name = self._safe(
            scca_file.get_executable_filename, "executable_name", failures
        )
        prefetch_hash = self._extract_prefetch_hash(scca_file, failures)
        format_version = self._safe(scca_file.get_format_version, "format_version", failures)
        run_count = self._safe(scca_file.get_run_count, "run_count", failures)
        last_run_times = self._extract_last_run_times(scca_file)
        referenced_filenames = self._extract_referenced_filenames(scca_file, failures)
        volumes = self._extract_volumes(scca_file, failures)
        filename_hash_matches = self._check_filename_hash(source_path, prefetch_hash)

        record = PrefetchRecord(
            source_path=source_path,
            executable_name=executable_name,
            prefetch_hash=prefetch_hash,
            filename_hash_matches=filename_hash_matches,
            format_version=format_version,
            run_count=run_count,
            last_run_times=tuple(last_run_times),
            referenced_filenames=tuple(referenced_filenames),
            volumes=tuple(volumes),
        )

        logger.debug(
            "Extracted Prefetch record: executable=%s, run_count=%s, failures=%d",
            executable_name,
            run_count,
            len(failures),
        )
        return record, failures

    @staticmethod
    def _safe(getter, field_group: str, failures: list[ParseFailure]):
        """Call a zero-argument getter, recording failure instead of raising.

        Args:
            getter: A zero-argument callable (typically a bound
                ``pyscca.file`` getter method).
            field_group: A label identifying which field this getter
                populates, used in the recorded failure if it raises.
            failures: The list to append a :class:`ParseFailure` to if
                the getter raises.

        Returns:
            The getter's return value, or ``None`` if it raised.
        """
        try:
            return getter()
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: isolates a single field group's failure
            # so the rest of the Prefetch file can still be extracted.
            logger.warning("Failed to extract '%s': %s", field_group, exc)
            failures.append(ParseFailure(field_group=field_group, reason=str(exc)))
            return None

    def _extract_prefetch_hash(
        self, scca_file: pyscca.file, failures: list[ParseFailure]
    ) -> str | None:
        """Extract the embedded prefetch hash as an 8-digit hex string.

        Args:
            scca_file: An already-opened ``pyscca.file`` instance.
            failures: The list to append a :class:`ParseFailure` to on
                error.

        Returns:
            The hash as an uppercase 8-character hex string, or
            ``None`` if unavailable.
        """
        raw_hash = self._safe(scca_file.get_prefetch_hash, "prefetch_hash", failures)
        if raw_hash is None:
            return None
        return f"{raw_hash:08X}"

    def _extract_last_run_times(self, scca_file: pyscca.file) -> list[datetime]:
        """Extract up to the maximum number of most-recent run timestamps.

        ``pyscca`` does not expose a direct "number of last run
        times" accessor, so this reads indices sequentially and stops
        at the first missing/unreadable slot. Running out of slots is
        expected behavior (older Prefetch format versions only have
        one), so unlike other extraction helpers this does not record
        a :class:`ParseFailure` when enumeration stops.

        Args:
            scca_file: An already-opened ``pyscca.file`` instance.

        Returns:
            A list of timezone-aware UTC timestamps, most recent
            first.
        """
        timestamps: list[datetime] = []
        for index in range(_MAX_LAST_RUN_TIMES):
            try:
                raw_timestamp = scca_file.get_last_run_time(index)
            except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
                # Deliberately broad: an out-of-range or unreadable slot
                # index should stop enumeration, not abort the whole record.
                logger.debug("Stopped reading last_run_times at index %d: %s", index, exc)
                break
            if raw_timestamp is None:
                break
            timestamps.append(self._normalize_timestamp(raw_timestamp))
        return timestamps

    def _extract_referenced_filenames(
        self, scca_file: pyscca.file, failures: list[ParseFailure]
    ) -> list[str]:
        """Extract the list of files/DLLs referenced during execution.

        Args:
            scca_file: An already-opened ``pyscca.file`` instance.
            failures: The list to append a :class:`ParseFailure` to on
                error.

        Returns:
            A list of referenced filenames, in file order. Empty if
            unavailable.
        """
        count = self._safe(
            scca_file.get_number_of_filenames, "referenced_filenames", failures
        )
        if not count:
            return []

        filenames: list[str] = []
        for index in range(count):
            try:
                name = scca_file.get_filename(index)
            except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
                # Deliberately broad: one unreadable filename entry should
                # not discard the rest of the (potentially large) list.
                logger.warning("Failed to read filename at index %d: %s", index, exc)
                failures.append(
                    ParseFailure(
                        field_group="referenced_filenames",
                        reason=f"index {index}: {exc}",
                    )
                )
                continue
            if name is not None:
                filenames.append(name)
        return filenames

    def _extract_volumes(
        self, scca_file: pyscca.file, failures: list[ParseFailure]
    ) -> list[VolumeInfo]:
        """Extract volume information for each volume referenced by the file.

        Args:
            scca_file: An already-opened ``pyscca.file`` instance.
            failures: The list to append a :class:`ParseFailure` to on
                error.

        Returns:
            A list of :class:`VolumeInfo` objects. Empty if
            unavailable.
        """
        count = self._safe(scca_file.get_number_of_volumes, "volumes", failures)
        if not count:
            return []

        volumes: list[VolumeInfo] = []
        for index in range(count):
            try:
                raw_volume = scca_file.get_volume_information(index)
            except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
                # Deliberately broad: one unreadable volume entry should not
                # discard volume information for the rest of the file.
                logger.warning("Failed to read volume at index %d: %s", index, exc)
                failures.append(
                    ParseFailure(field_group="volumes", reason=f"index {index}: {exc}")
                )
                continue
            if raw_volume is None:
                continue
            volumes.append(self._volume_to_model(raw_volume))
        return volumes

    def _volume_to_model(self, raw_volume: object) -> VolumeInfo:
        """Convert a raw ``pyscca`` volume information object into :class:`VolumeInfo`.

        Args:
            raw_volume: A raw volume information object as returned
                by ``pyscca.file.get_volume_information``.

        Returns:
            The populated :class:`VolumeInfo`.
        """
        device_path = getattr(raw_volume, "device_path", None)
        raw_serial = getattr(raw_volume, "serial_number", None)
        serial_number = f"{raw_serial:08X}" if raw_serial is not None else None
        raw_creation_time = getattr(raw_volume, "creation_time", None)
        creation_time = (
            self._normalize_timestamp(raw_creation_time) if raw_creation_time else None
        )
        return VolumeInfo(
            device_path=device_path,
            serial_number=serial_number,
            creation_time=creation_time,
        )

    @staticmethod
    def _normalize_timestamp(raw_timestamp: datetime) -> datetime:
        """Normalize a raw timestamp to timezone-aware UTC.

        Args:
            raw_timestamp: The timestamp as returned by ``pyscca``
                (typically a naive UTC ``datetime``).

        Returns:
            A timezone-aware UTC :class:`~datetime.datetime`.
        """
        if raw_timestamp.tzinfo is None:
            return raw_timestamp.replace(tzinfo=timezone.utc)
        return raw_timestamp.astimezone(timezone.utc)

    @staticmethod
    def _check_filename_hash(source_path: str, embedded_hash: str | None) -> bool | None:
        """Compare the hash encoded in the filename to the embedded hash.

        A mismatch is a strong anti-forensic indicator: it suggests
        the ``.pf`` file was renamed, or that its contents were
        modified after the filename was set (the OS names Prefetch
        files ``EXECUTABLE.EXE-HHHHHHHH.pf`` where ``HHHHHHHH`` is
        the hash of the executable's original path).

        Args:
            source_path: The path of the ``.pf`` file.
            embedded_hash: The hash embedded in the file's own binary
                structure, as an 8-character hex string, or ``None``
                if unavailable.

        Returns:
            ``True`` if the filename's hash matches the embedded
            hash, ``False`` if they differ, or ``None`` if the
            filename doesn't match the expected pattern or the
            embedded hash is unavailable.
        """
        if embedded_hash is None:
            return None
        match = _PREFETCH_FILENAME_PATTERN.match(Path(source_path).name)
        if match is None:
            return None
        return match.group("hash").upper() == embedded_hash.upper()


# --------------------------------------------------------------------------
# File-level orchestration
# --------------------------------------------------------------------------


class PrefetchParser:  # pylint: disable=too-few-public-methods
    """Parses a single Windows Prefetch (``.pf``) file.

    Note:
        This class exposes a single public entry point (``parse``)
        backed by several private helper methods — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

    Unlike EVTX or registry hives, a Prefetch file represents a
    single executable's execution history rather than a stream of
    independent records, so :meth:`parse` returns one
    :class:`PrefetchRecord` rather than a list. Field-group-level
    extraction failures (e.g. a damaged volume information
    sub-structure) are captured in :attr:`parse_failures` rather than
    discarding the whole file, consistent with the resilience
    philosophy used throughout VeriTrace's parsers.

    Attributes:
        file_path: The path to the ``.pf`` file being parsed.
        parse_failures: Details of any field groups that failed to
            extract, populated after calling :meth:`parse`.

    Example:
        >>> parser = PrefetchParser("CALC.EXE-3EA9C6F2.pf")
        >>> record = parser.parse()
        >>> len(parser.parse_failures)
        0
    """

    def __init__(
        self,
        file_path: str | Path,
        extractor: PrefetchExtractor | None = None,
    ) -> None:
        """Initialize the parser for a given file.

        Args:
            file_path: Path to the ``.pf`` file to parse.
            extractor: A :class:`PrefetchExtractor` instance to use
                for converting the opened file into a
                :class:`PrefetchRecord`. Defaults to a new instance
                if not provided. Accepting this as a constructor
                parameter allows a mock/stub extractor to be injected
                in unit tests.
        """
        self.file_path = Path(file_path)
        self._extractor = extractor if extractor is not None else PrefetchExtractor()
        self.parse_failures: list[ParseFailure] = []

    def parse(self) -> PrefetchRecord:
        """Parse the configured ``.pf`` file into a single Prefetch record.

        Returns:
            The populated :class:`PrefetchRecord`. Field groups that
            could not be extracted are left at their default/empty
            value and recorded in :attr:`parse_failures`.

        Raises:
            PrefetchFileError: If the file does not exist, does not
                have a ``.pf`` extension, does not have a valid
                Prefetch signature, or cannot be opened/read at all.
        """
        self._validate_file_path()
        self.parse_failures = []

        logger.info("Starting Prefetch parse: %s", self.file_path)

        scca_file = pyscca.file()
        try:
            scca_file.open(str(self.file_path))
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: pyscca raises generic exceptions for
            # structural corruption, and we want a single, consistent
            # VeriTrace exception type at this boundary regardless of the
            # underlying library's specific error type.
            raise PrefetchFileError(
                f"Failed to open Prefetch file '{self.file_path}': {exc}"
            ) from exc

        try:
            record, failures = self._extractor.extract(scca_file, str(self.file_path))
        finally:
            scca_file.close()

        self.parse_failures = failures

        logger.info(
            "Completed Prefetch parse: %s (executable=%s, %d field failures)",
            self.file_path,
            record.executable_name,
            len(self.parse_failures),
        )
        return record

    def _validate_file_path(self) -> None:
        """Validate that the configured file path is a readable Prefetch file.

        Raises:
            PrefetchFileError: If the path does not exist, is not a
                file, does not have a ``.pf`` extension, or does not
                have a valid Prefetch (SCCA) file signature.
        """
        if not self.file_path.exists():
            raise PrefetchFileError(f"File not found: {self.file_path}")
        if not self.file_path.is_file():
            raise PrefetchFileError(f"Path is not a file: {self.file_path}")
        if self.file_path.suffix.lower() != _EXPECTED_EXTENSION:
            raise PrefetchFileError(
                f"Expected a '{_EXPECTED_EXTENSION}' file, got: {self.file_path.suffix}"
            )
        try:
            has_valid_signature = pyscca.check_file_signature(str(self.file_path))
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: signature checking is a validation
            # convenience; any failure here should surface as a clear
            # PrefetchFileError rather than an opaque library exception.
            raise PrefetchFileError(
                f"Failed to check Prefetch file signature for '{self.file_path}': {exc}"
            ) from exc
        if not has_valid_signature:
            raise PrefetchFileError(
                f"File does not have a valid Prefetch (SCCA) signature: {self.file_path}"
            )


# --------------------------------------------------------------------------
# Batch (folder) orchestration
# --------------------------------------------------------------------------


def parse_folder(folder_path: str | Path) -> dict[Path, PrefetchRecord]:
    """Parse every ``.pf`` file found directly inside a folder.

    This is the most common real-world use case for Prefetch parsing:
    ``C:\\Windows\\Prefetch`` typically contains hundreds of ``.pf``
    files, one per distinct executable path, and analysts almost
    always want the whole folder processed together.

    Files that fail to open entirely (see :class:`PrefetchFileError`)
    are logged and skipped so that one corrupt or inaccessible file
    does not prevent the rest of the folder from being processed.
    Field-group-level parse failures within an otherwise-readable
    file are logged per file but not returned in bulk here; call
    :meth:`PrefetchParser.parse` directly on a specific file if you
    need that detail.

    Args:
        folder_path: Path to a directory containing ``.pf`` files.
            Only files directly inside this folder are considered
            (non-recursive).

    Returns:
        A dict mapping each successfully parsed file's
        :class:`~pathlib.Path` to its extracted
        :class:`PrefetchRecord`. Files that failed to open are
        omitted from the returned dict.

    Raises:
        PrefetchFileError: If ``folder_path`` does not exist or is
            not a directory.
    """
    folder = Path(folder_path)
    if not folder.exists():
        raise PrefetchFileError(f"Folder not found: {folder}")
    if not folder.is_dir():
        raise PrefetchFileError(f"Path is not a directory: {folder}")

    results: dict[Path, PrefetchRecord] = {}
    pf_files = sorted(folder.glob("*.pf"))

    logger.info("Found %d .pf file(s) in %s", len(pf_files), folder)

    for pf_file in pf_files:
        parser = PrefetchParser(pf_file)
        try:
            record = parser.parse()
        except PrefetchFileError as exc:
            logger.error("Skipping file '%s': %s", pf_file.name, exc)
            continue

        results[pf_file] = record
        if parser.parse_failures:
            logger.warning(
                "'%s': %d field group(s) failed to parse.",
                pf_file.name,
                len(parser.parse_failures),
            )
        if record.filename_hash_matches is False:
            logger.warning(
                "'%s': filename hash does not match embedded hash "
                "(possible rename/tampering).",
                pf_file.name,
            )

    return results


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _run_single_file(file_path: Path) -> None:
    """Parse and log the results of a single ``.pf`` file.

    Args:
        file_path: Path to the ``.pf`` file to parse.
    """
    parser = PrefetchParser(file_path)
    try:
        record = parser.parse()
    except PrefetchFileError as exc:
        logger.error("Parsing failed: %s", exc)
        raise SystemExit(1) from exc

    logger.info(
        "Executable=%s | RunCount=%s | Hash=%s | HashMatchesFilename=%s | Format=%s",
        record.executable_name,
        record.run_count,
        record.prefetch_hash,
        record.filename_hash_matches,
        record.format_version,
    )
    for run_time in record.last_run_times:
        logger.info("  Last run: %s", run_time)
    for volume in record.volumes:
        logger.info(
            "  Volume: %s | Serial=%s | Created=%s",
            volume.device_path,
            volume.serial_number,
            volume.creation_time,
        )
    logger.info("  Referenced %d file(s).", len(record.referenced_filenames))

    if parser.parse_failures:
        logger.warning("%d field group(s) failed to parse.", len(parser.parse_failures))


def _run_folder(folder_path: Path) -> None:
    """Parse and log a summary of every ``.pf`` file in a folder.

    Args:
        folder_path: Path to a directory containing ``.pf`` files.
    """
    try:
        results = parse_folder(folder_path)
    except PrefetchFileError as exc:
        logger.error("Batch parsing failed: %s", exc)
        raise SystemExit(1) from exc

    if not results:
        logger.warning("No .pf files were successfully parsed in %s", folder_path)
        return

    mismatches = 0
    for file_path, record in results.items():
        logger.info(
            "%s: executable=%s, run_count=%s",
            file_path.name,
            record.executable_name,
            record.run_count,
        )
        if record.filename_hash_matches is False:
            mismatches += 1

    logger.info(
        "Batch complete: %d file(s) parsed, %d filename/hash mismatch(es).",
        len(results),
        mismatches,
    )


def _main() -> None:
    """Run the parser as a script against either a single file or a folder.

    Usage:
        python prefetch.py <path-to-file.pf>
        python prefetch.py <path-to-folder>
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path-to-file.pf-or-folder>")
        raise SystemExit(1)

    target = Path(sys.argv[1])

    if target.is_dir():
        _run_folder(target)
    else:
        _run_single_file(target)


if __name__ == "__main__":
    _main()