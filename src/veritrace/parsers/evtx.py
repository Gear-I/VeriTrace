"""VeriTrace EVTX Parser — single-file module.

Parses Windows ``.evtx`` event log files into structured, immutable
``EventRecord`` objects for use in cross-artifact consistency analysis
within the VeriTrace digital forensics framework.

This module is self-contained: exceptions, data models, XML
extraction logic, and file-level orchestration all live here so the
parser can be dropped into a project as a single file. The
command-line entry point supports both a single ``.evtx`` file and a
folder of ``.evtx`` files.

Requires:
    python-evtx (``pip install python-evtx``)

Example:
    >>> from evtx import EvtxParser
    >>> parser = EvtxParser("Security.evtx")
    >>> records = parser.parse()
    >>> for record in records:
    ...     print(record.record_number, record.event_id, record.provider_name)
    >>> for failure in parser.parse_failures:
    ...     print(failure.record_number, failure.reason)

Command-line usage:
    Single file:
        python evtx.py Security.evtx

    Folder of files (parses every .evtx file found):
        python evtx.py "C:\\path\\to\\evtx_folder"
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_record_xml_view

logger = logging.getLogger(__name__)

# The Windows Event Log XML schema namespace used in EVTX record XML.
_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

_EXPECTED_EXTENSION = ".evtx"


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------


class EvtxParsingError(Exception):
    """Base exception for all errors raised by the EVTX parsing subsystem.

    All other exceptions in this module inherit from this class, so
    calling code that wants to catch any EVTX-related failure can
    catch ``EvtxParsingError`` alone.
    """


class EvtxFileError(EvtxParsingError):
    """Raised for file-level failures that prevent parsing from starting.

    Examples include a missing file, an unreadable file, an incorrect
    file extension, or a file whose binary structure is so damaged
    that not even the file header can be read.
    """


class RecordExtractionError(EvtxParsingError):
    """Raised when a single event record cannot be converted to an EventRecord.

    This exception is intentionally scoped to a *single record* so
    that :class:`EvtxParser` can catch it, log it, and continue
    processing the remaining records in the file rather than
    aborting the entire parse.
    """


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EventRecord:
    """A single parsed Windows Event Log record.

    Attributes:
        record_number: The EVTX record number, unique within a single
            log file. Gaps or non-monotonic sequences in record
            numbers across a file can themselves be forensic
            indicators of log tampering.
        event_id: The numeric Event ID (e.g. 4624 for a successful
            logon).
        timestamp: The UTC timestamp at which the event was logged,
            taken from the record's ``TimeCreated`` XML element.
        provider_name: The name of the component that logged the
            event (the ``Provider Name`` attribute), or ``None`` if
            absent.
        computer_name: The hostname of the machine that generated the
            event, or ``None`` if absent.
        channel: The event log channel the record belongs to (e.g.
            ``"Security"``, ``"System"``), or ``None`` if absent.
        level: The numeric severity level of the event (0-5,
            corresponding to LogAlways, Critical, Error, Warning,
            Information, Verbose), or ``None`` if absent.
        message: The rendered event message/description, if available.
            ``python-evtx`` does not resolve message templates from
            provider DLLs/manifests, so this is typically ``None``
            unless the message text is embedded directly in the
            record's ``EventData``/``UserData``.
        raw_xml: The full, unmodified XML representation of the
            record as produced by ``python-evtx``. Retained for
            evidentiary and audit purposes so that any field derived
            above can be independently verified against the original
            structured representation of the record.
    """

    record_number: int
    event_id: int | None
    timestamp: datetime | None
    provider_name: str | None
    computer_name: str | None
    channel: str | None
    level: int | None
    message: str | None
    raw_xml: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RecordParseFailure:
    """Details about a single EVTX record that failed extraction.

    Retaining failure details (rather than merely counting failures)
    supports anti-forensic detection: a cluster of corrupt records at
    a particular offset, or a suspicious gap in record numbers, can
    itself be an indicator of log tampering (e.g. partial log wiping
    tools that corrupt rather than cleanly delete records).

    Attributes:
        record_number: The record number that failed to parse, if it
            could be determined before the failure occurred.
            ``None`` if the record number itself could not be read.
        reason: A human-readable description of why extraction failed.
    """

    record_number: int | None
    reason: str


# --------------------------------------------------------------------------
# XML extraction
# --------------------------------------------------------------------------


class EventRecordExtractor:
    """Extracts :class:`EventRecord` instances from Windows Event XML.

    This class is stateless: it holds no per-file or per-record state
    between calls, so a single instance may safely be reused across
    an entire EVTX file (or across multiple files). It has no
    dependency on file I/O or ``python-evtx``, which makes it fast to
    unit test with hand-crafted XML strings.

    Example:
        >>> extractor = EventRecordExtractor()
        >>> record = extractor.extract(xml_string, record_number=1)
    """

    def extract(self, xml_string: str, record_number: int) -> EventRecord:
        """Convert a single record's XML into an :class:`EventRecord`.

        Args:
            xml_string: The full XML representation of one Windows
                Event Log record, as produced by
                ``Evtx.Views.evtx_record_xml_view``.
            record_number: The EVTX record number associated with
                this XML, used for logging and error reporting.

        Returns:
            The populated :class:`EventRecord`.

        Raises:
            RecordExtractionError: If the XML is malformed, or the
                mandatory ``System`` element cannot be located.
        """
        try:
            root = ElementTree.fromstring(xml_string)
        except ElementTree.ParseError as exc:
            raise RecordExtractionError(
                f"Record {record_number}: malformed XML ({exc})"
            ) from exc

        system_element = root.find(f"{_EVENT_NS}System")
        if system_element is None:
            raise RecordExtractionError(
                f"Record {record_number}: missing mandatory <System> element"
            )

        try:
            event_id = self._extract_event_id(system_element)
            timestamp = self._extract_timestamp(system_element)
            provider_name = self._extract_provider_name(system_element)
            computer_name = self._extract_text(system_element, "Computer")
            channel = self._extract_text(system_element, "Channel")
            level = self._extract_level(system_element)
            message = self._extract_message(root)
        except RecordExtractionError:
            raise
        except Exception as exc:  # noqa: BLE001 - convert any parsing surprise
            raise RecordExtractionError(
                f"Record {record_number}: unexpected extraction failure ({exc})"
            ) from exc

        logger.debug(
            "Extracted record %s: event_id=%s, provider=%s",
            record_number,
            event_id,
            provider_name,
        )

        return EventRecord(
            record_number=record_number,
            event_id=event_id,
            timestamp=timestamp,
            provider_name=provider_name,
            computer_name=computer_name,
            channel=channel,
            level=level,
            message=message,
            raw_xml=xml_string,
        )

    def _extract_text(self, system_element: ElementTree.Element, tag: str) -> str | None:
        """Return the text content of a direct child element, if present.

        Args:
            system_element: The ``<System>`` XML element to search
                within.
            tag: The unqualified tag name of the child element to
                find (the event namespace is applied automatically).

        Returns:
            The element's text content, or ``None`` if the element is
            absent or has no text.
        """
        element = system_element.find(f"{_EVENT_NS}{tag}")
        if element is None or element.text is None:
            return None
        return element.text.strip()

    def _extract_event_id(self, system_element: ElementTree.Element) -> int | None:
        """Extract and parse the numeric Event ID.

        Args:
            system_element: The ``<System>`` XML element to search
                within.

        Returns:
            The Event ID as an integer, or ``None`` if absent or
            unparseable.
        """
        raw_value = self._extract_text(system_element, "EventID")
        if raw_value is None:
            return None
        try:
            return int(raw_value)
        except ValueError:
            logger.warning("Non-numeric EventID encountered: %r", raw_value)
            return None

    def _extract_timestamp(self, system_element: ElementTree.Element) -> datetime | None:
        """Extract and parse the event's creation timestamp.

        Args:
            system_element: The ``<System>`` XML element to search
                within.

        Returns:
            A timezone-aware UTC :class:`~datetime.datetime`, or
            ``None`` if the ``TimeCreated`` element or its
            ``SystemTime`` attribute is absent or unparseable.
        """
        time_created = system_element.find(f"{_EVENT_NS}TimeCreated")
        if time_created is None:
            return None

        raw_value = time_created.get("SystemTime")
        if raw_value is None:
            return None

        try:
            # EVTX timestamps are ISO 8601 UTC, e.g. "2024-01-01T00:00:00.123456Z".
            normalized = raw_value.replace("Z", "+00:00")
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            logger.warning("Unparseable TimeCreated value: %r", raw_value)
            return None

    def _extract_provider_name(self, system_element: ElementTree.Element) -> str | None:
        """Extract the provider name from the ``<Provider>`` element.

        Args:
            system_element: The ``<System>`` XML element to search
                within.

        Returns:
            The value of the ``Name`` attribute on ``<Provider>``, or
            ``None`` if absent.
        """
        provider = system_element.find(f"{_EVENT_NS}Provider")
        if provider is None:
            return None
        return provider.get("Name")

    def _extract_level(self, system_element: ElementTree.Element) -> int | None:
        """Extract and parse the numeric event severity level.

        Args:
            system_element: The ``<System>`` XML element to search
                within.

        Returns:
            The level as an integer, or ``None`` if absent or
            unparseable.
        """
        raw_value = self._extract_text(system_element, "Level")
        if raw_value is None:
            return None
        try:
            return int(raw_value)
        except ValueError:
            logger.warning("Non-numeric Level encountered: %r", raw_value)
            return None

    def _extract_message(self, root: ElementTree.Element) -> str | None:
        """Extract a best-effort message string from event data.

        ``python-evtx`` does not resolve message templates against
        provider message-table DLLs/manifests, so a fully rendered
        message (as seen in Event Viewer) is generally unavailable
        offline. This method falls back to concatenating any
        ``EventData``/``UserData`` string values so that at least
        some human-readable content is surfaced when present.

        Args:
            root: The root ``<Event>`` XML element.

        Returns:
            A concatenated string of available event data values, or
            ``None`` if no such data exists.
        """
        event_data = root.find(f"{_EVENT_NS}EventData")
        if event_data is None:
            event_data = root.find(f"{_EVENT_NS}UserData")
        if event_data is None:
            return None

        values = [
            elem.text.strip() for elem in event_data.iter() if elem.text and elem.text.strip()
        ]
        if not values:
            return None
        return " | ".join(values)


# --------------------------------------------------------------------------
# File-level orchestration
# --------------------------------------------------------------------------


class EvtxParser:
    """Parses a Windows ``.evtx`` file into a list of :class:`EventRecord` objects.

    The parser is resilient to per-record corruption: if an
    individual record cannot be read or converted, the failure is
    logged and recorded in :attr:`parse_failures`, and parsing
    continues with the next record. This is a deliberate design
    choice for forensic use: aborting on the first bad record would
    make it impossible to distinguish "a tool bug" from "an
    anti-forensic artifact," and would discard all records that
    parsed successfully.

    Attributes:
        file_path: The path to the ``.evtx`` file being parsed.
        parse_failures: Details of any records that failed to parse,
            populated after calling :meth:`parse`.

    Example:
        >>> parser = EvtxParser("Security.evtx")
        >>> records = parser.parse()
        >>> len(parser.parse_failures)
        0
    """

    def __init__(
        self,
        file_path: str | Path,
        extractor: EventRecordExtractor | None = None,
    ) -> None:
        """Initialize the parser for a given file.

        Args:
            file_path: Path to the ``.evtx`` file to parse.
            extractor: An :class:`EventRecordExtractor` instance to
                use for converting record XML into
                :class:`EventRecord` objects. Defaults to a new
                instance if not provided. Accepting this as a
                constructor parameter allows a mock/stub extractor to
                be injected in unit tests.
        """
        self.file_path = Path(file_path)
        self._extractor = extractor if extractor is not None else EventRecordExtractor()
        self.parse_failures: list[RecordParseFailure] = []

    def parse(self) -> list[EventRecord]:
        """Parse the configured ``.evtx`` file into event records.

        Returns:
            A list of successfully extracted :class:`EventRecord`
            objects, in the order they appear in the file. Records
            that fail to parse are omitted from this list but are
            recorded in :attr:`parse_failures`.

        Raises:
            EvtxFileError: If the file does not exist, does not have
                a ``.evtx`` extension, or cannot be opened/read as a
                valid EVTX file (e.g. the file header is corrupt).
        """
        self._validate_file_path()
        self.parse_failures = []
        records: list[EventRecord] = []

        logger.info("Starting EVTX parse: %s", self.file_path)

        try:
            with Evtx(str(self.file_path)) as evtx_log:
                for raw_record in evtx_log.records():
                    self._process_record(raw_record, records)
        except EvtxFileError:
            raise
        except Exception as exc:  # noqa: BLE001 - any low-level parser failure
            raise EvtxFileError(
                f"Failed to open or read EVTX file '{self.file_path}': {exc}"
            ) from exc

        logger.info(
            "Completed EVTX parse: %s (%d records extracted, %d failures)",
            self.file_path,
            len(records),
            len(self.parse_failures),
        )
        return records

    def _process_record(self, raw_record: object, records: list[EventRecord]) -> None:
        """Extract a single raw record and append it to ``records`` on success.

        Failures are caught, logged, and appended to
        :attr:`parse_failures` rather than propagated, so that one
        damaged record does not halt processing of the rest of the
        file.

        Args:
            raw_record: A record object as yielded by
                ``Evtx.records()``.
            records: The accumulator list to append successfully
                extracted :class:`EventRecord` objects to.
        """
        record_number: int | None = None
        try:
            # python-evtx ships no type stubs, so the raw record object is
            # typed as `object` at this boundary; `record_num()` is part of
            # its documented runtime interface.
            record_number = raw_record.record_num()  # type: ignore[attr-defined]
            xml_string = evtx_record_xml_view(raw_record)
            event_record = self._extractor.extract(xml_string, record_number)
            records.append(event_record)
        except RecordExtractionError as exc:
            logger.warning("Skipping record %s: %s", record_number, exc)
            self.parse_failures.append(
                RecordParseFailure(record_number=record_number, reason=str(exc))
            )
        except Exception as exc:  # noqa: BLE001 - isolate any unexpected per-record error
            logger.warning(
                "Skipping record %s due to unexpected error: %s", record_number, exc
            )
            self.parse_failures.append(
                RecordParseFailure(record_number=record_number, reason=str(exc))
            )

    def _validate_file_path(self) -> None:
        """Validate that the configured file path is a readable ``.evtx`` file.

        Raises:
            EvtxFileError: If the path does not exist, is not a file,
                or does not have a ``.evtx`` extension.
        """
        if not self.file_path.exists():
            raise EvtxFileError(f"File not found: {self.file_path}")
        if not self.file_path.is_file():
            raise EvtxFileError(f"Path is not a file: {self.file_path}")
        if self.file_path.suffix.lower() != _EXPECTED_EXTENSION:
            raise EvtxFileError(
                f"Expected a '{_EXPECTED_EXTENSION}' file, got: {self.file_path.suffix}"
            )


# --------------------------------------------------------------------------
# Batch (folder) orchestration
# --------------------------------------------------------------------------


def parse_folder(folder_path: str | Path) -> dict[Path, list[EventRecord]]:
    """Parse every ``.evtx`` file found directly inside a folder.

    Files that fail to open entirely (see :class:`EvtxFileError`) are
    logged and skipped so that one corrupt or inaccessible file does
    not prevent the rest of the folder from being processed. Per-file
    parse failures (individual bad records) remain available on each
    file's own :class:`EvtxParser` instance and are not surfaced
    here; use :meth:`EvtxParser.parse` directly per file if you need
    that detail.

    Args:
        folder_path: Path to a directory containing ``.evtx`` files.
            Only files directly inside this folder are considered
            (non-recursive).

    Returns:
        A dict mapping each successfully parsed file's
        :class:`~pathlib.Path` to its list of extracted
        :class:`EventRecord` objects. Files that failed to open are
        omitted from the returned dict.

    Raises:
        EvtxFileError: If ``folder_path`` does not exist or is not a
            directory.
    """
    folder = Path(folder_path)
    if not folder.exists():
        raise EvtxFileError(f"Folder not found: {folder}")
    if not folder.is_dir():
        raise EvtxFileError(f"Path is not a directory: {folder}")

    results: dict[Path, list[EventRecord]] = {}
    evtx_files = sorted(folder.glob("*.evtx"))

    logger.info("Found %d .evtx file(s) in %s", len(evtx_files), folder)

    for evtx_file in evtx_files:
        parser = EvtxParser(evtx_file)
        try:
            records = parser.parse()
        except EvtxFileError as exc:
            logger.error("Skipping file '%s': %s", evtx_file.name, exc)
            continue

        results[evtx_file] = records
        if parser.parse_failures:
            logger.warning(
                "'%s': %d record(s) failed to parse.",
                evtx_file.name,
                len(parser.parse_failures),
            )

    return results


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _run_single_file(file_path: Path) -> None:
    """Parse and log the results of a single ``.evtx`` file.

    Args:
        file_path: Path to the ``.evtx`` file to parse.
    """
    parser = EvtxParser(file_path)
    try:
        records = parser.parse()
    except EvtxFileError as exc:
        logger.error("Parsing failed: %s", exc)
        raise SystemExit(1) from exc

    for record in records:
        logger.info(
            "Record %s | EventID=%s | %s | Provider=%s | Channel=%s | Level=%s | Computer=%s",
            record.record_number,
            record.event_id,
            record.timestamp,
            record.provider_name,
            record.channel,
            record.level,
            record.computer_name,
        )

    if parser.parse_failures:
        logger.warning("%d record(s) failed to parse.", len(parser.parse_failures))


def _run_folder(folder_path: Path) -> None:
    """Parse and log a summary of every ``.evtx`` file in a folder.

    Args:
        folder_path: Path to a directory containing ``.evtx`` files.
    """
    try:
        results = parse_folder(folder_path)
    except EvtxFileError as exc:
        logger.error("Batch parsing failed: %s", exc)
        raise SystemExit(1) from exc

    if not results:
        logger.warning("No .evtx files were successfully parsed in %s", folder_path)
        return

    total_records = 0
    for file_path, records in results.items():
        total_records += len(records)
        logger.info("%s: %d record(s) extracted", file_path.name, len(records))
        if records:
            first = records[0]
            logger.info(
                "  Sample: #%s | EventID=%s | %s | Provider=%s",
                first.record_number,
                first.event_id,
                first.timestamp,
                first.provider_name,
            )

    logger.info(
        "Batch complete: %d file(s) parsed, %d total record(s).",
        len(results),
        total_records,
    )


def _main() -> None:
    """Run the parser as a script against either a single file or a folder.

    Usage:
        python evtx.py <path-to-file.evtx>
        python evtx.py <path-to-folder>
    """
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) != 2:
        print(f"Usage: python {sys.argv[0]} <path-to-file.evtx-or-folder>")
        raise SystemExit(1)

    target = Path(sys.argv[1])

    if target.is_dir():
        _run_folder(target)
    else:
        _run_single_file(target)


if __name__ == "__main__":
    _main()