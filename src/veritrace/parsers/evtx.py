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

# pylint: disable=too-many-lines
# This module is intentionally kept as a single, self-contained file
# (exceptions + data models + extraction + orchestration + CLI + HTML
# export) so it can be dropped into a project without pulling in
# sibling modules. Splitting it would improve this metric but work
# against that portability goal.

from __future__ import annotations

import argparse
import html
import logging
import os
from concurrent.futures import ProcessPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_record_xml_view

try:
    from tqdm import tqdm

    _HAS_TQDM = True
except ImportError:  # pragma: no cover - exercised only when tqdm is absent
    _HAS_TQDM = False

    def tqdm(iterable, **_kwargs):  # type: ignore[no-redef]
        """Minimal no-op fallback used when ``tqdm`` is not installed.

        Behaves like ``tqdm`` as a pass-through iterator wrapper (so
        calling code doesn't need conditional logic), but prints no
        progress bar. Install ``tqdm`` (``pip install tqdm``) for
        real progress bars.

        Args:
            iterable: The iterable to pass through unchanged.
            **_kwargs: Accepted for signature compatibility with the
                real ``tqdm`` (e.g. ``total``, ``desc``, ``unit``);
                intentionally unused here.
        """
        return iterable

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
class EventRecord:  # pylint: disable=too-many-instance-attributes
    """A single parsed Windows Event Log record.

    Note:
        Each field below is a distinct, independently meaningful
        forensic attribute of a Windows event record; the field count
        reflects the EVTX schema itself, not incidental class
        complexity, so ``too-many-instance-attributes`` is
        intentionally suppressed for this dataclass.

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


class EventRecordExtractor:  # pylint: disable=too-few-public-methods
    """Extracts :class:`EventRecord` instances from Windows Event XML.

    Note:
        This class exposes a single public entry point (``extract``)
        backed by several private helper methods — a deliberate
        single-responsibility design, not a class that "should" have
        more public surface area, so ``too-few-public-methods`` is
        intentionally suppressed here.

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


class EvtxParser:  # pylint: disable=too-few-public-methods
    """Parses a Windows ``.evtx`` file into a list of :class:`EventRecord` objects.

    Note:
        This class exposes a single public entry point (``parse``)
        backed by several private helper methods — a deliberate
        single-responsibility design, so
        ``too-few-public-methods`` is intentionally suppressed here.

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

    def parse(self, show_progress: bool = False) -> list[EventRecord]:
        """Parse the configured ``.evtx`` file into event records.

        Args:
            show_progress: If ``True``, display a per-record progress
                bar (via ``tqdm``, if installed) while parsing. The
                total shown is an estimate taken from the file
                header's next-record-number field, since EVTX does
                not store an exact record count up front; the actual
                number of records processed may be slightly lower if
                the log has wrapped. Has no effect if ``tqdm`` is not
                installed.

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
                record_iter = evtx_log.records()
                if show_progress:
                    estimated_total = self._estimate_record_count(evtx_log)
                    record_iter = tqdm(
                        record_iter,
                        total=estimated_total,
                        desc=self.file_path.name,
                        unit="rec",
                    )
                for raw_record in record_iter:
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

    @staticmethod
    def _estimate_record_count(evtx_log: Evtx) -> int | None:
        """Estimate the number of records in an open EVTX file.

        Used only to size the progress bar; parsing correctness never
        depends on this estimate.

        Args:
            evtx_log: An open ``Evtx`` context.

        Returns:
            The file header's ``next_record_number`` as an estimated
            upper bound on record count, or ``None`` if it cannot be
            read (in which case ``tqdm`` falls back to an
            unbounded/counting progress display).
        """
        try:
            return int(evtx_log.get_file_header().next_record_number())
        except Exception:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Progress bar sizing is best-effort only; any failure here
            # (e.g. an unusual/corrupt file header) must never abort
            # the actual parse, so we deliberately catch broadly.
            return None

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
        except Exception as exc:  # noqa: BLE001 pylint: disable=broad-exception-caught
            # Deliberately broad: this isolates ANY unexpected failure to a
            # single record so one corrupt/anti-forensically-damaged record
            # cannot abort parsing of the rest of the file. See module
            # docstring / RecordExtractionError for the narrower, expected
            # failure path this complements.
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


def _parse_file_worker(file_path: Path) -> tuple[Path, list[EventRecord], int, str | None]:
    """Parse a single file; designed to run inside a worker process.

    Must be a module-level function (not a method or closure) so it
    can be pickled and sent to worker processes by
    ``ProcessPoolExecutor``.

    Args:
        file_path: Path to the ``.evtx`` file to parse.

    Returns:
        A tuple of ``(file_path, records, failure_count, error)``.
        ``error`` is ``None`` on success, or a message describing why
        the file could not be opened/parsed at all.
    """
    parser = EvtxParser(file_path)
    try:
        records = parser.parse()
    except EvtxFileError as exc:
        return file_path, [], 0, str(exc)
    return file_path, records, len(parser.parse_failures), None


def parse_folder(
    folder_path: str | Path,
    show_progress: bool = False,
    max_workers: int | None = None,
) -> dict[Path, list[EventRecord]]:
    """Parse every ``.evtx`` file found directly inside a folder.

    Files are parsed in parallel across separate processes (EVTX
    parsing is CPU-bound, so this can substantially reduce total
    wall-clock time on multi-core machines when a folder has several
    files). Files that fail to open entirely (see
    :class:`EvtxFileError`) are logged and skipped so that one
    corrupt or inaccessible file does not prevent the rest of the
    folder from being processed. Per-file parse failures (individual
    bad records within an otherwise-readable file) are logged per
    file but not returned in bulk here; call
    :meth:`EvtxParser.parse` directly on a specific file if you need
    that detail.

    Args:
        folder_path: Path to a directory containing ``.evtx`` files.
            Only files directly inside this folder are considered
            (non-recursive).
        show_progress: If ``True``, display a progress bar (via
            ``tqdm``, if installed) tracking how many files have
            completed. Has no effect if ``tqdm`` is not installed.
        max_workers: Maximum number of worker processes to use.
            Defaults to :func:`os.cpu_count` if not specified.

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
    if not evtx_files:
        return results

    worker_count = max_workers if max_workers is not None else os.cpu_count()

    with ProcessPoolExecutor(max_workers=worker_count) as executor:
        futures = {
            executor.submit(_parse_file_worker, evtx_file): evtx_file
            for evtx_file in evtx_files
        }
        completed = as_completed(futures)
        if show_progress:
            completed = tqdm(completed, total=len(futures), desc="Files", unit="file")

        for future in completed:
            file_path, records, failure_count, error = future.result()
            if error is not None:
                logger.error("Skipping file '%s': %s", file_path.name, error)
                continue
            results[file_path] = records
            if failure_count:
                logger.warning(
                    "'%s': %d record(s) failed to parse.", file_path.name, failure_count
                )

    return results


# --------------------------------------------------------------------------
# HTML export
# --------------------------------------------------------------------------

_HTML_DOCUMENT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 1.5rem;
          color: #1a1a1a; background: #fafafa; }}
  h1 {{ font-size: 1.4rem; margin-bottom: 0.2rem; }}
  .subtitle {{ color: #555; margin-bottom: 1rem; font-size: 0.9rem; }}
  .controls {{ margin-bottom: 0.75rem; }}
  input#filterBox {{ padding: 0.4rem 0.6rem; width: 320px; font-size: 0.9rem;
                      border: 1px solid #ccc; border-radius: 4px; }}
  .count {{ color: #555; font-size: 0.85rem; margin-left: 0.75rem; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff;
           box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
  th, td {{ border: 1px solid #e0e0e0; padding: 6px 10px; font-size: 0.85rem;
            text-align: left; vertical-align: top; }}
  th {{ background: #2d2d2d; color: #fff; position: sticky; top: 0; cursor: pointer;
        user-select: none; }}
  th:hover {{ background: #444; }}
  tr:nth-child(even) {{ background: #f6f6f6; }}
  tr:hover {{ background: #eef4ff; }}
  .level-1, .level-2 {{ background: #fdecea !important; }}
  .level-3 {{ background: #fff8e1 !important; }}
  .msg-cell {{ max-width: 420px; white-space: pre-wrap; word-break: break-word; }}
  .failures {{ margin-top: 1.5rem; }}
  .failures summary {{ cursor: pointer; font-weight: 600; color: #a33; }}
  .failures ul {{ font-size: 0.85rem; color: #a33; }}
  .section-title {{ margin-top: 2rem; }}
</style>
</head>
<body>
<h1>{title}</h1>
<div class="subtitle">{subtitle}</div>
<div class="controls">
  <input type="text" id="filterBox" placeholder="Filter rows..." oninput="filterTables()">
</div>
{body}
<script>
  function filterTables() {{
    var query = document.getElementById('filterBox').value.toLowerCase();
    var tables = document.querySelectorAll('table.records');
    tables.forEach(function(table) {{
      var rows = table.querySelectorAll('tbody tr');
      var visible = 0;
      rows.forEach(function(row) {{
        var match = row.textContent.toLowerCase().indexOf(query) !== -1;
        row.style.display = match ? '' : 'none';
        if (match) visible++;
      }});
      var counter = table.parentElement.querySelector('.count');
      if (counter) counter.textContent = visible + ' / ' + rows.length + ' rows shown';
    }});
  }}
  function sortTable(table, columnIndex) {{
    var tbody = table.querySelector('tbody');
    var rows = Array.prototype.slice.call(tbody.querySelectorAll('tr'));
    var ascending = table.getAttribute('data-sort-col') !== String(columnIndex)
                     || table.getAttribute('data-sort-dir') === 'desc';
    rows.sort(function(a, b) {{
      var av = a.children[columnIndex].textContent.trim();
      var bv = b.children[columnIndex].textContent.trim();
      var an = parseFloat(av), bn = parseFloat(bv);
      var cmp = (!isNaN(an) && !isNaN(bn)) ? (an - bn) : av.localeCompare(bv);
      return ascending ? cmp : -cmp;
    }});
    rows.forEach(function(row) {{ tbody.appendChild(row); }});
    table.setAttribute('data-sort-col', String(columnIndex));
    table.setAttribute('data-sort-dir', ascending ? 'asc' : 'desc');
  }}
  document.querySelectorAll('table.records th').forEach(function(th, idx) {{
    th.addEventListener('click', function() {{ sortTable(th.closest('table'), idx); }});
  }});
</script>
</body>
</html>
"""

_HTML_TABLE_COLUMNS = (
    "Record #",
    "Event ID",
    "Timestamp (UTC)",
    "Provider",
    "Computer",
    "Channel",
    "Level",
    "Message",
)


def _record_to_html_row(record: EventRecord) -> str:
    """Render a single :class:`EventRecord` as an HTML table row.

    All field values are HTML-escaped to prevent malformed or
    malicious event content (e.g. a message containing HTML markup)
    from breaking the generated report.

    Args:
        record: The event record to render.

    Returns:
        A ``<tr>...</tr>`` HTML fragment.
    """
    level_class = f' class="level-{record.level}"' if record.level is not None else ""
    cells = (
        record.record_number,
        record.event_id if record.event_id is not None else "",
        record.timestamp.isoformat() if record.timestamp else "",
        record.provider_name or "",
        record.computer_name or "",
        record.channel or "",
        record.level if record.level is not None else "",
        record.message or "",
    )
    tds = "".join(
        f'<td class="msg-cell">{html.escape(str(cell))}</td>'
        if i == len(cells) - 1
        else f"<td>{html.escape(str(cell))}</td>"
        for i, cell in enumerate(cells)
    )
    return f"<tr{level_class}>{tds}</tr>"


def _render_records_table(records: list[EventRecord]) -> str:
    """Render a list of event records as a filterable/sortable HTML table.

    Args:
        records: The event records to render.

    Returns:
        An HTML fragment containing the table and its row count.
    """
    header_cells = "".join(f"<th>{html.escape(col)}</th>" for col in _HTML_TABLE_COLUMNS)
    rows = "".join(_record_to_html_row(record) for record in records)
    return (
        f'<div class="table-block">'
        f'<div class="count">{len(records)} / {len(records)} rows shown</div>'
        f'<table class="records"><thead><tr>{header_cells}</tr></thead>'
        f"<tbody>{rows}</tbody></table></div>"
    )


def _render_failures(parse_failures: list[RecordParseFailure]) -> str:
    """Render a list of parse failures as a collapsible HTML section.

    Args:
        parse_failures: The failures to render.

    Returns:
        An HTML fragment, or an empty string if there are no failures.
    """
    if not parse_failures:
        return ""
    items = "".join(
        f"<li>Record {html.escape(str(f.record_number))}: {html.escape(f.reason)}</li>"
        for f in parse_failures
    )
    return (
        f'<details class="failures"><summary>{len(parse_failures)} record(s) '
        f"failed to parse</summary><ul>{items}</ul></details>"
    )


def export_to_html(
    records: list[EventRecord],
    output_path: str | Path,
    source_label: str | None = None,
    parse_failures: list[RecordParseFailure] | None = None,
) -> Path:
    """Export a list of event records to a self-contained HTML report.

    The report includes a live text filter box and clickable
    column-sort headers (implemented in vanilla JavaScript, no
    external dependencies), so the output file can be opened and
    explored directly in a browser without any server or additional
    tooling.

    Args:
        records: The event records to export.
        output_path: Path to write the ``.html`` file to. Parent
            directories are created if they don't already exist.
        source_label: A human-readable label for the source file,
            shown in the report title/subtitle. Defaults to
            ``"EVTX Report"`` if not provided.
        parse_failures: Optional list of records that failed to
            parse, rendered as a collapsible section for visibility
            into anti-forensic indicators (e.g. corrupted records).

    Returns:
        The :class:`~pathlib.Path` the report was written to.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    title = source_label or "EVTX Report"
    subtitle = f"{len(records)} record(s) extracted"
    body = _render_records_table(records)
    if parse_failures:
        body += _render_failures(parse_failures)

    document = _HTML_DOCUMENT_TEMPLATE.format(
        title=html.escape(title), subtitle=html.escape(subtitle), body=body
    )
    output_path.write_text(document, encoding="utf-8")
    logger.info("Wrote HTML report: %s", output_path)
    return output_path


def export_folder_to_html(
    results: dict[Path, list[EventRecord]], output_path: str | Path
) -> Path:
    """Export folder-level batch parse results to one combined HTML report.

    Each source file gets its own titled, filterable/sortable table
    within a single output document.

    Args:
        results: Mapping of source file path to its extracted
            records, as returned by :func:`parse_folder`.
        output_path: Path to write the combined ``.html`` file to.
            Parent directories are created if they don't already
            exist.

    Returns:
        The :class:`~pathlib.Path` the report was written to.
    """
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    total_records = sum(len(records) for records in results.values())
    sections = []
    for file_path, records in results.items():
        sections.append(
            f'<h2 class="section-title">{html.escape(file_path.name)}</h2>'
            + _render_records_table(records)
        )
    body = "".join(sections)

    document = _HTML_DOCUMENT_TEMPLATE.format(
        title=html.escape("VeriTrace EVTX Batch Report"),
        subtitle=html.escape(
            f"{len(results)} file(s), {total_records} total record(s)"
        ),
        body=body,
    )
    output_path.write_text(document, encoding="utf-8")
    logger.info("Wrote HTML batch report: %s", output_path)
    return output_path


# --------------------------------------------------------------------------
# Command-line entry point
# --------------------------------------------------------------------------


def _run_single_file(file_path: Path, show_progress: bool, html_output: Path | None) -> None:
    """Parse and log the results of a single ``.evtx`` file.

    Args:
        file_path: Path to the ``.evtx`` file to parse.
        show_progress: Whether to display a per-record progress bar.
        html_output: If provided, export results to this HTML file
            path instead of (in addition to) logging each record.
    """
    parser = EvtxParser(file_path)
    try:
        records = parser.parse(show_progress=show_progress)
    except EvtxFileError as exc:
        logger.error("Parsing failed: %s", exc)
        raise SystemExit(1) from exc

    if html_output is not None:
        export_to_html(
            records,
            html_output,
            source_label=file_path.name,
            parse_failures=parser.parse_failures,
        )
    else:
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


def _run_folder(
    folder_path: Path,
    show_progress: bool,
    max_workers: int | None,
    html_output: Path | None,
) -> None:
    """Parse and log a summary of every ``.evtx`` file in a folder.

    Args:
        folder_path: Path to a directory containing ``.evtx`` files.
        show_progress: Whether to display a per-file progress bar.
        max_workers: Maximum number of worker processes to use for
            parallel parsing. ``None`` uses :func:`os.cpu_count`.
        html_output: If provided, export combined results to this
            HTML file path instead of (in addition to) logging a
            per-file summary.
    """
    try:
        results = parse_folder(
            folder_path, show_progress=show_progress, max_workers=max_workers
        )
    except EvtxFileError as exc:
        logger.error("Batch parsing failed: %s", exc)
        raise SystemExit(1) from exc

    if not results:
        logger.warning("No .evtx files were successfully parsed in %s", folder_path)
        return

    if html_output is not None:
        export_folder_to_html(results, html_output)
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
        python evtx.py <path-to-file.evtx-or-folder> [options]

    Options:
        --progress          Show a progress bar while parsing
                             (requires ``pip install tqdm`` for a
                             real bar; otherwise silently ignored).
        --html PATH          Export results to an HTML report at
                             PATH instead of logging each record.
        --workers N          Max parallel worker processes to use
                             when parsing a folder (default: all
                             available CPU cores).
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="evtx.py",
        description="Parse a Windows .evtx file or a folder of .evtx files.",
    )
    parser.add_argument("target", help="Path to a .evtx file or a folder of .evtx files.")
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Show a progress bar while parsing (requires tqdm).",
    )
    parser.add_argument(
        "--html",
        metavar="PATH",
        default=None,
        help="Export results to an HTML report at PATH.",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=None,
        metavar="N",
        help="Max parallel worker processes when parsing a folder (default: all cores).",
    )
    args = parser.parse_args()

    if args.progress and not _HAS_TQDM:
        logger.warning("tqdm is not installed; --progress will have no visible effect. "
                        "Install it with: pip install tqdm")

    target = Path(args.target)
    html_output = Path(args.html) if args.html else None

    if target.is_dir():
        _run_folder(target, args.progress, args.workers, html_output)
    else:
        _run_single_file(target, args.progress, html_output)


if __name__ == "__main__":
    _main()