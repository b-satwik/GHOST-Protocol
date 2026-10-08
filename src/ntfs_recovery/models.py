"""
NTFS Recovery — Shared Parsed-Record and Attribute Data Models.

These are the canonical in-memory representations produced by the earlier
Components (1-12).  Component 13 (DirectoryPathReconstructor) consumes them
without re-parsing binary NTFS structures.

Data model contracts:
  - ``ParsedMftRecord.mft_record_number``  – 0-based MFT entry index.
  - ``ParsedMftRecord.sequence_number``    – 16-bit wrap-around MFT sequence counter.
  - ``ParsedMftRecord.is_directory``       – True when the record represents a directory.
  - ``ParsedMftRecord.is_allocated``       – False for deleted / unallocated records.
  - ``ParsedMftRecord.file_names``         – List[FileNameAttribute] (may be empty).
  - ``FileNameAttribute.parent_reference`` – (parent_mft_number, parent_sequence_number).
  - ``FileNameAttribute.name``             – Unicode file/directory name (no path separator).
  - ``FileNameAttribute.namespace``        – 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---------------------------------------------------------------------------
# $FILE_NAME namespace constants
# ---------------------------------------------------------------------------

NS_POSIX: int = 0
NS_WIN32: int = 1
NS_DOS: int = 2
NS_WIN32_AND_DOS: int = 3


@dataclass
class FileNameAttribute:
    """
    In-memory representation of a decoded NTFS $FILE_NAME attribute (0x30).

    ``parent_reference`` stores the (mft_number, sequence_number) pair extracted
    from the MFT_SEGMENT_REFERENCE embedded in the $FILE_NAME structure.
    ``sequence_number`` here is the *parent's* sequence number at the time this
    attribute was written — used for stale-parent detection in Component 13.
    """

    name: str
    """Unicode name of this file or directory (no path separators)."""

    namespace: int = NS_WIN32_AND_DOS
    """$FILE_NAME namespace: 0=POSIX, 1=Win32, 2=DOS, 3=Win32&DOS."""

    parent_mft_number: int = 0
    """MFT record number of the parent directory."""

    parent_sequence_number: int = 0
    """Sequence number of the parent directory *at the time this attribute was written*."""

    # Convenience accessor -------------------------------------------------
    @property
    def parent_reference(self) -> Tuple[int, int]:
        """(parent_mft_number, parent_sequence_number)."""
        return (self.parent_mft_number, self.parent_sequence_number)


@dataclass
class ParsedMftRecord:
    """
    Fully parsed NTFS MFT entry as produced by Components 1-12.

    Only the fields consumed by Component 13 are declared here;
    additional fields (e.g., $DATA run-lists, $ATTRIBUTE_LIST details)
    are carried by the same record object transparently.
    """

    mft_record_number: int
    """0-based index of this MFT entry (= byte_offset / record_size)."""

    sequence_number: int = 0
    """
    MFT entry sequence number.  Incremented each time the record is de-allocated;
    used to detect stale parent back-references.
    """

    is_directory: bool = False
    """True when the MFT entry has the FILE_ATTRIBUTE_DIRECTORY flag set."""

    is_allocated: bool = True
    """
    False for deleted / unallocated entries (the 'in-use' flag in the MFT record
    header is cleared).
    """

    file_names: List[FileNameAttribute] = field(default_factory=list)
    """
    All $FILE_NAME attributes decoded from this record (including those resolved
    from extension MFT entries via Component 12).  Typically one or two
    (Win32 + DOS) for a given file.
    """

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def best_file_name(self) -> Optional[FileNameAttribute]:
        """
        Returns the most descriptive $FILE_NAME attribute using namespace
        preference order: Win32&DOS (3) > Win32 (1) > POSIX (0) > DOS (2).
        Returns None if ``file_names`` is empty.
        """
        if not self.file_names:
            return None
        preference = {NS_WIN32_AND_DOS: 0, NS_WIN32: 1, NS_POSIX: 2, NS_DOS: 3}
        return min(
            self.file_names,
            key=lambda fn: preference.get(fn.namespace, 99),
        )
