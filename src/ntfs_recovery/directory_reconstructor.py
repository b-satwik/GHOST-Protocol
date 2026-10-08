"""
NTFS Recovery — Component 13: Directory & Full-Path Reconstruction.

Builds an in-memory parent-child relationship graph from existing
``$FILE_NAME`` attributes and reconstructs deterministic full filesystem
paths for every parsed MFT record.

Design constraints (per specification):
  - NTFS root directory is MFT record #5.
  - Parent validation: ``parent_node.sequence_number`` MUST equal
    ``child.parent_sequence_number``.  Mismatches are labelled
    ``ORPHANED_STALE_PARENT``.
  - Files with no resolvable ``$FILE_NAME`` are labelled ``NO_FILENAME``.
  - Cycles are detected and broken; cycle members are labelled
    ``ORPHANED_CYCLE``.
  - Deleted (``is_allocated=False``) records are included so that
    the caller can reconstruct paths for carving candidates.
  - This component does NOT perform file recovery, carving, $UsnJrnl
    parsing, $LogFile parsing, timeline reconstruction, or GUI changes.
  - Zero external dependencies beyond the Python standard library.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Iterator, List, Optional, Set

from .models import FileNameAttribute, ParsedMftRecord

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

NTFS_ROOT_MFT_NUMBER: int = 5
"""MFT record number of the NTFS root directory ('.')."""

_PATH_SEPARATOR: str = "/"
"""Canonical path separator used in reconstructed paths."""


# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class OrphanReason(str, Enum):
    """Reason why a record could not be attached to the directory tree."""

    NONE = "NONE"
    """Record is properly resolved — no orphan condition."""

    NO_FILENAME = "NO_FILENAME"
    """The MFT record has no $FILE_NAME attributes at all."""

    MISSING_PARENT = "MISSING_PARENT"
    """The parent MFT record number is not present in the record set."""

    STALE_PARENT = "STALE_PARENT"
    """
    The parent MFT record exists but its sequence_number does not match
    the child's ``parent_sequence_number``  (stale back-reference).
    """

    CYCLE = "CYCLE"
    """This record is part of a parent-chain cycle (loop) in the graph."""


@dataclass
class PathNode:
    """
    Resolved path information for a single MFT record.

    Produced by :class:`DirectoryPathReconstructor` for every record in the
    input corpus.
    """

    record: ParsedMftRecord
    """The original parsed MFT record."""

    full_path: str = ""
    """
    Reconstructed full path, e.g. ``/Users/alice/Documents/report.docx``.
    Empty string when the path could not be resolved (see ``orphan_reason``).
    """

    orphan_reason: OrphanReason = OrphanReason.NONE
    """Why this record is orphaned, or :attr:`OrphanReason.NONE` if resolved."""

    depth: int = 0
    """
    Depth in the directory tree, where the root (MFT #5) has depth 0.
    Orphaned records have depth -1.
    """

    parent_mft_number: Optional[int] = None
    """MFT record number of the direct parent, or None for root / orphans."""

    children: List["PathNode"] = field(default_factory=list)
    """Direct children attached to this node (populated during graph build)."""

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    @property
    def mft_record_number(self) -> int:
        return self.record.mft_record_number

    @property
    def is_orphan(self) -> bool:
        return self.orphan_reason is not OrphanReason.NONE

    @property
    def is_directory(self) -> bool:
        return self.record.is_directory

    @property
    def name(self) -> str:
        """Best file/directory name, or empty string if unavailable."""
        fn = self.record.best_file_name()
        return fn.name if fn else ""

    def __repr__(self) -> str:
        return (
            f"PathNode(mft={self.mft_record_number}, "
            f"path={self.full_path!r}, "
            f"orphan={self.orphan_reason.value})"
        )


@dataclass
class ReconstructionResult:
    """
    Complete output of :meth:`DirectoryPathReconstructor.reconstruct`.

    Callers iterate :attr:`nodes` or use :attr:`by_mft` for O(1) lookup.
    """

    nodes: List[PathNode] = field(default_factory=list)
    """All path nodes, one per input MFT record, in MFT-number order."""

    by_mft: Dict[int, PathNode] = field(default_factory=dict)
    """Index mapping MFT record number → PathNode for O(1) lookup."""

    root_node: Optional[PathNode] = None
    """PathNode for MFT record #5 (NTFS root directory)."""

    orphan_count: int = 0
    """Total number of orphaned records (any :class:`OrphanReason` ≠ NONE)."""

    resolved_count: int = 0
    """Total number of successfully resolved records."""

    total_count: int = 0
    """Total number of input records processed."""

    # ------------------------------------------------------------------
    # Iteration helpers
    # ------------------------------------------------------------------

    def iter_orphans(self) -> Iterator[PathNode]:
        """Yields all orphaned PathNodes."""
        return (n for n in self.nodes if n.is_orphan)

    def iter_resolved(self) -> Iterator[PathNode]:
        """Yields all successfully resolved PathNodes."""
        return (n for n in self.nodes if not n.is_orphan)

    def iter_directories(self) -> Iterator[PathNode]:
        """Yields all resolved directory nodes (excludes orphans)."""
        return (n for n in self.nodes if n.is_directory and not n.is_orphan)

    def paths_under(self, directory_path: str) -> List[PathNode]:
        """
        Returns all nodes whose full path starts with ``directory_path``.

        The match is performed on the canonical reconstructed path,
        so ``/Users`` matches ``/Users/alice`` but not ``/Users2/bob``.
        """
        prefix = directory_path.rstrip(_PATH_SEPARATOR) + _PATH_SEPARATOR
        root_match = directory_path.rstrip(_PATH_SEPARATOR)
        return [
            n
            for n in self.nodes
            if not n.is_orphan
            and (
                n.full_path == root_match
                or n.full_path.startswith(prefix)
            )
        ]


# ---------------------------------------------------------------------------
# Core reconstructor
# ---------------------------------------------------------------------------


class DirectoryPathReconstructor:
    """
    Builds a parent-child directory graph from ``ParsedMftRecord`` objects
    and reconstructs full filesystem paths.

    Usage::

        records: List[ParsedMftRecord] = ...  # from Components 1-12
        reconstructor = DirectoryPathReconstructor(records)
        result: ReconstructionResult = reconstructor.reconstruct()

    The reconstructor is **read-only** with respect to its input; it does not
    modify any ``ParsedMftRecord`` or ``FileNameAttribute`` objects.

    Reconstruction algorithm
    ------------------------
    1. Index all records by MFT record number.
    2. Create a :class:`PathNode` for every record.
    3. For each node, select the **best** ``$FILE_NAME`` attribute (namespace
       preference: Win32&DOS > Win32 > POSIX > DOS).
    4. Validate the parent reference:
       - Parent must exist in the index.
       - ``parent_node.sequence_number`` must equal
         ``fn.parent_sequence_number`` (stale-parent guard).
    5. Wire child→parent edges and build the parent's ``children`` list.
    6. Detect cycles using a DFS visited-set before path expansion.
    7. Expand full paths top-down from the root (MFT #5).
    8. Assign ``OrphanReason`` for all unresolved nodes.
    """

    def __init__(self, records: List[ParsedMftRecord]) -> None:
        """
        Parameters
        ----------
        records:
            Iterable of fully parsed MFT records produced by Components 1-12.
            Ordering is irrelevant; the reconstructor indexes by MFT number.
        """
        self._records = list(records)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reconstruct(self) -> ReconstructionResult:
        """
        Performs the full directory-tree reconstruction.

        Returns a :class:`ReconstructionResult` containing every input record
        as a :class:`PathNode`, the directory tree rooted at MFT #5, and
        per-record orphan diagnostics.
        """
        # Step 1: Index records by MFT number.
        record_index: Dict[int, ParsedMftRecord] = {
            r.mft_record_number: r for r in self._records
        }

        # Step 2: Create PathNodes.
        node_index: Dict[int, PathNode] = {
            mft_num: PathNode(record=rec)
            for mft_num, rec in record_index.items()
        }

        # Step 3-5: Wire parent-child edges.
        _parent_of: Dict[int, Optional[int]] = {}  # child_mft → parent_mft

        for mft_num, node in node_index.items():
            rec = node.record
            fn = rec.best_file_name()

            if fn is None:
                node.orphan_reason = OrphanReason.NO_FILENAME
                _parent_of[mft_num] = None
                continue

            parent_mft = fn.parent_mft_number

            # Root directory is its own parent in NTFS; treat it as the tree root.
            if mft_num == NTFS_ROOT_MFT_NUMBER:
                _parent_of[mft_num] = None
                node.parent_mft_number = None
                continue

            parent_node = node_index.get(parent_mft)
            if parent_node is None:
                node.orphan_reason = OrphanReason.MISSING_PARENT
                _parent_of[mft_num] = None
                continue

            # Sequence-number guard (stale-parent detection).
            if parent_node.record.sequence_number != fn.parent_sequence_number:
                node.orphan_reason = OrphanReason.STALE_PARENT
                _parent_of[mft_num] = None
                continue

            # Valid parent — wire the edge.
            _parent_of[mft_num] = parent_mft
            node.parent_mft_number = parent_mft
            parent_node.children.append(node)

        # Step 6: Cycle detection via DFS.
        self._mark_cycles(node_index, _parent_of)

        # Step 7: Expand full paths top-down from root.
        root_node = node_index.get(NTFS_ROOT_MFT_NUMBER)
        if root_node is not None:
            self._expand_paths(root_node, parent_path="", depth=0)

        # Step 8: Assign depth=-1 and empty full_path for all remaining orphans.
        for node in node_index.values():
            if node.is_orphan:
                node.full_path = ""
                node.depth = -1

        # Assemble result.
        ordered_nodes = [
            node_index[n] for n in sorted(node_index.keys())
        ]
        orphan_count = sum(1 for n in ordered_nodes if n.is_orphan)
        resolved_count = len(ordered_nodes) - orphan_count

        return ReconstructionResult(
            nodes=ordered_nodes,
            by_mft=node_index,
            root_node=root_node,
            orphan_count=orphan_count,
            resolved_count=resolved_count,
            total_count=len(ordered_nodes),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _mark_cycles(
        self,
        node_index: Dict[int, PathNode],
        parent_of: Dict[int, Optional[int]],
    ) -> None:
        """
        Detects cycles in the parent-chain graph using a DFS walk from each
        unvisited node.  Any node that forms or is part of a cycle is marked
        ``OrphanReason.CYCLE``.

        A cycle exists when following parent pointers eventually revisits a
        node already on the current ancestor path (not just any visited node,
        to distinguish revisiting a resolved ancestor from an actual cycle).
        """
        visited: Set[int] = set()

        for start_mft in list(node_index.keys()):
            if start_mft in visited:
                continue

            # Walk the ancestor chain, collecting the path taken this run.
            path_set: Set[int] = set()
            path_list: List[int] = []
            current = start_mft

            while current is not None and current not in visited:
                if current in path_set:
                    # Found a cycle — mark all members in the cycle portion.
                    cycle_start_idx = path_list.index(current)
                    for cycle_member in path_list[cycle_start_idx:]:
                        cycle_node = node_index[cycle_member]
                        # Only override if not already orphaned for another reason.
                        if not cycle_node.is_orphan:
                            cycle_node.orphan_reason = OrphanReason.CYCLE
                            cycle_node.parent_mft_number = None
                            # Remove from parent's children list to break the edge.
                            for other in node_index.values():
                                if cycle_node in other.children:
                                    other.children.remove(cycle_node)
                    break

                path_set.add(current)
                path_list.append(current)
                current = parent_of.get(current)

            # Mark everything on this chain as visited.
            visited.update(path_list)

    def _expand_paths(
        self,
        node: PathNode,
        parent_path: str,
        depth: int,
    ) -> None:
        """
        Recursively expands full paths top-down from the tree root.

        The root node itself gets path ``"/"``; all children receive
        ``"/<root_name>/<child_name>/..."`` paths.

        Parameters
        ----------
        node:
            The current node being expanded.
        parent_path:
            The already-resolved path of *node's parent*, or empty string
            when expanding the root.
        depth:
            Current depth in the tree (root = 0).
        """
        # Build this node's path.
        if depth == 0:
            # NTFS root: MFT #5 is always "/"
            node.full_path = _PATH_SEPARATOR
        else:
            node_name = node.name or f"[mft_{node.mft_record_number}]"
            if parent_path == _PATH_SEPARATOR:
                node.full_path = _PATH_SEPARATOR + node_name
            else:
                node.full_path = parent_path + _PATH_SEPARATOR + node_name

        node.depth = depth

        # Recurse into children sorted by name for deterministic output.
        for child in sorted(node.children, key=lambda c: (c.name or "").lower()):
            if not child.is_orphan:
                self._expand_paths(child, node.full_path, depth + 1)
