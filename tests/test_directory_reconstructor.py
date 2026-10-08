"""
Unit tests for Component 13 — DirectoryPathReconstructor.

Covers:
  - Root-only tree (MFT #5 alone)
  - Single-level hierarchy (root → child)
  - Multi-level hierarchy (root → dir → file)
  - Missing-parent orphan
  - Stale-sequence-number orphan (ORPHANED_STALE_PARENT)
  - No-$FILE_NAME orphan
  - Cycle detection and breaking
  - Multiple files in same directory (sorted paths)
  - Deleted (is_allocated=False) records included in reconstruction
  - O(1) by_mft lookup on result
  - ReconstructionResult helper methods (iter_orphans, iter_resolved, paths_under)
  - Deterministic ordering (sorted children)
  - Win32 namespace preference over DOS
"""

import unittest
from src.ntfs_recovery.models import (
    FileNameAttribute,
    ParsedMftRecord,
    NS_DOS,
    NS_WIN32,
    NS_WIN32_AND_DOS,
    NS_POSIX,
)
from src.ntfs_recovery.directory_reconstructor import (
    DirectoryPathReconstructor,
    OrphanReason,
    PathNode,
    ReconstructionResult,
    NTFS_ROOT_MFT_NUMBER,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_root() -> ParsedMftRecord:
    """MFT #5 — NTFS root directory, self-referencing parent."""
    return ParsedMftRecord(
        mft_record_number=NTFS_ROOT_MFT_NUMBER,
        sequence_number=1,
        is_directory=True,
        is_allocated=True,
        file_names=[
            FileNameAttribute(
                name=".",
                namespace=NS_WIN32_AND_DOS,
                parent_mft_number=NTFS_ROOT_MFT_NUMBER,
                parent_sequence_number=1,
            )
        ],
    )


def make_directory(
    mft_num: int,
    name: str,
    parent_mft: int,
    parent_seq: int,
    seq: int = 1,
    allocated: bool = True,
) -> ParsedMftRecord:
    return ParsedMftRecord(
        mft_record_number=mft_num,
        sequence_number=seq,
        is_directory=True,
        is_allocated=allocated,
        file_names=[
            FileNameAttribute(
                name=name,
                namespace=NS_WIN32_AND_DOS,
                parent_mft_number=parent_mft,
                parent_sequence_number=parent_seq,
            )
        ],
    )


def make_file(
    mft_num: int,
    name: str,
    parent_mft: int,
    parent_seq: int,
    seq: int = 1,
    allocated: bool = True,
) -> ParsedMftRecord:
    return ParsedMftRecord(
        mft_record_number=mft_num,
        sequence_number=seq,
        is_directory=False,
        is_allocated=allocated,
        file_names=[
            FileNameAttribute(
                name=name,
                namespace=NS_WIN32_AND_DOS,
                parent_mft_number=parent_mft,
                parent_sequence_number=parent_seq,
            )
        ],
    )


def reconstruct(*records: ParsedMftRecord) -> ReconstructionResult:
    return DirectoryPathReconstructor(list(records)).reconstruct()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestRootOnly(unittest.TestCase):
    """Root-only tree: only MFT #5."""

    def setUp(self):
        self.result = reconstruct(make_root())

    def test_total_count(self):
        self.assertEqual(self.result.total_count, 1)

    def test_root_node_exists(self):
        self.assertIsNotNone(self.result.root_node)

    def test_root_path(self):
        self.assertEqual(self.result.root_node.full_path, "/")

    def test_root_depth(self):
        self.assertEqual(self.result.root_node.depth, 0)

    def test_root_not_orphan(self):
        self.assertFalse(self.result.root_node.is_orphan)

    def test_resolved_count(self):
        self.assertEqual(self.result.resolved_count, 1)

    def test_orphan_count(self):
        self.assertEqual(self.result.orphan_count, 0)


class TestSingleLevelHierarchy(unittest.TestCase):
    """Root → single child directory."""

    def setUp(self):
        root = make_root()
        child = make_directory(10, "Users", parent_mft=5, parent_seq=1)
        self.result = reconstruct(root, child)

    def test_child_path(self):
        node = self.result.by_mft[10]
        self.assertEqual(node.full_path, "/Users")

    def test_child_depth(self):
        self.assertEqual(self.result.by_mft[10].depth, 1)

    def test_child_not_orphan(self):
        self.assertFalse(self.result.by_mft[10].is_orphan)

    def test_root_has_one_child(self):
        root = self.result.root_node
        self.assertEqual(len(root.children), 1)

    def test_resolved_count(self):
        self.assertEqual(self.result.resolved_count, 2)


class TestMultiLevelHierarchy(unittest.TestCase):
    """Root → dir → file (3 levels)."""

    def setUp(self):
        root = make_root()
        users = make_directory(10, "Users", parent_mft=5, parent_seq=1)
        alice = make_directory(20, "alice", parent_mft=10, parent_seq=1)
        doc = make_file(30, "report.docx", parent_mft=20, parent_seq=1)
        self.result = reconstruct(root, users, alice, doc)

    def test_deep_file_path(self):
        node = self.result.by_mft[30]
        self.assertEqual(node.full_path, "/Users/alice/report.docx")

    def test_deep_file_depth(self):
        self.assertEqual(self.result.by_mft[30].depth, 3)

    def test_intermediate_dir_path(self):
        self.assertEqual(self.result.by_mft[20].full_path, "/Users/alice")

    def test_all_resolved(self):
        self.assertEqual(self.result.orphan_count, 0)


class TestMissingParentOrphan(unittest.TestCase):
    """File references a parent MFT number that is not in the record set."""

    def setUp(self):
        root = make_root()
        # Parent MFT #99 does not exist in our corpus.
        orphan = make_file(15, "ghost.exe", parent_mft=99, parent_seq=1)
        self.result = reconstruct(root, orphan)

    def test_orphan_reason(self):
        node = self.result.by_mft[15]
        self.assertEqual(node.orphan_reason, OrphanReason.MISSING_PARENT)

    def test_orphan_path_empty(self):
        self.assertEqual(self.result.by_mft[15].full_path, "")

    def test_orphan_depth(self):
        self.assertEqual(self.result.by_mft[15].depth, -1)

    def test_orphan_count(self):
        self.assertEqual(self.result.orphan_count, 1)


class TestStaleParentOrphan(unittest.TestCase):
    """
    File references a parent whose sequence_number has changed —
    stale back-reference; parent directory has been re-used.
    """

    def setUp(self):
        root = make_root()
        # Directory at MFT #10 was deleted and re-allocated; seq=2 now.
        reused_dir = make_directory(10, "Recycled", parent_mft=5, parent_seq=1, seq=2)
        # File still holds old parent_seq=1, which no longer matches seq=2.
        stale_file = make_file(20, "old.txt", parent_mft=10, parent_seq=1)
        self.result = reconstruct(root, reused_dir, stale_file)

    def test_stale_orphan_reason(self):
        node = self.result.by_mft[20]
        self.assertEqual(node.orphan_reason, OrphanReason.STALE_PARENT)

    def test_stale_path_empty(self):
        self.assertEqual(self.result.by_mft[20].full_path, "")

    def test_reused_dir_resolved(self):
        # The reused directory itself is fine — it has a valid parent.
        node = self.result.by_mft[10]
        self.assertFalse(node.is_orphan)
        self.assertEqual(node.full_path, "/Recycled")


class TestNoFilenameOrphan(unittest.TestCase):
    """Record with no $FILE_NAME attributes at all."""

    def setUp(self):
        root = make_root()
        no_fn = ParsedMftRecord(
            mft_record_number=42,
            sequence_number=1,
            is_directory=False,
            is_allocated=True,
            file_names=[],  # empty
        )
        self.result = reconstruct(root, no_fn)

    def test_no_filename_orphan_reason(self):
        node = self.result.by_mft[42]
        self.assertEqual(node.orphan_reason, OrphanReason.NO_FILENAME)

    def test_no_filename_path_empty(self):
        self.assertEqual(self.result.by_mft[42].full_path, "")


class TestCycleDetection(unittest.TestCase):
    """
    A → B → A parent cycle (neither A nor B is MFT #5).
    Both should be labelled CYCLE.
    """

    def setUp(self):
        root = make_root()
        # A points to B as parent; B points to A as parent → cycle.
        rec_a = ParsedMftRecord(
            mft_record_number=100,
            sequence_number=1,
            is_directory=True,
            file_names=[
                FileNameAttribute(
                    name="CycleA",
                    namespace=NS_WIN32_AND_DOS,
                    parent_mft_number=101,
                    parent_sequence_number=1,
                )
            ],
        )
        rec_b = ParsedMftRecord(
            mft_record_number=101,
            sequence_number=1,
            is_directory=True,
            file_names=[
                FileNameAttribute(
                    name="CycleB",
                    namespace=NS_WIN32_AND_DOS,
                    parent_mft_number=100,
                    parent_sequence_number=1,
                )
            ],
        )
        self.result = reconstruct(root, rec_a, rec_b)

    def test_cycle_nodes_orphaned(self):
        for mft_num in (100, 101):
            node = self.result.by_mft[mft_num]
            self.assertEqual(node.orphan_reason, OrphanReason.CYCLE,
                             f"MFT #{mft_num} should be CYCLE orphan")

    def test_cycle_paths_empty(self):
        for mft_num in (100, 101):
            self.assertEqual(self.result.by_mft[mft_num].full_path, "")

    def test_root_not_affected(self):
        self.assertFalse(self.result.root_node.is_orphan)


class TestMultipleFilesInDirectory(unittest.TestCase):
    """Multiple files in the same directory — sorted deterministically."""

    def setUp(self):
        root = make_root()
        docs = make_directory(10, "Documents", parent_mft=5, parent_seq=1)
        f1 = make_file(20, "zebra.txt", parent_mft=10, parent_seq=1)
        f2 = make_file(21, "alpha.txt", parent_mft=10, parent_seq=1)
        f3 = make_file(22, "middle.txt", parent_mft=10, parent_seq=1)
        self.result = reconstruct(root, docs, f1, f2, f3)

    def test_all_paths_correct(self):
        self.assertEqual(self.result.by_mft[20].full_path, "/Documents/zebra.txt")
        self.assertEqual(self.result.by_mft[21].full_path, "/Documents/alpha.txt")
        self.assertEqual(self.result.by_mft[22].full_path, "/Documents/middle.txt")

    def test_children_sorted(self):
        docs_node = self.result.by_mft[10]
        child_names = [c.name for c in docs_node.children]
        self.assertEqual(child_names, sorted(child_names, key=str.lower))


class TestDeletedRecordsIncluded(unittest.TestCase):
    """Deleted (is_allocated=False) records are still path-resolved if parent is valid."""

    def setUp(self):
        root = make_root()
        deleted_file = make_file(
            50, "deleted.db", parent_mft=5, parent_seq=1, allocated=False
        )
        self.result = reconstruct(root, deleted_file)

    def test_deleted_file_path_resolved(self):
        node = self.result.by_mft[50]
        self.assertEqual(node.full_path, "/deleted.db")
        self.assertFalse(node.is_orphan)

    def test_deleted_flag_preserved(self):
        self.assertFalse(self.result.by_mft[50].record.is_allocated)


class TestByMftLookup(unittest.TestCase):
    """O(1) by_mft lookup on result."""

    def setUp(self):
        root = make_root()
        f = make_file(77, "lookup.txt", parent_mft=5, parent_seq=1)
        self.result = reconstruct(root, f)

    def test_lookup_by_mft(self):
        node = self.result.by_mft.get(77)
        self.assertIsNotNone(node)
        self.assertEqual(node.full_path, "/lookup.txt")

    def test_missing_key_returns_none(self):
        self.assertIsNone(self.result.by_mft.get(9999))


class TestResultHelpers(unittest.TestCase):
    """ReconstructionResult helper methods: iter_orphans, iter_resolved, paths_under."""

    def setUp(self):
        root = make_root()
        docs = make_directory(10, "Documents", parent_mft=5, parent_seq=1)
        f1 = make_file(20, "a.txt", parent_mft=10, parent_seq=1)
        orphan = make_file(30, "lost.txt", parent_mft=999, parent_seq=1)
        self.result = reconstruct(root, docs, f1, orphan)

    def test_iter_orphans(self):
        orphans = list(self.result.iter_orphans())
        self.assertEqual(len(orphans), 1)
        self.assertEqual(orphans[0].mft_record_number, 30)

    def test_iter_resolved(self):
        resolved = list(self.result.iter_resolved())
        self.assertEqual(len(resolved), 3)

    def test_paths_under_documents(self):
        under_docs = self.result.paths_under("/Documents")
        paths = {n.full_path for n in under_docs}
        self.assertIn("/Documents", paths)
        self.assertIn("/Documents/a.txt", paths)
        self.assertNotIn("/", paths)

    def test_paths_under_root(self):
        under_root = self.result.paths_under("/")
        # Should include everything except orphans
        self.assertGreaterEqual(len(under_root), 3)


class TestNamespacePreference(unittest.TestCase):
    """Win32 namespace is preferred over DOS when both are present."""

    def setUp(self):
        root = make_root()
        # File has both a DOS short-name and a Win32 long-name.
        f = ParsedMftRecord(
            mft_record_number=40,
            sequence_number=1,
            is_directory=False,
            is_allocated=True,
            file_names=[
                FileNameAttribute(
                    name="LONGFI~1.TXT",
                    namespace=NS_DOS,
                    parent_mft_number=5,
                    parent_sequence_number=1,
                ),
                FileNameAttribute(
                    name="LongFileName.txt",
                    namespace=NS_WIN32,
                    parent_mft_number=5,
                    parent_sequence_number=1,
                ),
            ],
        )
        self.result = reconstruct(root, f)

    def test_win32_name_used(self):
        node = self.result.by_mft[40]
        self.assertEqual(node.full_path, "/LongFileName.txt")


class TestNoRecords(unittest.TestCase):
    """Empty corpus returns an empty result with no crash."""

    def test_empty(self):
        result = reconstruct()
        self.assertEqual(result.total_count, 0)
        self.assertIsNone(result.root_node)
        self.assertEqual(result.orphan_count, 0)
        self.assertEqual(result.resolved_count, 0)


class TestRootMissingFromCorpus(unittest.TestCase):
    """When MFT #5 is absent, all records are orphaned (MISSING_PARENT)."""

    def setUp(self):
        # File points to MFT #5 (root) but root is not in the record set.
        f = make_file(10, "lonely.txt", parent_mft=5, parent_seq=1)
        self.result = reconstruct(f)

    def test_file_is_orphaned(self):
        node = self.result.by_mft[10]
        self.assertTrue(node.is_orphan)
        self.assertEqual(node.orphan_reason, OrphanReason.MISSING_PARENT)

    def test_no_root_node(self):
        self.assertIsNone(self.result.root_node)


if __name__ == "__main__":
    unittest.main()
