import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from core.payload_provenance import PayloadProvenance


def test_provenance_init():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "test.db")
        prov = PayloadProvenance(db_path=db)
        stats = prov.get_stats()
        assert stats["total_records"] == 0
        prov.close()


def test_provenance_record():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "test.db")
        prov = PayloadProvenance(db_path=db)
        class FakeRepo:
            commit_hash = "abc123"
            commit_date = None
            release_tag = "v1.0"
            url = "https://github.com/test"
            name = "TestRepo"

        pid = prov.record_file(
            file_info={"path": "RCE/test.txt", "filename": "test.txt", "category": "RCE"},
            payload_hash="deadbeef",
            repo_info=FakeRepo(),
        )
        assert pid is not None
        stats = prov.get_stats()
        assert stats["total_records"] == 1
        prov.close()


def test_provenance_search():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "test.db")
        prov = PayloadProvenance(db_path=db)
        class FakeRepo:
            commit_hash = "abc123"
            commit_date = None
            release_tag = "v1.0"
            url = "https://github.com/test"
            name = "TestRepo"

        prov.record_file(
            file_info={"path": "XSS/test.txt", "filename": "test.txt", "category": "XSS"},
            payload_hash="feed0011",
            repo_info=FakeRepo(),
        )
        results = prov.search("XSS")
        assert len(results) == 1
        assert results[0].category == "XSS"
        prov.close()


def test_provenance_get_by_hash():
    with tempfile.TemporaryDirectory() as tmp:
        db = os.path.join(tmp, "test.db")
        prov = PayloadProvenance(db_path=db)
        class FakeRepo:
            commit_hash = "abc123"
            commit_date = None
            release_tag = "v1.0"
            url = "https://github.com/test"
            name = "TestRepo"

        prov.record_file(
            file_info={"path": "LFI/test.txt", "filename": "test.txt", "category": "LFI"},
            payload_hash="hash1234",
            repo_info=FakeRepo(),
        )
        record = prov.get_by_hash("hash1234")
        assert record is not None
        assert record.payload_hash == "hash1234"
        prov.close()
