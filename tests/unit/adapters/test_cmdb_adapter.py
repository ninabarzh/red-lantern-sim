# tests/unit/adapters/test_cmdb_adapter.py
from datetime import datetime, timezone
import pytest
from simulator.output.cmdb_adapter import CMDBAdapter

@pytest.fixture
def cmdb_adapter():
    return CMDBAdapter()

def _format_ts(ts: int) -> str:
    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.strftime("%b %d %H:%M:%S")

def test_cmdb_change_event_transforms_correctly(cmdb_adapter):
    event = {
        "event_type": "cmdb.change",
        "timestamp": 1700000000,
        "attributes": {
            "actor": "alice",
            "files_changed": ["file1.cfg", "file2.cfg"]
        }
    }
    lines = list(cmdb_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} cmdb-server CMDB change by alice, files: ['file1.cfg', 'file2.cfg']"]

def test_cmdb_change_event_with_default_actor(cmdb_adapter):
    event = {
        "event_type": "cmdb.change",
        "timestamp": 1700000010,
        "attributes": {
            "files_changed": ["file1.cfg"]
        }
    }
    lines = list(cmdb_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} cmdb-server CMDB change by unknown, files: ['file1.cfg']"]

def test_cmdb_change_event_with_no_files(cmdb_adapter):
    event = {
        "event_type": "cmdb.change",
        "timestamp": 1700000020,
        "attributes": {
            "actor": "bob"
        }
    }
    lines = list(cmdb_adapter.transform(event))
    ts_str = _format_ts(event["timestamp"])
    assert lines == [f"{ts_str} cmdb-server CMDB change by bob, files: []"]

def test_irrelevant_event_is_ignored(cmdb_adapter):
    event = {
        "event_type": "router.syslog",  # not cmdb.change
        "timestamp": 1700000030,
        "attributes": {
            "actor": "eve",
            "files_changed": ["fileX.cfg"]
        }
    }
    lines = list(cmdb_adapter.transform(event))
    assert lines == []

def test_empty_event_defaults(cmdb_adapter):
    event = {}
    lines = list(cmdb_adapter.transform(event))
    assert lines == []
