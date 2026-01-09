"""Unit tests for ScenarioAdapter."""

from unittest.mock import Mock, patch

import pytest

from simulator.output.adapter import ScenarioAdapter, write_scenario_logs


class TestScenarioAdapterInit:
    """Test ScenarioAdapter initialization."""

    def test_init_creates_adapter_mapping(self):
        """Test that __init__ creates correct adapter mapping."""
        adapter = ScenarioAdapter()

        # Check all expected mappings exist
        expected_mappings = {
            "access.login": "TACACSAdapter",
            "access.logout": "TACACSAdapter",
            "router.syslog": "RouterAdapter",
            "bgp.update": "RouterAdapter",
            "rpki.validation": "RPKIAdapter",
            "cmdb.change": "CMDBAdapter",
        }

        for event_type, adapter_class_name in expected_mappings.items():
            assert event_type in adapter.adapters
            # Check it's an instance of the right class (by class name)
            assert adapter.adapters[event_type].__class__.__name__ == adapter_class_name

    def test_adapters_attribute_is_dict(self):
        """Test that adapters attribute is a dictionary."""
        adapter = ScenarioAdapter()
        assert isinstance(adapter.adapters, dict)


class TestScenarioAdapterTransform:
    """Test transform method."""

    @pytest.fixture
    def adapter(self):
        return ScenarioAdapter()

    def test_transform_with_known_event_type(self, adapter):
        """Test transform with known event type returns adapter output."""
        # Create mock event with known type
        test_event = {
            "event_type": "bgp.update",
            "timestamp": 1700000000,
            "attributes": {"prefix": "203.0.113.0/24"},
        }

        # Mock the RouterAdapter's transform method
        router_adapter = adapter.adapters["bgp.update"]
        original_transform = router_adapter.transform

        try:
            # Replace with mock that returns test output
            router_adapter.transform = Mock(
                return_value=["Router log line 1", "Router log line 2"]
            )

            result = adapter.transform(test_event)

            # Should return the mock adapter's output
            assert result == ["Router log line 1", "Router log line 2"]
            router_adapter.transform.assert_called_once_with(test_event)
        finally:
            # Restore original method
            router_adapter.transform = original_transform

    def test_transform_with_unknown_event_type(self, adapter):
        """Test transform with unknown event type returns empty list."""
        test_event = {
            "event_type": "unknown.event.type",  # Not in adapters dict
            "timestamp": 1700000000,
        }

        result = adapter.transform(test_event)

        assert result == []

    def test_transform_with_missing_event_type(self, adapter):
        """Test transform with missing event_type key returns empty list."""
        test_event = {
            "timestamp": 1700000000,
            "data": "some data",
            # No event_type key
        }

        result = adapter.transform(test_event)

        assert result == []

    def test_transform_returns_list(self, adapter):
        """Test transform always returns a list."""
        # Test with known event type
        test_event = {"event_type": "router.syslog", "timestamp": 1700000000}

        router_adapter = adapter.adapters["router.syslog"]
        original_transform = router_adapter.transform

        try:
            # Mock to return different iterable types
            test_cases = [
                (["line1", "line2"], ["line1", "line2"]),  # list
                (("line1", "line2"), ["line1", "line2"]),  # tuple
                (iter(["line1", "line2"]), ["line1", "line2"]),  # iterator
                ([], []),  # empty list
            ]

            for mock_return, expected in test_cases:
                router_adapter.transform = Mock(return_value=mock_return)
                result = adapter.transform(test_event)
                assert result == expected
                assert isinstance(result, list)
        finally:
            router_adapter.transform = original_transform

    @pytest.mark.parametrize(
        "event_type,expected_adapter",
        [
            ("access.login", "TACACSAdapter"),
            ("access.logout", "TACACSAdapter"),
            ("router.syslog", "RouterAdapter"),
            ("bgp.update", "RouterAdapter"),
            ("rpki.validation", "RPKIAdapter"),
            ("cmdb.change", "CMDBAdapter"),
        ],
    )
    def test_all_event_type_mappings(self, event_type, expected_adapter, adapter):
        """Test all event type mappings use correct adapter."""
        test_event = {"event_type": event_type}

        # Get the adapter for this event type
        event_adapter = adapter.adapters.get(event_type)
        assert event_adapter is not None
        assert event_adapter.__class__.__name__ == expected_adapter

        # Mock the adapter's transform method
        original_transform = event_adapter.transform

        try:
            event_adapter.transform = Mock(return_value=["mocked output"])

            result = adapter.transform(test_event)

            assert result == ["mocked output"]
            event_adapter.transform.assert_called_once_with(test_event)
        finally:
            event_adapter.transform = original_transform


class TestWriteScenarioLogs:
    """Test write_scenario_logs function."""

    @pytest.fixture
    def mock_events(self):
        """Sample events for testing."""
        return [
            {"event_type": "bgp.update", "timestamp": 1000, "data": "event1"},
            {"event_type": "router.syslog", "timestamp": 2000, "data": "event2"},
            {"event_type": "unknown.type", "timestamp": 3000, "data": "event3"},
        ]

    def test_write_scenario_logs_creates_file(self, mock_events, tmp_path):
        """Test that write_scenario_logs creates output file."""
        output_file = tmp_path / "output.log"

        # Mock the adapters to return predictable output
        with patch("simulator.output.adapter.ScenarioAdapter") as MockAdapter:
            mock_adapter = Mock()
            mock_adapter.transform.side_effect = [
                ["BGP log line 1", "BGP log line 2"],  # For event1
                ["Router log line"],  # For event2
                [],  # For event3 (unknown type)
            ]
            MockAdapter.return_value = mock_adapter

            write_scenario_logs(mock_events, str(output_file))

        # Check file was created
        assert output_file.exists()

        # Check file content
        with open(output_file) as f:
            content = f.read().splitlines()

        assert content == [
            "BGP log line 1",
            "BGP log line 2",
            "Router log line",
        ]

    def test_write_scenario_logs_creates_parent_directories(
        self, mock_events, tmp_path
    ):
        """Test that write_scenario_logs creates parent directories."""
        nested_file = tmp_path / "deep" / "nested" / "dir" / "output.log"

        # Mock adapter
        with patch("simulator.output.adapter.ScenarioAdapter") as MockAdapter:
            mock_adapter = Mock()
            mock_adapter.transform.return_value = ["test line"]
            MockAdapter.return_value = mock_adapter

            write_scenario_logs(mock_events[:1], str(nested_file))

        # Check file and parent directories were created
        assert nested_file.exists()
        assert nested_file.parent.exists()

    def test_write_scenario_logs_handles_adapter_exception(
        self, mock_events, tmp_path, capsys
    ):
        """Test that write_scenario_logs handles adapter exceptions gracefully."""
        output_file = tmp_path / "output.log"

        with patch("simulator.output.adapter.ScenarioAdapter") as MockAdapter:
            mock_adapter = Mock()

            # First event works, second raises exception, third works
            def side_effect(event):
                if event["timestamp"] == 1000:
                    return ["line1"]
                elif event["timestamp"] == 2000:
                    raise ValueError("Adapter failed")
                else:
                    return ["line3"]

            mock_adapter.transform.side_effect = side_effect
            MockAdapter.return_value = mock_adapter

            write_scenario_logs(mock_events, str(output_file))

        # Check file content (should have lines 1 and 3)
        with open(output_file) as f:
            content = f.read().splitlines()

        assert content == ["line1", "line3"]

        # Check error was printed to stderr
        captured = capsys.readouterr()
        assert "Warning: failed to transform event" in captured.err
        assert "Adapter failed" in captured.err

    def test_write_scenario_logs_skips_empty_lines(self, mock_events, tmp_path):
        """Test that empty lines from adapter are skipped."""
        output_file = tmp_path / "output.log"

        with patch("simulator.output.adapter.ScenarioAdapter") as MockAdapter:
            mock_adapter = Mock()
            # Adapter returns lines including empty strings
            mock_adapter.transform.return_value = ["line1", "", "line2", ""]
            MockAdapter.return_value = mock_adapter

            write_scenario_logs(mock_events[:1], str(output_file))

        # Check file content (empty lines should be skipped)
        with open(output_file) as f:
            content = f.read().splitlines()

        assert content == ["line1", "line2"]

    def test_write_scenario_logs_handles_empty_events(self, tmp_path):
        """Test write_scenario_logs with empty events list."""
        output_file = tmp_path / "output.log"

        with patch("simulator.output.adapter.ScenarioAdapter") as MockAdapter:
            mock_adapter = Mock()
            MockAdapter.return_value = mock_adapter

            write_scenario_logs([], str(output_file))

        # File should be created but empty
        assert output_file.exists()

        with open(output_file) as f:
            content = f.read()

        assert content == ""
        # Adapter should not be called
        mock_adapter.transform.assert_not_called()


@pytest.mark.parametrize(
    "event,expected_adapter_class",
    [
        ({"event_type": "access.login"}, "TACACSAdapter"),
        ({"event_type": "router.syslog"}, "RouterAdapter"),
        ({"event_type": "rpki.validation"}, "RPKIAdapter"),
        ({"event_type": "cmdb.change"}, "CMDBAdapter"),
    ],
)
def test_adapter_dispatch_parametrized(event, expected_adapter_class):
    """Parametrized test for adapter dispatch."""
    adapter = ScenarioAdapter()

    # Get the actual adapter
    event_adapter = adapter.adapters.get(event["event_type"])
    assert event_adapter is not None
    assert event_adapter.__class__.__name__ == expected_adapter_class
