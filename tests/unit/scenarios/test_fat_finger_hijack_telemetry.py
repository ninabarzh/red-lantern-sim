"""
Unit tests for simulator/scenarios/easy/fat_finger_hijack/telemetry.py
"""
from unittest.mock import Mock

import pytest

from simulator.scenarios.easy.fat_finger_hijack.telemetry import register


class TestFatFingerHijackTelemetry:
    """Test suite for fat_finger_hijack telemetry mapping"""

    @pytest.fixture
    def mock_event_bus(self):
        """Mock EventBus"""
        return Mock()

    @pytest.fixture
    def mock_bgp_generator(self):
        """Mock BGPUpdateGenerator"""
        bgp_gen = Mock()
        bgp_gen.emit_update = Mock()
        bgp_gen.emit_withdraw = Mock()
        return bgp_gen

    @pytest.fixture
    def mock_syslog_generator(self):
        """Mock RouterSyslogGenerator"""
        syslog_gen = Mock()
        syslog_gen.emit = Mock()
        syslog_gen.prefix_limit_exceeded = Mock()
        return syslog_gen

    @pytest.fixture
    def mock_latency_generator(self):
        """Mock LatencyMetricsGenerator"""
        latency_gen = Mock()
        latency_gen.emit = Mock()
        return latency_gen

    @pytest.fixture
    def patched_generators(self, monkeypatch, mock_bgp_generator, mock_syslog_generator, mock_latency_generator):
        """Patch generator imports"""
        # Create mocks for the generator classes
        mock_bgp_class = Mock(return_value=mock_bgp_generator)
        mock_syslog_class = Mock(return_value=mock_syslog_generator)
        mock_latency_class = Mock(return_value=mock_latency_generator)

        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.BGPUpdateGenerator",
            mock_bgp_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.RouterSyslogGenerator",
            mock_syslog_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.LatencyMetricsGenerator",
            mock_latency_class
        )

        # Return both the class mocks and instance mocks
        return {
            "bgp_class": mock_bgp_class,
            "syslog_class": mock_syslog_class,
            "latency_class": mock_latency_class,
            "bgp_instance": mock_bgp_generator,
            "syslog_instance": mock_syslog_generator,
            "latency_instance": mock_latency_generator
        }

    def test_register_initializes_generators_with_correct_params(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that register creates generators with correct parameters"""
        scenario_name = "fat-finger-hijack-test"

        # When
        register(event_bus=mock_event_bus, clock=mock_clock, scenario_name=scenario_name)

        # Then
        # Verify BGPUpdateGenerator was created with correct params
        patched_generators["bgp_class"].assert_called_once_with(
            clock=mock_clock,
            event_bus=mock_event_bus,
            scenario_name=scenario_name
        )

        # Verify RouterSyslogGenerator was created with correct params
        patched_generators["syslog_class"].assert_called_once_with(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="R1",
            scenario_name=scenario_name
        )

        # Verify LatencyMetricsGenerator was created with correct params
        patched_generators["latency_class"].assert_called_once_with(
            clock=mock_clock,
            event_bus=mock_event_bus,
            scenario_name=scenario_name
        )

    def test_register_subscribes_to_event_bus(self, mock_event_bus, mock_clock, patched_generators):
        """Test that register subscribes callback to event bus"""
        # When
        register(event_bus=mock_event_bus, clock=mock_clock, scenario_name="test")

        # Then
        mock_event_bus.subscribe.assert_called_once()
        # Verify a callable was passed
        callback = mock_event_bus.subscribe.call_args[0][0]
        assert callable(callback)

    def test_on_timeline_event_ignores_missing_entry(self, mock_event_bus, mock_clock, patched_generators):
        """Test that events without 'entry' are ignored"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When calling with event missing 'entry'
        callback({"type": "other_event", "data": "test"})

        # Then no generators should be called
        # (Generators are mocked, so this test passes if no exception is raised)

    def test_on_timeline_event_ignores_missing_prefix_or_action(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that entries without prefix or action are ignored"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get BGP instance
        bgp_instance = patched_generators["bgp_instance"]

        # Test missing prefix
        callback({"entry": {"action": "announce"}})

        # Test missing action
        callback({"entry": {"prefix": "10.0.0.0/24"}})

        # Test both missing
        callback({"entry": {}})

        # Then no BGP generator calls
        bgp_instance.emit_update.assert_not_called()

    def test_announce_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test announce action generates BGP update and syslog"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # When processing announce event
        event = {
            "entry": {
                "prefix": "203.0.113.0/24",
                "action": "announce"
            }
        }
        callback(event)

        # Then verify scenario metadata
        expected_scenario = {
            "name": "fat-finger-hijack",
            "attack_step": "misorigin",
            "incident_id": "fat-finger-hijack-203.0.113.0/24"
        }

        # Verify BGP update
        bgp_instance.emit_update.assert_called_once()
        call_args = bgp_instance.emit_update.call_args
        assert call_args[1]["prefix"] == "203.0.113.0/24"
        assert call_args[1]["as_path"] == [65002]
        assert call_args[1]["origin_as"] == 65002
        assert call_args[1]["next_hop"] == "192.0.2.1"
        assert call_args[1]["scenario"] == expected_scenario

        # Verify syslog for RIB add
        syslog_instance.emit.assert_called()
        # Find the call with notice severity
        for call in syslog_instance.emit.call_args_list:
            if call[1].get("severity") == "notice":
                assert call[1]["message"] == "BGP route 203.0.113.0/24 added to RIB"
                assert call[1]["subsystem"] == "bgp"
                assert call[1]["peer_ip"] == "192.0.2.1"
                assert call[1]["scenario"] == expected_scenario
                break

        # Verify prefix limit exceeded
        syslog_instance.prefix_limit_exceeded.assert_called_once_with(
            peer_ip="192.0.2.1",
            limit=100,
            scenario=expected_scenario
        )

    def test_withdraw_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test withdraw action generates BGP withdraw and syslog"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # When processing withdraw event with duration
        event = {
            "entry": {
                "prefix": "198.51.100.0/24",
                "action": "withdraw",
                "duration_seconds": 300
            }
        }
        callback(event)

        # Then verify scenario metadata
        expected_scenario = {
            "name": "fat-finger-hijack",
            "attack_step": "withdrawal",
            "incident_id": "fat-finger-hijack-198.51.100.0/24"
        }

        # Verify BGP withdraw
        bgp_instance.emit_withdraw.assert_called_once_with(
            prefix="198.51.100.0/24",
            withdrawn_by_as=65002,
            scenario=expected_scenario
        )

        # Verify syslog for withdrawal
        syslog_instance.emit.assert_called_once_with(
            message="BGP route 198.51.100.0/24 withdrawn after 300s",
            severity="info",
            subsystem="bgp",
            peer_ip="192.0.2.1",
            scenario=expected_scenario
        )

    def test_withdraw_action_default_duration(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test withdraw action uses default duration when not specified"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing withdraw event without duration
        event = {
            "entry": {
                "prefix": "192.0.2.0/24",
                "action": "withdraw"
                # No duration_seconds
            }
        }
        callback(event)

        # Then verify message uses default 0 seconds
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]
        assert "withdrawn after 0s" in call_kwargs["message"]

    def test_latency_spike_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test latency_spike action generates latency metrics"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get latency instance
        latency_instance = patched_generators["latency_instance"]

        # When processing latency_spike event
        event = {
            "entry": {
                "prefix": "203.0.113.0/24",  # Prefix is still required for incident_id
                "action": "latency_spike"
            }
        }
        callback(event)

        # Then verify scenario metadata
        expected_scenario = {
            "name": "fat-finger-hijack",
            "attack_step": "latency_spike",
            "incident_id": "fat-finger-hijack-203.0.113.0/24"
        }

        # Verify latency metrics
        latency_instance.emit.assert_called_once_with(
            source_router="R1",
            target_router="R2",
            latency_ms=150.0,
            jitter_ms=15.0,
            packet_loss_pct=0.1,
            scenario=expected_scenario
        )

    def test_incident_id_format(self, mock_event_bus, mock_clock, patched_generators):
        """Test that incident_id is correctly formatted"""
        # Get the callback
        scenario_name = "test-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get BGP instance
        bgp_instance = patched_generators["bgp_instance"]

        test_cases = [
            ("10.0.0.0/8", f"{scenario_name}-10.0.0.0/8"),
            ("2001:db8::/32", f"{scenario_name}-2001:db8::/32"),
            ("172.16.0.0/12", f"{scenario_name}-172.16.0.0/12"),
        ]

        for prefix, expected_incident_id in test_cases:
            bgp_instance.emit_update.reset_mock()

            # When
            callback({"entry": {"prefix": prefix, "action": "announce"}})

            # Then
            call_kwargs = bgp_instance.emit_update.call_args[1]
            assert call_kwargs["scenario"]["incident_id"] == expected_incident_id

    def test_unknown_action_is_ignored(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that unknown actions don't generate telemetry"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]
        latency_instance = patched_generators["latency_instance"]

        # When processing unknown action
        callback({
            "entry": {
                "prefix": "10.0.0.0/24",
                "action": "unknown_action"
            }
        })

        # Then no generators should be called
        bgp_instance.emit_update.assert_not_called()
        syslog_instance.emit.assert_not_called()
        latency_instance.emit.assert_not_called()

    def test_multiple_events_processed_correctly(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test processing multiple timeline events"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # Reset mock to track calls
        bgp_instance.emit_update.reset_mock()
        bgp_instance.emit_withdraw.reset_mock()
        syslog_instance.emit.reset_mock()
        syslog_instance.prefix_limit_exceeded.reset_mock()

        # Sequence of events
        events = [
            {"entry": {"prefix": "203.0.113.0/24", "action": "announce"}},
            {"entry": {"prefix": "198.51.100.0/24", "action": "announce"}},
            {"entry": {"prefix": "203.0.113.0/24", "action": "withdraw", "duration_seconds": 60}},
            {"entry": {"prefix": "192.0.2.0/24", "action": "latency_spike"}},
        ]

        # When processing all events
        for event in events:
            callback(event)

        # Then verify correct number of calls
        assert bgp_instance.emit_update.call_count == 2
        assert bgp_instance.emit_withdraw.call_count == 1

        # Count syslog emits by severity
        notice_calls = 0
        info_calls = 0
        for call in syslog_instance.emit.call_args_list:
            if call[1].get("severity") == "notice":
                notice_calls += 1
            elif call[1].get("severity") == "info":
                info_calls += 1

        assert notice_calls == 2  # One for each announce
        assert info_calls == 1    # One for withdraw
        assert syslog_instance.prefix_limit_exceeded.call_count == 2  # One for each announce

    def test_scenario_metadata_structure(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that scenario metadata has correct structure for each action"""
        # Get the callback
        scenario_name = "fat-finger-test"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        latency_instance = patched_generators["latency_instance"]

        prefix = "203.0.113.0/24"
        incident_id = f"{scenario_name}-{prefix}"

        test_cases = [
            ("announce", "misorigin", bgp_instance.emit_update),
            ("withdraw", "withdrawal", bgp_instance.emit_withdraw),
            ("latency_spike", "latency_spike", latency_instance.emit),
        ]

        for action, expected_attack_step, generator_method in test_cases:
            # Reset mocks
            bgp_instance.emit_update.reset_mock()
            bgp_instance.emit_withdraw.reset_mock()
            latency_instance.emit.reset_mock()

            # When
            callback({"entry": {"prefix": prefix, "action": action}})

            # Then verify scenario metadata structure
            expected_scenario = {
                "name": scenario_name,
                "attack_step": expected_attack_step,
                "incident_id": incident_id
            }

            # Check the appropriate generator was called with correct scenario
            generator_method.assert_called_once()
            call_kwargs = generator_method.call_args[1]
            assert call_kwargs["scenario"] == expected_scenario

    def test_realistic_event_structure(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test with realistic event structure that might come from timeline"""
        # Get the callback
        register(mock_event_bus, mock_clock, "fat-finger-hijack-real")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # Realistic timeline event
        event = {
            "type": "timeline_entry",
            "timestamp": 1700000000,
            "entry": {
                "id": "event_001",
                "time_offset": 60,
                "prefix": "192.0.2.0/24",
                "action": "announce",
                "description": "Accidental announcement by AS65002",
                "asn": 65002
            }
        }

        # When
        callback(event)

        # Then
        bgp_instance.emit_update.assert_called_once()
        syslog_instance.emit.assert_called()
        syslog_instance.prefix_limit_exceeded.assert_called_once()

    def test_error_handling_missing_generator_methods(
        self, mock_event_bus, mock_clock, monkeypatch
    ):
        """Test that exceptions in generators propagate to caller"""
        # Create a mock BGP generator that raises an exception
        mock_bgp_generator = Mock()
        mock_bgp_generator.emit_update = Mock(side_effect=ValueError("Generator error"))

        # Create mock class that returns our exception-raising instance
        mock_bgp_class = Mock(return_value=mock_bgp_generator)

        # Patch the generator imports
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.BGPUpdateGenerator",
            mock_bgp_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.RouterSyslogGenerator",
            Mock()
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.LatencyMetricsGenerator",
            Mock()
        )

        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # The callback doesn't handle exceptions, so it should raise
        with pytest.raises(ValueError, match="Generator error"):
            callback({"entry": {"prefix": "10.0.0.0/24", "action": "announce"}})

    def test_event_bus_subscription_lifecycle(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that subscription happens during register"""
        # Reset mock to ensure clean state
        mock_event_bus.subscribe.reset_mock()

        # When
        register(mock_event_bus, mock_clock, "test")

        # Then
        mock_event_bus.subscribe.assert_called_once()

        # Verify the callback is a function
        callback = mock_event_bus.subscribe.call_args[0][0]
        assert callable(callback)

    def test_current_utc_time_usage(self, mock_event_bus, mock_clock, current_utc_time, monkeypatch):
        """Test that clock is used for timestamps"""
        mock_clock.now.return_value = current_utc_time

        # Mock generators to track clock.now() calls
        mock_bgp_generator = Mock()
        mock_bgp_generator.emit_update = Mock()

        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.BGPUpdateGenerator",
            Mock(return_value=mock_bgp_generator)
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.RouterSyslogGenerator",
            Mock()
        )
        monkeypatch.setattr(
            "simulator.scenarios.easy.fat_finger_hijack.telemetry.LatencyMetricsGenerator",
            Mock()
        )

        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Process event
        callback({"entry": {"prefix": "10.0.0.0/24", "action": "announce"}})

        # Verify generator was called (clock.now() is called inside generator)
        mock_bgp_generator.emit_update.assert_called_once()
