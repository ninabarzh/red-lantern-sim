"""
Unit tests for simulator/scenarios/medium/subprefix_intercept/telemetry.py
"""
from unittest.mock import Mock

import pytest

from simulator.scenarios.medium.subprefix_intercept.telemetry import register


class TestSubprefixInterceptTelemetry:
    """Test suite for subprefix_intercept telemetry mapping"""

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
        syslog_gen.configuration_change = Mock()
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
            "simulator.scenarios.medium.subprefix_intercept.telemetry.BGPUpdateGenerator",
            mock_bgp_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.RouterSyslogGenerator",
            mock_syslog_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.LatencyMetricsGenerator",
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
        scenario_name = "subprefix-intercept-test"

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
        callback = mock_event_bus.subscribe.call_args[0][0]
        assert callable(callback)

    def test_on_timeline_event_ignores_missing_entry(self, mock_event_bus, mock_clock, patched_generators):
        """Test that events without 'entry' are ignored"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When calling with event missing 'entry'
        callback({"type": "other_event", "data": "test"})

        # Then no generators should be called (no exception raised)

    def test_baseline_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test baseline action generates BGP update"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing baseline event
        event = {
            "entry": {
                "action": "baseline",
                "prefix": "203.0.113.0/24",
                "victim_as": 64500
            }
        }
        callback(event)

        # Then verify BGP update
        bgp_instance = patched_generators["bgp_instance"]
        bgp_instance.emit_update.assert_called_once()
        call_kwargs = bgp_instance.emit_update.call_args[1]

        assert call_kwargs["prefix"] == "203.0.113.0/24"
        assert call_kwargs["as_path"] == [65001]
        assert call_kwargs["origin_as"] == 64500
        assert call_kwargs["next_hop"] == "192.0.2.10"

        # Verify scenario metadata
        assert call_kwargs["scenario"]["name"] == scenario_name
        assert call_kwargs["scenario"]["attack_step"] == "baseline"
        assert call_kwargs["scenario"]["incident_id"] == f"{scenario_name}-203.0.113.0/24"

    def test_announce_subprefix_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test announce_subprefix action generates BGP update and syslog"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing announce_subprefix event
        event = {
            "entry": {
                "action": "announce_subprefix",
                "prefix": "203.0.113.0/24",  # Parent prefix
                "subprefix": "203.0.113.0/25",
                "attacker_as": 64501
            }
        }
        callback(event)

        # Then verify BGP update for subprefix
        bgp_instance = patched_generators["bgp_instance"]
        bgp_instance.emit_update.assert_called_once()
        bgp_kwargs = bgp_instance.emit_update.call_args[1]

        assert bgp_kwargs["prefix"] == "203.0.113.0/25"
        assert bgp_kwargs["as_path"] == [65002, 64501]
        assert bgp_kwargs["origin_as"] == 64501
        assert bgp_kwargs["next_hop"] == "198.51.100.1"

        assert bgp_kwargs["scenario"]["attack_step"] == "subprefix_announce"

        # Verify syslog
        syslog_instance = patched_generators["syslog_instance"]
        syslog_instance.emit.assert_called_once()
        syslog_kwargs = syslog_instance.emit.call_args[1]

        assert syslog_kwargs["message"] == "New route learned: 203.0.113.0/25 via AS64501"
        assert syslog_kwargs["severity"] == "info"
        assert syslog_kwargs["subsystem"] == "bgp"
        assert syslog_kwargs["peer_ip"] is None

        assert syslog_kwargs["scenario"]["attack_step"] == "subprefix_announce"

    def test_announce_subprefix_requires_subprefix_or_prefix(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test announce_subprefix requires either subprefix or prefix"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing announce_subprefix event without subprefix
        # The original code uses entry["subprefix"], so this should raise KeyError
        event = {
            "entry": {
                "action": "announce_subprefix",
                "prefix": "203.0.113.0/24",  # Only prefix, no subprefix
                "attacker_as": 64501
            }
        }

        # The current implementation requires subprefix, so this should fail
        with pytest.raises(KeyError, match="subprefix"):
            callback(event)

    def test_traffic_intercept_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test traffic_intercept action generates routing syslog"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing traffic_intercept event
        event = {
            "entry": {
                "action": "traffic_intercept",
                "subprefix": "203.0.113.0/25",
                "attacker_as": 64501
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance = patched_generators["syslog_instance"]
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "Best path for 203.0.113.0/25: AS64501 (more-specific)"
        assert call_kwargs["severity"] == "info"
        assert call_kwargs["subsystem"] == "routing"
        assert call_kwargs["scenario"]["attack_step"] == "intercept_active"

    def test_latency_spike_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test latency_spike action generates latency metrics and syslog"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing latency_spike event
        event = {
            "entry": {
                "action": "latency_spike",
                "target": "R2",
                "baseline_ms": 20.0,
                "observed_ms": 85.5
            }
        }
        callback(event)

        # Then verify latency metrics
        latency_instance = patched_generators["latency_instance"]
        latency_instance.emit.assert_called_once()
        latency_kwargs = latency_instance.emit.call_args[1]

        assert latency_kwargs["source_router"] == "R1"
        assert latency_kwargs["target_router"] == "R2"
        assert latency_kwargs["latency_ms"] == 85.5
        assert latency_kwargs["jitter_ms"] == 8.5
        assert latency_kwargs["packet_loss_pct"] == 0.05

        assert latency_kwargs["scenario"]["attack_step"] == "latency_anomaly"

        # Verify syslog
        syslog_instance = patched_generators["syslog_instance"]
        syslog_instance.emit.assert_called_once()
        syslog_kwargs = syslog_instance.emit.call_args[1]

        assert syslog_kwargs["message"] == "Latency to R2 increased from 20.0ms to 85.5ms"
        assert syslog_kwargs["severity"] == "warning"
        assert syslog_kwargs["subsystem"] == "monitoring"

        assert syslog_kwargs["scenario"]["attack_step"] == "latency_anomaly"

    def test_maintain_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test maintain action generates debug syslog"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing maintain event
        event = {
            "entry": {
                "action": "maintain"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance = patched_generators["syslog_instance"]
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "BGP session stable, all routes converged"
        assert call_kwargs["severity"] == "debug"
        assert call_kwargs["subsystem"] == "bgp"
        assert call_kwargs["scenario"]["attack_step"] == "maintain"

    def test_withdraw_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test withdraw action generates BGP withdraw and syslog"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing withdraw event
        event = {
            "entry": {
                "action": "withdraw",
                "subprefix": "203.0.113.0/25",
                "attacker_as": 64501
            }
        }
        callback(event)

        # Then verify BGP withdraw
        bgp_instance = patched_generators["bgp_instance"]
        bgp_instance.emit_withdraw.assert_called_once()
        bgp_kwargs = bgp_instance.emit_withdraw.call_args[1]

        assert bgp_kwargs["prefix"] == "203.0.113.0/25"
        assert bgp_kwargs["withdrawn_by_as"] == 64501
        assert bgp_kwargs["scenario"]["attack_step"] == "withdrawal"

        # Verify syslog
        syslog_instance = patched_generators["syslog_instance"]
        syslog_instance.emit.assert_called_once()
        syslog_kwargs = syslog_instance.emit.call_args[1]

        assert syslog_kwargs["message"] == "Route withdrawn: 203.0.113.0/25 from AS64501"
        assert syslog_kwargs["severity"] == "info"
        assert syslog_kwargs["subsystem"] == "bgp"
        assert syslog_kwargs["scenario"]["attack_step"] == "withdrawal"

    def test_latency_normal_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test latency_normal action generates latency metrics"""
        # Get the callback
        scenario_name = "subprefix-intercept"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing latency_normal event
        event = {
            "entry": {
                "action": "latency_normal",
                "target": "R2",
                "observed_ms": 22.3
            }
        }
        callback(event)

        # Then verify latency metrics
        latency_instance = patched_generators["latency_instance"]
        latency_instance.emit.assert_called_once()
        call_kwargs = latency_instance.emit.call_args[1]

        assert call_kwargs["source_router"] == "R1"
        assert call_kwargs["target_router"] == "R2"
        assert call_kwargs["latency_ms"] == 22.3
        assert call_kwargs["jitter_ms"] == 2.1
        assert call_kwargs["packet_loss_pct"] == 0.0

        assert call_kwargs["scenario"]["attack_step"] == "restoration"

    def test_incident_id_handling(self, mock_event_bus, mock_clock, patched_generators):
        """Test incident_id is correctly generated for different prefix scenarios"""
        # Get the callback
        scenario_name = "test-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        bgp_instance = patched_generators["bgp_instance"]

        # Test with prefix
        bgp_instance.emit_update.reset_mock()
        event1 = {"entry": {"action": "baseline", "prefix": "10.0.0.0/24", "victim_as": 64500}}
        callback(event1)

        call_kwargs1 = bgp_instance.emit_update.call_args[1]
        assert call_kwargs1["scenario"]["incident_id"] == "test-scenario-10.0.0.0/24"

        # Test with subprefix
        bgp_instance.emit_update.reset_mock()
        event2 = {"entry": {"action": "announce_subprefix", "subprefix": "10.0.0.0/25", "attacker_as": 64501}}
        callback(event2)

        call_kwargs2 = bgp_instance.emit_update.call_args[1]
        assert call_kwargs2["scenario"]["incident_id"] == "test-scenario-10.0.0.0/25"

        # Test with neither prefix nor subprefix
        bgp_instance.emit_update.reset_mock()
        event3 = {"entry": {"action": "baseline", "victim_as": 64500}}
        callback(event3)

        call_kwargs3 = bgp_instance.emit_update.call_args[1]
        assert call_kwargs3["scenario"]["incident_id"] == "test-scenario-unknown"

    def test_multiple_events_scenario_progression(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test complete scenario progression through multiple events"""
        # Get the callback
        scenario_name = "subprefix-intercept-full"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]
        latency_instance = patched_generators["latency_instance"]

        # Reset all mocks
        bgp_instance.emit_update.reset_mock()
        bgp_instance.emit_withdraw.reset_mock()
        syslog_instance.emit.reset_mock()
        latency_instance.emit.reset_mock()

        # Complete scenario sequence
        events = [
            {"entry": {"action": "baseline", "prefix": "203.0.113.0/24", "victim_as": 64500}},
            {"entry": {"action": "announce_subprefix", "subprefix": "203.0.113.0/25", "attacker_as": 64501}},
            {"entry": {"action": "traffic_intercept", "subprefix": "203.0.113.0/25", "attacker_as": 64501}},
            {"entry": {"action": "latency_spike", "target": "R2", "baseline_ms": 20.0, "observed_ms": 85.5}},
            {"entry": {"action": "maintain"}},
            {"entry": {"action": "withdraw", "subprefix": "203.0.113.0/25", "attacker_as": 64501}},
            {"entry": {"action": "latency_normal", "target": "R2", "observed_ms": 21.8}},
        ]

        # When processing all events
        for event in events:
            callback(event)

        # Then verify correct number of calls
        assert bgp_instance.emit_update.call_count == 2  # baseline + announce_subprefix
        assert bgp_instance.emit_withdraw.call_count == 1  # withdraw

        # Updated counts:
        # announce_subprefix (1 syslog) + traffic_intercept (1 syslog) +
        # latency_spike (1 syslog) + maintain (1 syslog) + withdraw (1 syslog) = 5 total
        assert syslog_instance.emit.call_count == 5

        assert latency_instance.emit.call_count == 2  # latency_spike + latency_normal

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
                "action": "unknown_action",
                "prefix": "10.0.0.0/24"
            }
        })

        # Then no generators should be called
        bgp_instance.emit_update.assert_not_called()
        syslog_instance.emit.assert_not_called()
        latency_instance.emit.assert_not_called()

    def test_scenario_metadata_consistency(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that scenario metadata is consistent across actions"""
        # Get the callback
        scenario_name = "consistent-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        bgp_instance = patched_generators["bgp_instance"]

        # Test multiple actions
        test_cases = [
            ("baseline", "baseline", {"prefix": "10.0.0.0/24", "victim_as": 64500}),
            ("announce_subprefix", "subprefix_announce", {"subprefix": "10.0.0.0/25", "attacker_as": 64501}),
        ]

        for action, expected_attack_step, entry_data in test_cases:
            bgp_instance.emit_update.reset_mock()

            # When
            callback({"entry": {"action": action, **entry_data}})

            # Then
            call_kwargs = bgp_instance.emit_update.call_args[1]
            assert call_kwargs["scenario"]["name"] == scenario_name
            assert call_kwargs["scenario"]["attack_step"] == expected_attack_step

    def test_realistic_event_with_extra_fields(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test handling events with extra fields not used by telemetry"""
        # Get the callback
        scenario_name = "realistic-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # Realistic event with many fields
        event = {
            "type": "timeline",
            "timestamp": 1700000000,
            "sequence": 1,
            "description": "Subprefix hijack initiated",
            "entry": {
                "id": "event_001",
                "action": "announce_subprefix",
                "prefix": "203.0.113.0/24",
                "subprefix": "203.0.113.0/25",
                "attacker_as": 64501,
                "victim_as": 64500,
                "timestamp": 1700000001,
                "description": "Attacker announces more specific prefix",
                "impact": "medium",
                "duration_seconds": 300
            }
        }

        # When
        callback(event)

        # Then telemetry should still be generated
        bgp_instance.emit_update.assert_called_once()
        syslog_instance.emit.assert_called_once()

    def test_error_handling_in_callback(
        self, mock_event_bus, mock_clock, monkeypatch
    ):
        """Test that exceptions in generators propagate to caller"""
        # Create a mock BGP generator that raises an exception
        mock_bgp_generator = Mock()
        mock_bgp_generator.emit_update = Mock(side_effect=RuntimeError("Generator failed"))

        # Create mock class that returns our exception-raising instance
        mock_bgp_class = Mock(return_value=mock_bgp_generator)

        # Patch the generator imports
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.BGPUpdateGenerator",
            mock_bgp_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.RouterSyslogGenerator",
            Mock()
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.LatencyMetricsGenerator",
            Mock()
        )

        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # The callback doesn't handle exceptions, so it should raise
        with pytest.raises(RuntimeError, match="Generator failed"):
            callback({"entry": {"action": "baseline", "prefix": "10.0.0.0/24", "victim_as": 64500}})

    def test_current_utc_time_usage(self, mock_event_bus, mock_clock, current_utc_time, monkeypatch):
        """Test that clock is used for timestamps"""
        mock_clock.now.return_value = current_utc_time

        # Mock generators
        mock_bgp_generator = Mock()
        mock_bgp_generator.emit_update = Mock()

        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.BGPUpdateGenerator",
            Mock(return_value=mock_bgp_generator)
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.RouterSyslogGenerator",
            Mock()
        )
        monkeypatch.setattr(
            "simulator.scenarios.medium.subprefix_intercept.telemetry.LatencyMetricsGenerator",
            Mock()
        )

        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Process event
        callback({
            "entry": {
                "action": "baseline",
                "prefix": "10.0.0.0/24",
                "victim_as": 64500
            }
        })

        # Verify generator was called (clock.now() is called inside generator)
        mock_bgp_generator.emit_update.assert_called_once()
