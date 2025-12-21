"""
Unit tests for telemetry/generators/router_syslog.py
"""
from datetime import datetime
from unittest.mock import Mock, call

import pytest

from telemetry.generators.router_syslog import RouterSyslogGenerator


class TestRouterSyslogGenerator:
    """Test suite for RouterSyslogGenerator"""

    @pytest.fixture
    def mock_clock(self):
        """Mock SimulationClock"""
        clock = Mock()
        clock.now.return_value = datetime(2024, 1, 1, 12, 0, 0)
        return clock

    @pytest.fixture
    def mock_event_bus(self):
        """Mock EventBus"""
        return Mock()

    @pytest.fixture
    def generator(self, mock_clock, mock_event_bus):
        """Create a generator instance for testing"""
        return RouterSyslogGenerator(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="test-router-01",
            scenario_name="bgp-hijack-scenario"
        )

    def test_initialization(self, generator, mock_clock, mock_event_bus):
        """Test generator initialization with correct attributes"""
        assert generator.clock == mock_clock
        assert generator.event_bus == mock_event_bus
        assert generator.router_name == "test-router-01"
        assert generator.scenario_name == "bgp-hijack-scenario"

    def test_emit_basic_event(self, generator, mock_clock, mock_event_bus):
        """Test emit method publishes basic event structure"""
        # When
        generator.emit(message="Test syslog message")

        # Then
        mock_event_bus.publish.assert_called_once()
        event = mock_event_bus.publish.call_args[0][0]

        # Verify event structure
        assert event["event_type"] == "router.syslog"
        assert event["timestamp"] == mock_clock.now.return_value
        assert event["source"] == {"feed": "router-syslog", "observer": "router"}

        # Verify attributes
        attributes = event["attributes"]
        assert attributes["router"] == "test-router-01"
        assert attributes["severity"] == "info"  # Default
        assert attributes["message"] == "Test syslog message"
        assert attributes["subsystem"] is None
        assert attributes["peer_ip"] is None

        # Verify default scenario
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": None,
            "incident_id": None
        }

    def test_emit_with_all_parameters(self, generator, mock_clock, mock_event_bus):
        """Test emit method with all optional parameters"""
        # When
        generator.emit(
            message="BGP session established",
            severity="notice",
            subsystem="bgp",
            peer_ip="192.168.1.1"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        attributes = event["attributes"]

        assert attributes["severity"] == "notice"
        assert attributes["subsystem"] == "bgp"
        assert attributes["peer_ip"] == "192.168.1.1"
        assert attributes["message"] == "BGP session established"

    def test_emit_with_custom_scenario(self, generator, mock_event_bus):
        """Test emit with custom scenario dictionary"""
        custom_scenario = {
            "name": "custom-scenario",
            "attack_step": "lateral_movement",
            "incident_id": "inc-12345",
            "additional_field": "extra_data"
        }

        # When
        generator.emit(
            message="Test with custom scenario",
            scenario=custom_scenario
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"] == custom_scenario

    def test_emit_with_none_scenario(self, generator, mock_event_bus):
        """Test emit with scenario=None should use default"""
        # When
        generator.emit(message="Test", scenario=None)

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": None,
            "incident_id": None
        }

    @pytest.mark.parametrize("severity", ["info", "notice", "warning", "error"])
    def test_emit_different_severities(self, generator, mock_event_bus, severity):
        """Test emit with various severity levels"""
        # When
        generator.emit(message=f"Severity: {severity}", severity=severity)

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["severity"] == severity

    def test_prefix_limit_exceeded(self, generator, mock_event_bus):
        """Test prefix_limit_exceeded method"""
        # When
        generator.prefix_limit_exceeded(
            peer_ip="10.0.0.1",
            limit=100
        )

        # Then
        mock_event_bus.publish.assert_called_once()
        event = mock_event_bus.publish.call_args[0][0]

        attributes = event["attributes"]
        assert attributes["severity"] == "error"
        assert attributes["subsystem"] == "bgp"
        assert attributes["peer_ip"] == "10.0.0.1"
        assert attributes["message"] == "Prefix limit 100 exceeded from neighbour 10.0.0.1"

        # Default scenario
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": None,
            "incident_id": None
        }

    def test_prefix_limit_exceeded_with_scenario(self, generator, mock_event_bus):
        """Test prefix_limit_exceeded with custom scenario"""
        custom_scenario = {
            "name": "prefix-flood-attack",
            "attack_step": "flood_initiation",
            "incident_id": "flood-001"
        }

        # When
        generator.prefix_limit_exceeded(
            peer_ip="192.168.100.50",
            limit=500,
            scenario=custom_scenario
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"] == custom_scenario
        assert event["attributes"]["message"] == "Prefix limit 500 exceeded from neighbour 192.168.100.50"

    def test_bgp_session_reset(self, generator, mock_event_bus):
        """Test bgp_session_reset method"""
        # When
        generator.bgp_session_reset(
            peer_ip="203.0.113.1",
            reason="hold timer expired"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]

        attributes = event["attributes"]
        assert attributes["severity"] == "warning"
        assert attributes["subsystem"] == "bgp"
        assert attributes["peer_ip"] == "203.0.113.1"
        assert attributes["message"] == "BGP session to 203.0.113.1 reset: hold timer expired"

    def test_bgp_session_reset_with_scenario(self, generator, mock_event_bus):
        """Test bgp_session_reset with custom scenario"""
        custom_scenario = {
            "name": "session-disruption",
            "attack_step": "reset_triggered",
            "incident_id": "reset-2024"
        }

        # When
        generator.bgp_session_reset(
            peer_ip="198.51.100.1",
            reason="manual administrative reset",
            scenario=custom_scenario
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"] == custom_scenario
        assert event["attributes"]["message"] == "BGP session to 198.51.100.1 reset: manual administrative reset"

    def test_configuration_change(self, generator, mock_event_bus):
        """Test configuration_change method"""
        # When
        generator.configuration_change(
            user="admin",
            change_summary="Added route-map for customer AS64500"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]

        attributes = event["attributes"]
        assert attributes["severity"] == "notice"
        assert attributes["subsystem"] == "config"
        assert attributes["message"] == "Configuration change by admin: Added route-map for customer AS64500"
        assert attributes["peer_ip"] is None

        # Scenario should have name but no attack_step by default
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": None
        }

    def test_configuration_change_with_attack_step(self, generator, mock_event_bus):
        """Test configuration_change with attack_step parameter"""
        # When
        generator.configuration_change(
            user="attacker",
            change_summary="Modified BGP community values",
            attack_step="privilege_escalation"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]

        assert event["attributes"]["message"] == "Configuration change by attacker: Modified BGP community values"
        assert event["scenario"]["name"] == "bgp-hijack-scenario"
        assert event["scenario"]["attack_step"] == "privilege_escalation"
        # Note: incident_id is not included in configuration_change scenario

    def test_configuration_change_scenario_structure(self, generator, mock_event_bus):
        """Verify configuration_change creates minimal scenario dict"""
        # When
        generator.configuration_change(
            user="operator",
            change_summary="Updated prefix-list"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]

        # Only name and attack_step, no incident_id
        assert set(event["scenario"].keys()) == {"name", "attack_step"}
        assert event["scenario"]["name"] == "bgp-hijack-scenario"
        assert event["scenario"]["attack_step"] is None

    def test_multiple_emissions(self, generator, mock_clock, mock_event_bus):
        """Test multiple event emissions"""
        # Reset mock to track calls
        mock_clock.now.reset_mock()
        mock_event_bus.publish.reset_mock()

        # When emitting multiple events
        generator.emit(message="First event")
        generator.prefix_limit_exceeded(peer_ip="10.1.1.1", limit=200)
        generator.bgp_session_reset(peer_ip="10.2.2.2", reason="interface down")
        generator.configuration_change(user="admin", change_summary="Backup config")

        # Then
        assert mock_clock.now.call_count == 4
        assert mock_event_bus.publish.call_count == 4

        # Verify each call was made
        calls = mock_event_bus.publish.call_args_list
        assert len(calls) == 4

        # Check first event
        first_event = calls[0][0][0]
        assert first_event["attributes"]["message"] == "First event"

        # Check second event
        second_event = calls[1][0][0]
        assert "Prefix limit 200 exceeded" in second_event["attributes"]["message"]

        # Check third event
        third_event = calls[2][0][0]
        assert "BGP session to 10.2.2.2 reset" in third_event["attributes"]["message"]

        # Check fourth event
        fourth_event = calls[3][0][0]
        assert "Configuration change by admin" in fourth_event["attributes"]["message"]

    def test_different_generator_instances(self, mock_clock, mock_event_bus):
        """Test that different generator instances have independent state"""
        # Given two generators
        generator1 = RouterSyslogGenerator(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="router-east",
            scenario_name="scenario-alpha"
        )

        generator2 = RouterSyslogGenerator(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="router-west",
            scenario_name="scenario-beta"
        )

        # When both emit events
        generator1.emit(message="From east")
        event1 = mock_event_bus.publish.call_args[0][0]

        generator2.emit(message="From west")
        event2 = mock_event_bus.publish.call_args[0][0]

        # Then they should have different router names and scenario names
        assert event1["attributes"]["router"] == "router-east"
        assert event2["attributes"]["router"] == "router-west"

        assert event1["scenario"]["name"] == "scenario-alpha"
        assert event2["scenario"]["name"] == "scenario-beta"

    def test_emit_uses_clock_for_timestamp(self, generator, mock_clock, mock_event_bus):
        """Test that emit uses clock.now() for timestamp"""
        # Setup different timestamps
        timestamps = [
            datetime(2024, 1, 1, 10, 0, 0),
            datetime(2024, 1, 1, 10, 0, 1),
            datetime(2024, 1, 1, 10, 0, 2)
        ]
        mock_clock.now.side_effect = timestamps

        # When emitting multiple events
        generator.emit(message="Event 1")
        generator.emit(message="Event 2")
        generator.emit(message="Event 3")

        # Then each event should have the corresponding timestamp
        calls = mock_event_bus.publish.call_args_list
        assert calls[0][0][0]["timestamp"] == timestamps[0]
        assert calls[1][0][0]["timestamp"] == timestamps[1]
        assert calls[2][0][0]["timestamp"] == timestamps[2]

    @pytest.mark.parametrize("method,args,expected_subsystem", [
        ("prefix_limit_exceeded", {"peer_ip": "1.1.1.1", "limit": 100}, "bgp"),
        ("bgp_session_reset", {"peer_ip": "2.2.2.2", "reason": "test"}, "bgp"),
        ("configuration_change", {"user": "test", "change_summary": "test"}, "config"),
    ])
    def test_methods_set_correct_subsystem(self, generator, mock_event_bus, method, args, expected_subsystem):
        """Test that specialized methods set the correct subsystem"""
        # When
        method_func = getattr(generator, method)
        method_func(**args)

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["subsystem"] == expected_subsystem

    @pytest.mark.parametrize("method,args,expected_severity", [
        ("prefix_limit_exceeded", {"peer_ip": "1.1.1.1", "limit": 100}, "error"),
        ("bgp_session_reset", {"peer_ip": "2.2.2.2", "reason": "test"}, "warning"),
        ("configuration_change", {"user": "test", "change_summary": "test"}, "notice"),
    ])
    def test_methods_set_correct_severity(self, generator, mock_event_bus, method, args, expected_severity):
        """Test that specialized methods set the correct severity"""
        # When
        method_func = getattr(generator, method)
        method_func(**args)

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["severity"] == expected_severity

    def test_edge_case_empty_message(self, generator, mock_event_bus):
        """Test emit with empty message"""
        # When
        generator.emit(message="")

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["message"] == ""

    def test_edge_case_special_characters_in_message(self, generator, mock_event_bus):
        """Test emit with special characters in message"""
        message = "BGP session to 192.168.1.1 reset: Interface GigabitEthernet0/0/1 (status: down)"

        # When
        generator.emit(message=message)

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["message"] == message

    def test_peer_ip_format_validation(self, generator, mock_event_bus):
        """Test that peer_ip is passed through as-is (no validation)"""
        test_ips = ["192.168.1.1", "2001:db8::1", "invalid-ip", None]

        for ip in test_ips:
            mock_event_bus.publish.reset_mock()

            # When
            generator.emit(message="Test", peer_ip=ip)

            # Then
            event = mock_event_bus.publish.call_args[0][0]
            assert event["attributes"]["peer_ip"] == ip

    def test_scenario_dict_reference_behavior(self, generator, mock_event_bus):
        """Test that scenario dict is not copied (current implementation behavior)"""
        # Given a mutable scenario dict
        mutable_scenario = {"name": "test", "attack_step": "initial"}

        # When emitting with this scenario
        generator.emit(message="Test", scenario=mutable_scenario)
        event = mock_event_bus.publish.call_args[0][0]

        # Then the same dict object is used (not a copy)
        # This means if we modify the original, it affects the event
        mutable_scenario["attack_step"] = "modified"

        # Current behavior: event scenario reflects the change
        assert event["scenario"]["attack_step"] == "modified"

        # Note: This test documents the current implementation behavior.
        # If immutability is required, the implementation should be changed to copy the dict.

    def test_default_scenario_created_per_call(self, generator, mock_event_bus):
        """Test that default scenario is a new dict each call"""
        # When emitting two events without scenario
        generator.emit(message="Event 1")
        event1 = mock_event_bus.publish.call_args[0][0]

        generator.emit(message="Event 2")
        event2 = mock_event_bus.publish.call_args[0][0]

        # Then they should be different dict objects
        assert event1["scenario"] is not event2["scenario"]
        # But have the same content
        assert event1["scenario"] == event2["scenario"]
