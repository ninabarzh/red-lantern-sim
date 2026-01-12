"""
Unit tests for telemetry/generators/router_syslog.py
"""

from datetime import datetime
from unittest.mock import Mock

import pytest

from telemetry.generators.router_syslog import RouterSyslogGenerator


class TestRouterSyslogGenerator:
    """Test suite for RouterSyslogGenerator"""

    @pytest.fixture
    def mock_clock(self):
        """Mock SimulationClock"""
        clock = Mock()
        clock.now.return_value = datetime(2024, 1, 1, 12, 0, 0).timestamp()
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
            scenario_name="bgp-hijack-scenario",
        )

    def test_initialization(self, generator, mock_clock, mock_event_bus):
        """Test generator initialization with correct attributes"""
        assert generator.clock == mock_clock
        assert generator.event_bus == mock_event_bus
        assert generator.router_name == "test-router-01"
        assert generator.scenario_name == "bgp-hijack-scenario"

    def test_bgp_neighbor_state_change_up(self, generator, mock_clock, mock_event_bus):
        """Test bgp_neighbor_state_change with state='up'"""
        # When
        generator.bgp_neighbor_state_change(
            peer_ip="192.168.1.1", state="up", reason="BGP session established"
        )

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
        assert attributes["severity"] == "notice"  # Up = notice
        assert attributes["subsystem"] == "bgp"
        assert attributes["peer_ip"] == "192.168.1.1"
        assert attributes["bgp_event"] == "neighbor_state_change"
        assert attributes["neighbor_state"] == "up"
        assert attributes["change_reason"] == "BGP session established"

        # Verify default scenario
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": None,
            "incident_id": None,
        }

    def test_bgp_neighbor_state_change_down(
        self, generator, mock_clock, mock_event_bus
    ):
        """Test bgp_neighbor_state_change with state='down'"""
        # When
        generator.bgp_neighbor_state_change(
            peer_ip="10.0.0.1", state="down", reason="Hold timer expired"
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        attributes = event["attributes"]

        assert attributes["severity"] == "warning"  # Down = warning
        assert attributes["neighbor_state"] == "down"
        assert attributes["change_reason"] == "Hold timer expired"
        assert attributes["peer_ip"] == "10.0.0.1"

    def test_bgp_neighbor_state_change_with_scenario(self, generator, mock_event_bus):
        """Test bgp_neighbor_state_change with custom scenario"""
        custom_scenario = {
            "name": "custom-attack",
            "attack_step": "session_disruption",
            "incident_id": "inc-12345",
            "additional_field": "extra_data",
        }

        # When
        generator.bgp_neighbor_state_change(
            peer_ip="203.0.113.1",
            state="up",
            reason="Manual activation",
            scenario=custom_scenario,
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"] == custom_scenario

    def test_bgp_neighbor_state_change_without_reason(self, generator, mock_event_bus):
        """Test bgp_neighbor_state_change with empty reason"""
        # When
        generator.bgp_neighbor_state_change(
            peer_ip="192.168.1.1", state="up", reason=""  # Empty reason
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["change_reason"] == ""

    def test_configuration_change_basic(self, generator, mock_clock, mock_event_bus):
        """Test configuration_change method"""
        # When
        generator.configuration_change(
            user="admin",
            change_type="bgp_config",
            target="Added route-map for customer AS64500",
            attack_step="configuration_update",
        )

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
        assert attributes["severity"] == "notice"
        assert attributes["subsystem"] == "config"
        assert attributes["config_event"] == "change"
        assert attributes["changed_by"] == "admin"
        assert attributes["change_type"] == "bgp_config"
        assert attributes["change_target"] == "Added route-map for customer AS64500"

        # Verify scenario with attack_step
        assert event["scenario"] == {
            "name": "bgp-hijack-scenario",
            "attack_step": "configuration_update",
            "incident_id": None,
        }

    def test_configuration_change_roa_request(self, generator, mock_event_bus):
        """Test configuration_change with roa_request type"""
        # When
        generator.configuration_change(
            user="operator@attacker-as64513.net",
            change_type="roa_request",
            target="ROA request for 198.51.100.0/24 AS64513",
            attack_step="establish_presence",
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        attributes = event["attributes"]

        assert attributes["changed_by"] == "operator@attacker-as64513.net"
        assert attributes["change_type"] == "roa_request"
        assert attributes["change_target"] == "ROA request for 198.51.100.0/24 AS64513"
        assert event["scenario"]["attack_step"] == "establish_presence"

    def test_configuration_change_without_attack_step(self, generator, mock_event_bus):
        """Test configuration_change without attack_step"""
        # When
        generator.configuration_change(
            user="admin",
            change_type="bgp_config",
            target="Updated BGP timers",
            # No attack_step parameter
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["scenario"]["attack_step"] is None

    def test_configuration_change_registry_access(self, generator, mock_event_bus):
        """Test configuration_change with registry_access type"""
        # When
        generator.configuration_change(
            user="admin@victim-network.net",
            change_type="registry_access",
            target="RIR portal access from 185.220.101.45",
            attack_step="credential_compromise",
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        attributes = event["attributes"]

        assert attributes["changed_by"] == "admin@victim-network.net"
        assert attributes["change_type"] == "registry_access"
        assert attributes["change_target"] == "RIR portal access from 185.220.101.45"
        assert event["scenario"]["attack_step"] == "credential_compromise"

    def test_multiple_method_calls(self, generator, mock_clock, mock_event_bus):
        """Test multiple method calls with different timestamps"""
        # Setup different timestamps
        timestamps = [1000.0, 1001.0, 1002.0]
        mock_clock.now.side_effect = timestamps

        # Reset mock to track calls
        mock_event_bus.publish.reset_mock()

        # When calling multiple methods
        generator.bgp_neighbor_state_change(peer_ip="10.0.0.1", state="up")
        generator.configuration_change(
            user="admin", change_type="bgp_config", target="First config change"
        )
        generator.bgp_neighbor_state_change(
            peer_ip="10.0.0.2", state="down", reason="Interface down"
        )

        # Then
        assert mock_event_bus.publish.call_count == 3
        calls = mock_event_bus.publish.call_args_list

        # Check timestamps
        assert calls[0][0][0]["timestamp"] == timestamps[0]
        assert calls[1][0][0]["timestamp"] == timestamps[1]
        assert calls[2][0][0]["timestamp"] == timestamps[2]

        # Check event types
        assert calls[0][0][0]["attributes"]["bgp_event"] == "neighbor_state_change"
        assert calls[1][0][0]["attributes"]["config_event"] == "change"
        assert calls[2][0][0]["attributes"]["bgp_event"] == "neighbor_state_change"

    def test_edge_case_empty_user_in_config_change(self, generator, mock_event_bus):
        """Test configuration_change with empty user"""
        # When
        generator.configuration_change(
            user="",  # Empty user
            change_type="system",
            target="Automatic system update",
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["changed_by"] == ""

    def test_edge_case_special_characters_in_target(self, generator, mock_event_bus):
        """Test configuration_change with special characters in target"""
        target = 'ROA request for "198.51.100.0/24" (AS64513) - maxLength /25'

        # When
        generator.configuration_change(
            user="operator", change_type="roa_request", target=target
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        assert event["attributes"]["change_target"] == target

    def test_invalid_state_in_bgp_neighbor_change(self, generator, mock_event_bus):
        """Test bgp_neighbor_state_change with invalid state (should still work)"""
        # When
        generator.bgp_neighbor_state_change(
            peer_ip="10.0.0.1",
            state="unknown",  # Not "up" or "down"
            reason="Unknown state change",
        )

        # Then
        event = mock_event_bus.publish.call_args[0][0]
        # Severity should still be "notice" (default in ternary)
        assert event["attributes"]["severity"] == "notice"
        assert event["attributes"]["neighbor_state"] == "unknown"

    def test_different_generator_instances(self, mock_clock, mock_event_bus):
        """Test that different generator instances have independent state"""
        # Given two generators
        generator1 = RouterSyslogGenerator(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="router-east",
            scenario_name="scenario-alpha",
        )

        generator2 = RouterSyslogGenerator(
            clock=mock_clock,
            event_bus=mock_event_bus,
            router_name="router-west",
            scenario_name="scenario-beta",
        )

        # When both emit events
        generator1.bgp_neighbor_state_change(peer_ip="10.0.0.1", state="up")
        event1 = mock_event_bus.publish.call_args[0][0]

        generator2.configuration_change(user="admin", change_type="test", target="test")
        event2 = mock_event_bus.publish.call_args[0][0]

        # Then they should have different router names and scenario names
        assert event1["attributes"]["router"] == "router-east"
        assert event2["attributes"]["router"] == "router-west"

        assert event1["scenario"]["name"] == "scenario-alpha"
        assert event2["scenario"]["name"] == "scenario-beta"

    def test_method_signatures(self):
        """Test that methods have correct signatures"""
        import inspect

        # Check bgp_neighbor_state_change signature
        sig = inspect.signature(RouterSyslogGenerator.bgp_neighbor_state_change)
        params = list(sig.parameters.keys())
        assert params == ["self", "peer_ip", "state", "reason", "scenario"]

        # Check configuration_change signature
        sig = inspect.signature(RouterSyslogGenerator.configuration_change)
        params = list(sig.parameters.keys())
        assert params == ["self", "user", "change_type", "target", "attack_step"]
