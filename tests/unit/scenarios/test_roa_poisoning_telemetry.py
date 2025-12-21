"""
Unit tests for simulator/scenarios/advanced/roa_poisoning/telemetry.py
"""
from unittest.mock import Mock

import pytest

from simulator.scenarios.advanced.roa_poisoning.telemetry import register


class TestROAPoisoningTelemetry:
    """Test suite for roa_poisoning telemetry mapping"""

    @pytest.fixture
    def mock_event_bus(self):
        """Mock EventBus"""
        return Mock()

    @pytest.fixture
    def mock_bgp_generator(self):
        """Mock BGPUpdateGenerator"""
        bgp_gen = Mock()
        bgp_gen.emit_update = Mock()
        return bgp_gen

    @pytest.fixture
    def mock_syslog_generator(self):
        """Mock RouterSyslogGenerator"""
        syslog_gen = Mock()
        syslog_gen.emit = Mock()
        syslog_gen.configuration_change = Mock()
        return syslog_gen

    @pytest.fixture
    def patched_generators(self, monkeypatch, mock_bgp_generator, mock_syslog_generator):
        """Patch generator imports"""
        # Create mocks for the generator classes
        mock_bgp_class = Mock(return_value=mock_bgp_generator)
        mock_syslog_class = Mock(return_value=mock_syslog_generator)

        monkeypatch.setattr(
            "simulator.scenarios.advanced.roa_poisoning.telemetry.BGPUpdateGenerator",
            mock_bgp_class
        )
        monkeypatch.setattr(
            "simulator.scenarios.advanced.roa_poisoning.telemetry.RouterSyslogGenerator",
            mock_syslog_class
        )

        # Return both the class mocks and instance mocks
        return {
            "bgp_class": mock_bgp_class,
            "syslog_class": mock_syslog_class,
            "bgp_instance": mock_bgp_generator,
            "syslog_instance": mock_syslog_generator
        }

    def test_register_initializes_generators_with_correct_params(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that register creates generators with correct parameters"""
        scenario_name = "roa-poisoning-test"

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

    def test_register_subscribes_to_event_bus(self, mock_event_bus, mock_clock, patched_generators):
        """Test that register subscribes callback to event bus"""
        # When
        register(event_bus=mock_event_bus, clock=mock_clock, scenario_name="test")

        # Then
        mock_event_bus.subscribe.assert_called_once()
        callback = mock_event_bus.subscribe.call_args[0][0]
        assert callable(callback)

    def test_on_timeline_event_handles_empty_entry_dict(self, mock_event_bus, mock_clock, patched_generators):
        """Test that events with empty entry dict are handled"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When calling with event that has empty entry dict
        callback({"entry": {}})

        # Then no generators should be called (no exception raised)

    def test_baseline_rpki_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test baseline_rpki action generates RPKI validation event"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing baseline_rpki event
        event = {
            "entry": {
                "action": "baseline_rpki",
                "prefix": "203.0.113.0/24",
                "origin_as": 64500,
                "rpki_state": "valid"
            }
        }
        callback(event)

        # Then verify event bus publish
        mock_event_bus.publish.assert_called_once()
        published_event = mock_event_bus.publish.call_args[0][0]

        assert published_event["event_type"] == "rpki.validation"
        assert published_event["timestamp"] == mock_clock.now.return_value
        assert published_event["source"] == {"feed": "rpki-validator", "observer": "validator"}

        attributes = published_event["attributes"]
        assert attributes["prefix"] == "203.0.113.0/24"
        assert attributes["origin_as"] == 64500
        assert attributes["validation_state"] == "valid"

        scenario = published_event["scenario"]
        assert scenario["name"] == scenario_name
        assert scenario["attack_step"] == "baseline"
        assert scenario["incident_id"] == f"{scenario_name}-203.0.113.0/24"

    def test_suspicious_login_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test suspicious_login action generates access login event"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # When processing suspicious_login event
        event = {
            "entry": {
                "action": "suspicious_login",
                "user": "admin",
                "source_ip": "192.168.1.100",
                "location": "unusual-location",
                "system": "ROA-management"
            }
        }
        callback(event)

        # Then verify event bus publish
        mock_event_bus.publish.assert_called_once()
        published_event = mock_event_bus.publish.call_args[0][0]

        assert published_event["event_type"] == "access.login"
        assert published_event["timestamp"] == mock_clock.now.return_value
        assert published_event["source"] == {"feed": "auth-system", "observer": "tacacs"}

        attributes = published_event["attributes"]
        assert attributes["user"] == "admin"
        assert attributes["source_ip"] == "192.168.1.100"
        assert attributes["location"] == "unusual-location"
        assert attributes["system"] == "ROA-management"
        assert attributes["suspicious"] is True
        assert attributes["reason"] == "unusual_location"

        scenario = published_event["scenario"]
        assert scenario["attack_step"] == "initial_access"
        assert scenario["incident_id"] == f"{scenario_name}-unknown"

    def test_roa_deleted_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test roa_deleted action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing roa_deleted event
        event = {
            "entry": {
                "action": "roa_deleted",
                "prefix": "198.51.100.0/24",
                "actor": "attacker"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "ROA for 198.51.100.0/24 removed by attacker"
        assert call_kwargs["severity"] == "warning"
        assert call_kwargs["subsystem"] == "rpki"
        assert call_kwargs["peer_ip"] is None

        scenario = call_kwargs["scenario"]
        assert scenario["name"] == scenario_name
        assert scenario["attack_step"] == "roa_manipulation"
        assert scenario["incident_id"] == f"{scenario_name}-198.51.100.0/24"

    def test_rpki_state_flip_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test rpki_state_flip action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing rpki_state_flip event
        event = {
            "entry": {
                "action": "rpki_state_flip",
                "prefix": "203.0.113.0/24",
                "previous_state": "valid",
                "current_state": "invalid"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "RPKI state for 203.0.113.0/24 flipped from valid to invalid"
        assert call_kwargs["severity"] == "notice"
        assert call_kwargs["subsystem"] == "rpki"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "rpki_impact"

    def test_policy_commit_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test policy_commit action generates configuration change"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing policy_commit event
        event = {
            "entry": {
                "action": "policy_commit",
                "user": "operator",
                "message": "Modified route-map for prefix filtering"
            }
        }
        callback(event)

        # Then verify configuration change
        syslog_instance.configuration_change.assert_called_once_with(
            user="operator",
            change_summary="Modified route-map for prefix filtering",
            attack_step="policy_change"
        )

    def test_announce_with_roa_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test announce_with_roa action generates BGP update"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get BGP instance
        bgp_instance = patched_generators["bgp_instance"]

        # When processing announce_with_roa event
        event = {
            "entry": {
                "action": "announce_with_roa",
                "prefix": "192.0.2.0/24",
                "attacker_as": 64501
            }
        }
        callback(event)

        # Then verify BGP update
        bgp_instance.emit_update.assert_called_once()
        call_kwargs = bgp_instance.emit_update.call_args[1]

        assert call_kwargs["prefix"] == "192.0.2.0/24"
        assert call_kwargs["as_path"] == [65004]
        assert call_kwargs["origin_as"] == 64501
        assert call_kwargs["next_hop"] == "198.51.100.10"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "malicious_announce"
        assert scenario["incident_id"] == f"{scenario_name}-192.0.2.0/24"

    def test_victim_route_rejected_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test victim_route_rejected action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing victim_route_rejected event
        event = {
            "entry": {
                "action": "victim_route_rejected",
                "prefix": "203.0.113.0/24",
                "victim_as": 64500,
                "reason": "RPKI invalid"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "Route 203.0.113.0/24 from AS64500 rejected: RPKI invalid"
        assert call_kwargs["severity"] == "error"
        assert call_kwargs["subsystem"] == "bgp"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "route_rejection"

    def test_blackhole_community_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test blackhole_community action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing blackhole_community event
        event = {
            "entry": {
                "action": "blackhole_community",
                "prefix": "198.51.100.0/24",
                "community": "65535:666"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "Blackhole community 65535:666 detected on 198.51.100.0/24"
        assert call_kwargs["severity"] == "critical"
        assert call_kwargs["subsystem"] == "bgp"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "blackhole"

    def test_coordinated_flap_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test coordinated_flap action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing coordinated_flap event
        event = {
            "entry": {
                "action": "coordinated_flap",
                "prefixes": ["203.0.113.0/24", "198.51.100.0/24"],
                "flap_count": 5
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "Coordinated flapping on prefixes: 203.0.113.0/24, 198.51.100.0/24, flap count: 5"
        assert call_kwargs["severity"] == "warning"
        assert call_kwargs["subsystem"] == "bgp"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "route_flapping"

    def test_roa_restored_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test roa_restored action generates syslog"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get syslog instance
        syslog_instance = patched_generators["syslog_instance"]

        # When processing roa_restored event
        event = {
            "entry": {
                "action": "roa_restored",
                "prefix": "192.0.2.0/24",
                "actor": "admin"
            }
        }
        callback(event)

        # Then verify syslog
        syslog_instance.emit.assert_called_once()
        call_kwargs = syslog_instance.emit.call_args[1]

        assert call_kwargs["message"] == "ROA for 192.0.2.0/24 restored by admin"
        assert call_kwargs["severity"] == "notice"
        assert call_kwargs["subsystem"] == "rpki"

        scenario = call_kwargs["scenario"]
        assert scenario["attack_step"] == "cleanup"

    def test_logout_action_generates_correct_telemetry(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test logout action generates access logout event"""
        # Get the callback
        scenario_name = "roa-poisoning"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Reset mock to track calls
        mock_event_bus.publish.reset_mock()

        # When processing logout event
        event = {
            "entry": {
                "action": "logout",
                "user": "admin"
            }
        }
        callback(event)

        # Then verify event bus publish
        mock_event_bus.publish.assert_called_once()
        published_event = mock_event_bus.publish.call_args[0][0]

        assert published_event["event_type"] == "access.logout"
        assert published_event["timestamp"] == mock_clock.now.return_value
        assert published_event["source"] == {"feed": "auth-system", "observer": "tacacs"}

        attributes = published_event["attributes"]
        assert attributes["user"] == "admin"

        scenario = published_event["scenario"]
        assert scenario["attack_step"] == "disconnection"
        assert scenario["incident_id"] == f"{scenario_name}-unknown"

    def test_incident_id_handling_with_subprefix(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test incident_id is correctly generated with subprefix"""
        # Get the callback
        scenario_name = "test-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Reset mock
        mock_event_bus.publish.reset_mock()

        # When processing event with subprefix
        event = {
            "entry": {
                "action": "baseline_rpki",
                "subprefix": "203.0.113.0/25",  # Using subprefix instead of prefix
                "origin_as": 64500,
                "rpki_state": "valid"
            }
        }
        callback(event)

        # Then verify incident_id uses subprefix
        published_event = mock_event_bus.publish.call_args[0][0]
        assert published_event["scenario"]["incident_id"] == "test-scenario-203.0.113.0/25"

    def test_incident_id_handling_no_prefix(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test incident_id uses 'unknown' when no prefix or subprefix"""
        # Get the callback
        scenario_name = "test-scenario"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Reset mock
        mock_event_bus.publish.reset_mock()

        # When processing event without prefix or subprefix
        event = {
            "entry": {
                "action": "suspicious_login",
                "user": "admin",
                "source_ip": "192.168.1.100",
                "location": "remote",
                "system": "management"
            }
        }
        callback(event)

        # Then verify incident_id is unknown
        published_event = mock_event_bus.publish.call_args[0][0]
        assert published_event["scenario"]["incident_id"] == "test-scenario-unknown"

    def test_multiple_actions_scenario_progression(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test complete scenario progression through multiple actions"""
        # Get the callback
        scenario_name = "roa-poisoning-full"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # Reset mocks
        mock_event_bus.publish.reset_mock()
        bgp_instance.emit_update.reset_mock()
        syslog_instance.emit.reset_mock()
        syslog_instance.configuration_change.reset_mock()

        # Complete scenario sequence
        events = [
            {"entry": {"action": "baseline_rpki", "prefix": "203.0.113.0/24", "origin_as": 64500, "rpki_state": "valid"}},
            {"entry": {"action": "suspicious_login", "user": "attacker", "source_ip": "10.0.0.1", "location": "unknown", "system": "ROA"}},
            {"entry": {"action": "roa_deleted", "prefix": "203.0.113.0/24", "actor": "attacker"}},
            {"entry": {"action": "rpki_state_flip", "prefix": "203.0.113.0/24", "previous_state": "valid", "current_state": "invalid"}},
            {"entry": {"action": "policy_commit", "user": "attacker", "message": "Modified prefix filters"}},
            {"entry": {"action": "announce_with_roa", "prefix": "203.0.113.0/24", "attacker_as": 64501}},
            {"entry": {"action": "victim_route_rejected", "prefix": "203.0.113.0/24", "victim_as": 64500, "reason": "RPKI invalid"}},
            {"entry": {"action": "blackhole_community", "prefix": "203.0.113.0/24", "community": "65535:666"}},
            {"entry": {"action": "coordinated_flap", "prefixes": ["203.0.113.0/24", "198.51.100.0/24"], "flap_count": 3}},
            {"entry": {"action": "roa_restored", "prefix": "203.0.113.0/24", "actor": "admin"}},
            {"entry": {"action": "logout", "user": "attacker"}},
        ]

        # When processing all events
        for event in events:
            callback(event)

        # Then verify correct number of calls
        assert mock_event_bus.publish.call_count == 3  # baseline_rpki + suspicious_login + logout
        assert bgp_instance.emit_update.call_count == 1  # announce_with_roa
        assert syslog_instance.emit.call_count == 6  # roa_deleted + rpki_state_flip + victim_route_rejected + blackhole_community + coordinated_flap + roa_restored
        assert syslog_instance.configuration_change.call_count == 1  # policy_commit

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

        # Reset mocks
        mock_event_bus.publish.reset_mock()
        bgp_instance.emit_update.reset_mock()
        syslog_instance.emit.reset_mock()

        # When processing unknown action
        callback({
            "entry": {
                "action": "unknown_action",
                "prefix": "10.0.0.0/24"
            }
        })

        # Then no generators should be called
        mock_event_bus.publish.assert_not_called()
        bgp_instance.emit_update.assert_not_called()
        syslog_instance.emit.assert_not_called()

    def test_scenario_metadata_structure_across_actions(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that scenario metadata has correct structure across different actions"""
        # Get the callback
        scenario_name = "roa-poisoning-consistency"
        register(mock_event_bus, mock_clock, scenario_name)
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Test different actions that generate different telemetry types
        test_cases = [
            ("baseline_rpki", "baseline", mock_event_bus.publish, "rpki.validation"),
            ("suspicious_login", "initial_access", mock_event_bus.publish, "access.login"),
            ("announce_with_roa", "malicious_announce", patched_generators["bgp_instance"].emit_update, None),
            ("roa_deleted", "roa_manipulation", patched_generators["syslog_instance"].emit, None),
        ]

        prefix = "203.0.113.0/24"
        incident_id = f"{scenario_name}-{prefix}"

        for action, expected_attack_step, mock_method, expected_event_type in test_cases:
            # Reset mock
            mock_method.reset_mock()

            # Prepare event based on action
            event = {"entry": {"action": action, "prefix": prefix}}

            # Add required fields for specific actions
            if action == "baseline_rpki":
                event["entry"]["origin_as"] = 64500
                event["entry"]["rpki_state"] = "valid"
            elif action == "suspicious_login":
                event["entry"]["user"] = "test"
                event["entry"]["source_ip"] = "192.168.1.1"
                event["entry"]["location"] = "test"
                event["entry"]["system"] = "test"
            elif action == "announce_with_roa":
                event["entry"]["attacker_as"] = 64501
            elif action == "roa_deleted":
                event["entry"]["actor"] = "test"

            # When
            callback(event)

            # Then
            mock_method.assert_called_once()

            # Check scenario metadata
            call_args = mock_method.call_args
            if expected_event_type:
                # For event_bus.publish calls
                published_event = call_args[0][0]
                assert published_event["scenario"]["name"] == scenario_name
                assert published_event["scenario"]["attack_step"] == expected_attack_step
                assert published_event["scenario"]["incident_id"] == incident_id
            else:
                # For generator method calls
                call_kwargs = call_args[1]
                assert call_kwargs["scenario"]["name"] == scenario_name
                assert call_kwargs["scenario"]["attack_step"] == expected_attack_step
                assert call_kwargs["scenario"]["incident_id"] == incident_id

    def test_clock_now_called_for_timestamp(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that clock.now() is called for events that need timestamps"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Reset mock
        mock_clock.now.reset_mock()
        mock_event_bus.publish.reset_mock()

        # When processing event that uses clock.now()
        event = {
            "entry": {
                "action": "baseline_rpki",
                "prefix": "10.0.0.0/24",
                "origin_as": 64500,
                "rpki_state": "valid"
            }
        }
        callback(event)

        # Then clock.now() should be called
        mock_clock.now.assert_called_once()

        # And timestamp should be used in published event
        published_event = mock_event_bus.publish.call_args[0][0]
        assert published_event["timestamp"] == mock_clock.now.return_value

    def test_empty_event_handling(
        self, mock_event_bus, mock_clock, patched_generators
    ):
        """Test that events without action are handled gracefully"""
        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Get instances
        bgp_instance = patched_generators["bgp_instance"]
        syslog_instance = patched_generators["syslog_instance"]

        # Reset mocks
        mock_event_bus.publish.reset_mock()
        bgp_instance.emit_update.reset_mock()
        syslog_instance.emit.reset_mock()

        # When processing event without action
        callback({
            "entry": {
                "prefix": "10.0.0.0/24",
                # No action field
            }
        })

        # Then no telemetry should be generated
        mock_event_bus.publish.assert_not_called()
        bgp_instance.emit_update.assert_not_called()
        syslog_instance.emit.assert_not_called()

    def test_current_utc_time_usage(self, mock_event_bus, mock_clock, current_utc_time, patched_generators):
        """Test that UTC time handling works correctly"""
        # Configure mock clock to use the current_utc_time fixture
        mock_clock.now.return_value = current_utc_time

        # Get the callback
        register(mock_event_bus, mock_clock, "test")
        callback = mock_event_bus.subscribe.call_args[0][0]

        # Reset mock
        mock_event_bus.publish.reset_mock()

        # When processing an event that publishes to event bus
        callback({
            "entry": {
                "action": "baseline_rpki",
                "prefix": "10.0.0.0/24",
                "origin_as": 64500,
                "rpki_state": "valid"
            }
        })

        # Then verify the clock was used and timestamp is timezone-aware
        mock_clock.now.assert_called_once()
        published_event = mock_event_bus.publish.call_args[0][0]
        assert published_event["timestamp"] == current_utc_time
        assert published_event["timestamp"].tzinfo is not None
