"""
Integration tests for ScenarioRunner with EventBus and real components.
Tests complete simulation workflows.
"""

import tempfile
from pathlib import Path

import pytest

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner


class TestScenarioRunnerIntegration:
    """Integration tests for ScenarioRunner in system context."""

    def test_complete_bgp_attack_simulation(self):
        """Test complete BGP attack simulation with multiple components."""
        # Create realistic BGP hijack scenario
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "bgp-hijack-advanced"
            description: "Advanced BGP prefix hijack simulation"
            attack_type: "route_leak"
            timeline:
              - t: 0
                type: "simulation_start"
                attacker: "AS65530"
                target: "AS65531"
              - t: 5
                type: "malicious_announcement"
                prefix: "192.0.2.0/24"
                as_path: "65530 65531"
                origin: "AS65530"
                hijacked_from: "AS65531"
              - t: 8
                type: "propagation_level1"
                ases_affected: ["65532", "65533"]
                propagation_speed: "fast"
              - t: 12
                type: "traffic_interception"
                prefix: "192.0.2.0/24"
                bytes_redirected: 2048000
                duration_seconds: 60
              - t: 15
                type: "propagation_level2"
                ases_affected: ["65534", "65535", "65536"]
                propagation_speed: "medium"
              - t: 18
                type: "attack_detection"
                detected_by: "AS65533"
                detection_method: "rpki_validation"
                confidence: 0.92
              - t: 20
                type: "countermeasure_initiated"
                action: "route_filtering"
                implemented_by: "AS65534"
              - t: 22
                type: "malicious_withdrawal"
                prefix: "192.0.2.0/24"
                reason: "detection_avoidance"
              - t: 25
                type: "legitimate_route_restored"
                prefix: "192.0.2.0/24"
                legitimate_origin: "AS65531"
              - t: 30
                type: "simulation_complete"
                success: false
                damage_assessment: "moderate"
                duration: 30
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            # Create shared EventBus for entire simulation
            event_bus = EventBus()

            # ===== SIMULATION COMPONENTS =====

            # 1. BGP Route Monitor
            class BgpRouteMonitor:
                def __init__(self):
                    self.routes = {}  # prefix -> (origin_as, timestamp)
                    self.hijacks_detected = []

                def monitor_routes(self, event):
                    entry = event["entry"]
                    if entry["type"] == "malicious_announcement":
                        prefix = entry["prefix"]
                        self.routes[prefix] = (entry["origin"], event["timestamp"])
                    elif entry["type"] == "legitimate_route_restored":
                        prefix = entry["prefix"]
                        self.routes[prefix] = (
                            entry["legitimate_origin"],
                            event["timestamp"],
                        )
                    elif entry["type"] == "attack_detection":
                        self.hijacks_detected.append(
                            {
                                "time": event["timestamp"],
                                "confidence": entry["confidence"],
                                "detector": entry["detected_by"],
                            }
                        )

            # 2. Traffic Analysis Engine
            class TrafficAnalysisEngine:
                def __init__(self):
                    self.total_bytes_intercepted = 0
                    self.interception_events = []

                def analyze_traffic(self, event):
                    entry = event["entry"]
                    if entry["type"] == "traffic_interception":
                        bytes_intercepted = entry.get("bytes_redirected", 0)
                        self.total_bytes_intercepted += bytes_intercepted
                        self.interception_events.append(
                            {
                                "time": event["timestamp"],
                                "prefix": entry["prefix"],
                                "bytes": bytes_intercepted,
                            }
                        )

            # 3. Attack Timeline Reconstructor
            class AttackTimelineReconstructor:
                def __init__(self):
                    self.timeline = []

                def reconstruct_timeline(self, event):
                    self.timeline.append(
                        {
                            "timestamp": event["timestamp"],
                            "type": event["entry"]["type"],
                            "details": {
                                k: v for k, v in event["entry"].items() if k != "type"
                            },
                        }
                    )

            # 4. Countermeasure Effectiveness Tracker
            class CountermeasureTracker:
                def __init__(self):
                    self.countermeasures = []
                    self.effectiveness_metrics = {
                        "detection_to_action_time": None,
                        "attack_duration": None,
                    }
                    self.detection_time = None

                def track_countermeasures(self, event):
                    entry = event["entry"]
                    if entry["type"] == "attack_detection":
                        self.detection_time = event["timestamp"]
                    elif entry["type"] == "countermeasure_initiated":
                        action_time = event["timestamp"]
                        if self.detection_time is not None:
                            self.effectiveness_metrics["detection_to_action_time"] = (
                                action_time - self.detection_time
                            )
                        self.countermeasures.append(
                            {
                                "time": action_time,
                                "action": entry["action"],
                                "implementer": entry["implemented_by"],
                            }
                        )
                    elif entry["type"] == "simulation_complete":
                        if self.detection_time is not None:
                            self.effectiveness_metrics["attack_duration"] = (
                                event["timestamp"] - self.detection_time
                            )

            # Instantiate all components
            bgp_monitor = BgpRouteMonitor()
            traffic_analyzer = TrafficAnalysisEngine()
            timeline_reconstructor = AttackTimelineReconstructor()
            countermeasure_tracker = CountermeasureTracker()

            # Subscribe all components to EventBus
            event_bus.subscribe(bgp_monitor.monitor_routes)
            event_bus.subscribe(traffic_analyzer.analyze_traffic)
            event_bus.subscribe(timeline_reconstructor.reconstruct_timeline)
            event_bus.subscribe(countermeasure_tracker.track_countermeasures)

            # Create and run ScenarioRunner
            runner = ScenarioRunner(temp_path, event_bus)
            runner.load()
            runner.run(close_bus=True)

            # ===== INTEGRATION ASSERTIONS =====

            # 1. Verify complete event flow through all components
            assert len(timeline_reconstructor.timeline) == 10  # All timeline events

            # 2. Verify BGP route hijack and restoration
            assert "192.0.2.0/24" in bgp_monitor.routes
            origin, time = bgp_monitor.routes["192.0.2.0/24"]
            assert origin == "AS65531"  # Legitimate origin restored
            assert time == 25  # Restoration time

            # 3. Verify traffic interception was tracked
            assert traffic_analyzer.total_bytes_intercepted == 2048000
            assert len(traffic_analyzer.interception_events) == 1
            assert traffic_analyzer.interception_events[0]["prefix"] == "192.0.2.0/24"

            # 4. Verify attack detection worked
            assert len(bgp_monitor.hijacks_detected) == 1
            assert bgp_monitor.hijacks_detected[0]["confidence"] == 0.92
            assert bgp_monitor.hijacks_detected[0]["detector"] == "AS65533"

            # 5. Verify countermeasure effectiveness metrics
            assert (
                countermeasure_tracker.effectiveness_metrics["detection_to_action_time"]
                == 2
            )  # 20 - 18
            assert (
                countermeasure_tracker.effectiveness_metrics["attack_duration"] == 12
            )  # 30 - 18

            # 6. Verify countermeasures were tracked
            assert len(countermeasure_tracker.countermeasures) == 1
            assert (
                countermeasure_tracker.countermeasures[0]["action"] == "route_filtering"
            )

            # 7. Verify ScenarioRunner completed correctly
            assert runner.clock.now() == 30
            assert event_bus._closed is True

            # 8. Verify timeline order
            events_in_order = [e["type"] for e in timeline_reconstructor.timeline]
            assert events_in_order[0] == "simulation_start"
            assert events_in_order[-1] == "simulation_complete"
            assert "malicious_announcement" in events_in_order
            assert "legitimate_route_restored" in events_in_order

        finally:
            temp_path.unlink()

    def test_multiple_scenario_sequential_execution(self):
        """Test running multiple scenarios with shared components."""
        # Create scenario A: Basic BGP announcement
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f_a:
            f_a.write(
                """
            id: "scenario-a-basic"
            timeline:
              - t: 1
                type: "bgp_announce"
                prefix: "198.51.100.0/24"
              - t: 3
                type: "bgp_withdraw"
                prefix: "198.51.100.0/24"
            """
            )
            path_a = Path(f_a.name)

        # Create scenario B: More complex attack
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f_b:
            f_b.write(
                """
            id: "scenario-b-advanced"
            timeline:
              - t: 2
                type: "bgp_announce"
                prefix: "203.0.113.0/24"
              - t: 4
                type: "traffic_interception"
                prefix: "203.0.113.0/24"
                bytes: 1000000
              - t: 6
                type: "bgp_withdraw"
                prefix: "203.0.113.0/24"
            """
            )
            path_b = Path(f_b.name)

        try:
            # Shared EventBus for both scenarios
            event_bus = EventBus()

            # Global statistics aggregator
            class GlobalStats:
                def __init__(self):
                    self.scenario_events = {}  # scenario_id -> event_count
                    self.total_events = 0
                    self.prefixes_announced = set()

                def collect_global_stats(self, event):
                    scenario_id = event["scenario_id"]
                    if scenario_id not in self.scenario_events:
                        self.scenario_events[scenario_id] = 0
                    self.scenario_events[scenario_id] += 1
                    self.total_events += 1

                    if event["entry"]["type"] == "bgp_announce":
                        self.prefixes_announced.add(event["entry"]["prefix"])

            # Scenario-specific analyzers
            class ScenarioAAnalyzer:
                def __init__(self):
                    self.events_received = 0

                def analyze_scenario_a(self, event):
                    if event["scenario_id"] == "scenario-a-basic":
                        self.events_received += 1

            class ScenarioBAnalyzer:
                def __init__(self):
                    self.traffic_bytes = 0

                def analyze_scenario_b(self, event):
                    if event["scenario_id"] == "scenario-b-advanced":
                        if event["entry"]["type"] == "traffic_interception":
                            self.traffic_bytes += event["entry"].get("bytes", 0)

            # Instantiate and subscribe
            global_stats = GlobalStats()
            analyzer_a = ScenarioAAnalyzer()
            analyzer_b = ScenarioBAnalyzer()

            event_bus.subscribe(global_stats.collect_global_stats)
            event_bus.subscribe(analyzer_a.analyze_scenario_a)
            event_bus.subscribe(analyzer_b.analyze_scenario_b)

            # ===== EXECUTE SCENARIO A =====
            runner_a = ScenarioRunner(path_a, event_bus)
            runner_a.load()
            runner_a.run(close_bus=False)  # Don't close after first scenario

            # ===== EXECUTE SCENARIO B =====
            runner_b = ScenarioRunner(path_b, event_bus)
            runner_b.load()
            runner_b.run(close_bus=True)  # Close after second scenario

            # ===== INTEGRATION ASSERTIONS =====

            # 1. Verify global stats collected from both scenarios
            assert global_stats.total_events == 5  # 2 from A + 3 from B
            assert set(global_stats.scenario_events.keys()) == {
                "scenario-a-basic",
                "scenario-b-advanced",
            }
            assert global_stats.scenario_events["scenario-a-basic"] == 2
            assert global_stats.scenario_events["scenario-b-advanced"] == 3

            # 2. Verify prefixes from both scenarios
            assert global_stats.prefixes_announced == {
                "198.51.100.0/24",
                "203.0.113.0/24",
            }

            # 3. Verify scenario-specific analyzers worked
            assert analyzer_a.events_received == 2
            assert analyzer_b.traffic_bytes == 1000000

            # 4. Verify EventBus is closed after all scenarios
            assert event_bus._closed is True

            # 5. Verify clocks are independent
            assert runner_a.clock.now() == 3  # Last event time in scenario A
            assert runner_b.clock.now() == 6  # Last event time in scenario B

            # 6. Verify no cross-scenario contamination
            # Each ScenarioRunner has its own clock
            assert runner_a.clock is not runner_b.clock

        finally:
            path_a.unlink()
            path_b.unlink()

    def test_scenario_runner_with_dynamic_subscribers(self):
        """Test ScenarioRunner with subscribers that subscribe during execution."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "dynamic-subscriber-test"
            timeline:
              - t: 1
                type: "phase1"
              - t: 3
                type: "phase2"
              - t: 5
                type: "phase3"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            event_bus = EventBus()

            # Subscriber that adds another subscriber when it sees phase2
            all_events_recorded = []
            late_subscriber_events = []

            def early_subscriber(event):
                all_events_recorded.append(("early", event["entry"]["type"]))

                # When we see phase2, add a late subscriber
                if event["entry"]["type"] == "phase2":

                    def late_subscriber(event):
                        late_subscriber_events.append(event["entry"]["type"])

                    # This tests dynamic subscription during ScenarioRunner execution
                    event_bus.subscribe(late_subscriber)

            event_bus.subscribe(early_subscriber)

            runner = ScenarioRunner(temp_path, event_bus)
            runner.load()
            runner.run(close_bus=True)

            # ===== INTEGRATION ASSERTIONS =====

            # 1. Early subscriber should see all events
            assert len(all_events_recorded) == 3
            assert all_events_recorded[0] == ("early", "phase1")
            assert all_events_recorded[1] == ("early", "phase2")
            assert all_events_recorded[2] == ("early", "phase3")

            # 2. Late subscriber should only see events after it was subscribed
            # It was subscribed during phase2, so should see phase2 and phase3
            assert len(late_subscriber_events) == 2
            assert (
                late_subscriber_events[0] == "phase2"
            )  # The event that triggered subscription
            assert late_subscriber_events[1] == "phase3"

            # 3. Verify EventBus handles dynamic subscriptions correctly
            # The late subscriber was added to the subscribers list while iterating

        finally:
            temp_path.unlink()

    def test_error_scenarios_in_integration(self):
        """Test error handling in integrated ScenarioRunner workflows."""
        # Scenario with intentionally problematic events
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            scenario_content = """
            id: "error-test-scenario"
            timeline:
              - t: 1
                type: "normal_start"
              - t: 2
                type: "problematic_event"
                should_fail: true
              - t: 3
                type: "recovery_event"
              - t: 4
                type: "normal_end"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            event_bus = EventBus()

            # Subscriber that fails on problematic_event
            events_processed = []

            def problematic_subscriber(event):
                if event["entry"].get("should_fail"):
                    raise RuntimeError("Intentional failure in subscriber")
                events_processed.append(event["entry"]["type"])

            # Always-works subscriber
            all_events_seen = []

            def reliable_subscriber(event):
                all_events_seen.append(event["entry"]["type"])

            # Subscribe problematic subscriber FIRST (so it runs first)
            event_bus.subscribe(problematic_subscriber)
            event_bus.subscribe(reliable_subscriber)

            runner = ScenarioRunner(temp_path, event_bus)
            runner.load()

            # ===== TEST ERROR PROPAGATION =====
            with pytest.raises(RuntimeError, match="Intentional failure in subscriber"):
                runner.run(close_bus=True)

            # ===== INTEGRATION ASSERTIONS =====

            # 1. Verify partial execution before error
            # Only normal_start should have been processed by problematic_subscriber
            assert events_processed == ["normal_start"]

            # 2. Verify reliable subscriber saw the failing event
            # (it runs after problematic_subscriber, so shouldn't see problematic_event)
            assert all_events_seen == ["normal_start"]

            # 3. Verify ScenarioRunner state after error
            assert runner.clock.now() == 2  # Only advanced to first event

            # 4. Verify EventBus state
            # Subscribers list should still contain both subscribers
            assert len(event_bus._subscribers) == 2

            # 5. Verify we can reset and retry with fixed subscriber
            # Remove the problematic subscriber
            event_bus._subscribers = event_bus._subscribers[1:]  # Keep only reliable

            # Reset runner
            runner.reset()
            events_processed.clear()
            all_events_seen.clear()

            # Retry - should work now
            runner.run(close_bus=True)

            assert events_processed == []  # Problematic subscriber removed
            assert all_events_seen == [
                "normal_start",
                "problematic_event",
                "recovery_event",
                "normal_end",
            ]
            assert runner.clock.now() == 4

        finally:
            temp_path.unlink()
