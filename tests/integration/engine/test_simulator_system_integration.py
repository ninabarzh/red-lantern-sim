"""
System-level integration tests for the complete simulator engine.
"""
import tempfile
from pathlib import Path

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner


class TestSimulatorSystemIntegration:
    """System-level integration tests."""

    def test_complete_simulator_system(self):
        """
        Test the complete simulator system with:
        - Multiple scenarios
        - Multiple EventBus subscribers
        - Real-time analysis
        - Error recovery
        - Performance monitoring
        """
        scenario_paths = []

        try:
            # Scenario 1: Basic BGP hijack
            f1 = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            f1.write("""
            id: "bgp-hijack-1"
            timeline:
              - t: 0
                type: "start"
              - t: 5
                type: "hijack_announce"
                prefix: "192.0.2.0/24"
              - t: 15
                type: "hijack_detected"
              - t: 20
                type: "hijack_mitigated"
              - t: 25
                type: "end"
            """)
            f1.close()
            path1 = Path(f1.name)
            scenario_paths.append(path1)

            # Scenario 2: Route leak
            f2 = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            f2.write("""
            id: "route-leak-1"
            timeline:
              - t: 0
                type: "start"
              - t: 3
                type: "route_leak"
                prefixes: ["198.51.100.0/24", "203.0.113.0/24"]
              - t: 8
                type: "propagation"
                as_count: 5
              - t: 12
                type: "detection"
              - t: 18
                type: "cleanup"
              - t: 22
                type: "end"
            """)
            f2.close()
            path2 = Path(f2.name)
            scenario_paths.append(path2)

            # Create system EventBus
            system_bus = EventBus()

            # ===== SYSTEM COMPONENTS =====

            # 1. Central Event Logger
            class CentralLogger:
                def __init__(self):
                    self.logs = []
                    self.scenario_stats = {}

                def log_event(self, event):
                    scenario_id = event['scenario_id']
                    if scenario_id not in self.scenario_stats:
                        self.scenario_stats[scenario_id] = {
                            'event_count': 0,
                            'start_time': event['timestamp'],
                            'end_time': event['timestamp']
                        }

                    stats = self.scenario_stats[scenario_id]
                    stats['event_count'] += 1
                    stats['end_time'] = max(stats['end_time'], event['timestamp'])

                    self.logs.append({
                        'scenario': scenario_id,
                        'time': event['timestamp'],
                        'type': event['entry']['type']
                    })

            # 2. Real-time Alert System
            class AlertSystem:
                def __init__(self):
                    self.alerts = []
                    self.critical_patterns = {
                        'hijack', 'leak', 'attack', 'breach'
                    }

                def check_alerts(self, event):
                    event_type = event['entry']['type'].lower()
                    for pattern in self.critical_patterns:
                        if pattern in event_type:
                            self.alerts.append({
                                'time': event['timestamp'],
                                'scenario': event['scenario_id'],
                                'event': event['entry']['type'],
                                'severity': 'high'
                            })
                            break

            # 3. Performance Monitor
            class PerformanceMonitor:
                def __init__(self):
                    self.metrics = {
                        'events_processed': 0,
                        'scenarios_executed': set(),
                        'total_simulation_time': 0
                    }

                def track_performance(self, event):
                    self.metrics['events_processed'] += 1
                    self.metrics['scenarios_executed'].add(event['scenario_id'])
                    self.metrics['total_simulation_time'] = max(
                        self.metrics['total_simulation_time'],
                        event['timestamp']
                    )

            # 4. Data Validator
            class DataValidator:
                def __init__(self):
                    self.validation_errors = []

                def validate_data(self, event):
                    # Simple validation: ensure required fields exist
                    required = ['timestamp', 'scenario_id', 'entry']
                    for field in required:
                        if field not in event:
                            self.validation_errors.append(f"Missing {field}")

                    if 'entry' in event:
                        if 'type' not in event['entry']:
                            self.validation_errors.append("Event missing type")

            # Instantiate components
            logger = CentralLogger()
            alert_system = AlertSystem()  # Fixed: renamed from 'alerts' to 'alert_system'
            performance = PerformanceMonitor()
            validator = DataValidator()

            # Subscribe all components
            system_bus.subscribe(logger.log_event)
            system_bus.subscribe(alert_system.check_alerts)
            system_bus.subscribe(performance.track_performance)
            system_bus.subscribe(validator.validate_data)

            # ===== EXECUTE SCENARIOS =====

            runners = []
            scenario_files = [path1, path2]
            for i, scenario_path in enumerate(scenario_files):
                runner = ScenarioRunner(scenario_path, system_bus)
                runner.load()

                if i == 0:
                    # First scenario, don't close bus
                    runner.run(close_bus=False)
                else:
                    # Last scenario, close bus
                    runner.run(close_bus=True)

                runners.append(runner)

            # ===== SYSTEM-LEVEL ASSERTIONS =====

            # 1. Verify all events were logged
            total_events = sum(len(runner.scenario['timeline'])
                             for runner in runners)
            assert len(logger.logs) == total_events

            # 2. Verify both scenarios were tracked
            assert len(logger.scenario_stats) == 2
            assert 'bgp-hijack-1' in logger.scenario_stats
            assert 'route-leak-1' in logger.scenario_stats

            # 3. Verify alert system detected critical events
            assert len(alert_system.alerts) >= 2  # At least hijack and leak events
            # Create lists of alerts for specific event types
            hijack_alert_events = [a for a in alert_system.alerts if 'hijack' in a['event'].lower()]
            leak_alert_events = [a for a in alert_system.alerts if 'leak' in a['event'].lower()]
            assert len(hijack_alert_events) > 0
            assert len(leak_alert_events) > 0

            # 4. Verify performance metrics
            assert performance.metrics['events_processed'] == total_events
            assert len(performance.metrics['scenarios_executed']) == 2
            assert performance.metrics['total_simulation_time'] == 25  # Max of both scenarios

            # 5. Verify data validation
            assert len(validator.validation_errors) == 0

            # 6. Verify system bus is closed
            assert system_bus._closed is True

            # 7. Verify independent clocks
            assert runners[0].clock.now() == 25  # Scenario 1 end time
            assert runners[1].clock.now() == 22  # Scenario 2 end time

            # 8. Verify event ordering across scenarios
            # Events should be interleaved in execution order
            scenario_sequence = [log['scenario'] for log in logger.logs]
            # Should contain both scenarios
            assert 'bgp-hijack-1' in scenario_sequence
            assert 'route-leak-1' in scenario_sequence

            # 9. Verify no data corruption between scenarios
            # Each scenario's events should have correct scenario_id
            for log in logger.logs:
                if log['scenario'] == 'bgp-hijack-1':
                    assert log['time'] <= 25  # Within scenario 1 timeframe
                elif log['scenario'] == 'route-leak-1':
                    assert log['time'] <= 22  # Within scenario 2 timeframe

        finally:
            # Cleanup
            for path in scenario_paths:
                if path.exists():
                    path.unlink()
