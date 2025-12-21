"""
Integration tests for EventBus with other components.
Tests how EventBus interacts with real systems and components.
"""
import tempfile
from pathlib import Path

import pytest

from simulator.engine.event_bus import EventBus
from simulator.engine.scenario_runner import ScenarioRunner

# from simulator.engine.clock import SimulationClock


class TestEventBusIntegration:
    """Integration tests for EventBus in system context."""

    def test_eventbus_in_full_simulation_workflow(self):
        """Test EventBus as communication hub in complete simulation."""
        # Create multiple components that communicate via EventBus
        event_bus = EventBus()

        # Component 1: Simulation Monitor
        class SimulationMonitor:
            def __init__(self):
                self.events_by_type = {}
                self.timeline = []

            def track_event(self, event):
                event_type = event['entry']['type']
                if event_type not in self.events_by_type:
                    self.events_by_type[event_type] = []
                self.events_by_type[event_type].append(event['timestamp'])
                self.timeline.append((event['timestamp'], event_type))

        # Component 2: Metrics Collector
        class MetricsCollector:
            def __init__(self):
                self.metrics = {
                    'event_count': 0,
                    'total_time': 0,
                    'last_timestamp': 0
                }

            def collect_metrics(self, event):
                self.metrics['event_count'] += 1
                timestamp = event['timestamp']
                if timestamp > self.metrics['last_timestamp']:
                    self.metrics['total_time'] = timestamp
                    self.metrics['last_timestamp'] = timestamp

        # Component 3: Alert System
        class AlertSystem:
            def __init__(self):
                self.alerts = []
                self.critical_events = {'attack_detected', 'traffic_interception'}

            def check_alerts(self, event):
                if event['entry']['type'] in self.critical_events:
                    self.alerts.append({
                        'time': event['timestamp'],
                        'type': event['entry']['type'],
                        'scenario': event['scenario_id']
                    })

        # Instantiate components
        monitor = SimulationMonitor()
        metrics = MetricsCollector()
        alerts = AlertSystem()

        # Subscribe all components to EventBus
        event_bus.subscribe(monitor.track_event)
        event_bus.subscribe(metrics.collect_metrics)
        event_bus.subscribe(alerts.check_alerts)

        # Create a scenario file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            scenario_content = """
            id: "eventbus-integration-test"
            description: "Test EventBus with multiple components"
            timeline:
              - t: 0
                type: "simulation_start"
              - t: 5
                type: "bgp_announce"
                prefix: "198.51.100.0/24"
              - t: 10
                type: "traffic_interception"
                bytes: 500000
              - t: 15
                type: "bgp_propagation"
                hops: 2
              - t: 20
                type: "attack_detected"
                confidence: 0.9
              - t: 25
                type: "bgp_withdraw"
                prefix: "198.51.100.0/24"
              - t: 30
                type: "simulation_end"
            """
            f.write(scenario_content)
            temp_path = Path(f.name)

        try:
            # Create ScenarioRunner with the shared EventBus
            runner = ScenarioRunner(temp_path, event_bus)
            runner.load()
            runner.run(close_bus=True)

            # ===== INTEGRATION ASSERTIONS =====

            # 1. Verify all components received all events
            assert metrics.metrics['event_count'] == 7  # All timeline events
            assert metrics.metrics['total_time'] == 30  # Final timestamp
            assert len(monitor.timeline) == 7

            # 2. Verify EventBus distributed events correctly
            assert len(monitor.events_by_type['bgp_announce']) == 1
            assert monitor.events_by_type['bgp_announce'][0] == 5
            assert len(monitor.events_by_type['bgp_withdraw']) == 1
            assert monitor.events_by_type['bgp_withdraw'][0] == 25

            # 3. Verify Alert System detected critical events
            assert len(alerts.alerts) == 2  # traffic_interception and attack_detected
            assert alerts.alerts[0]['type'] == 'traffic_interception'
            assert alerts.alerts[0]['time'] == 10
            assert alerts.alerts[1]['type'] == 'attack_detected'
            assert alerts.alerts[1]['time'] == 20

            # 4. Verify EventBus is closed (integration with ScenarioRunner)
            with pytest.raises(RuntimeError, match="Cannot subscribe"):
                event_bus.subscribe(lambda e: None)

            # 5. Verify time progression through components
            assert monitor.timeline[0] == (0, 'simulation_start')
            assert monitor.timeline[-1] == (30, 'simulation_end')

        finally:
            temp_path.unlink()

    def test_eventbus_with_multiple_independent_consumers(self):
        """Test EventBus with independent, decoupled consumers."""
        event_bus = EventBus()

        # Consumer 1: File Logger (simulates writing to log file)
        logged_events = []

        def file_logger(event):
            logged_events.append(f"{event['timestamp']}: {event['entry']['type']}")

        # Consumer 2: Statistics Aggregator
        stats = {'count': 0, 'types': set()}

        def stats_aggregator(event):
            stats['count'] += 1
            stats['types'].add(event['entry']['type'])

        # Consumer 3: Real-time Dashboard Updater
        dashboard_updates = []

        def dashboard_updater(event):
            if event['entry']['type'] in ['bgp_announce', 'bgp_withdraw']:
                dashboard_updates.append({
                    'time': event['timestamp'],
                    'event': event['entry']['type'],
                    'prefix': event['entry'].get('prefix', 'N/A')
                })

        # Subscribe all consumers
        event_bus.subscribe(file_logger)
        event_bus.subscribe(stats_aggregator)
        event_bus.subscribe(dashboard_updater)

        # Manually publish events (simulating ScenarioRunner or other sources)
        events_to_publish = [
            {'timestamp': 0, 'scenario_id': 'test', 'entry': {'t': 0, 'type': 'start'}},
            {'timestamp': 5, 'scenario_id': 'test',
             'entry': {'t': 5, 'type': 'bgp_announce', 'prefix': '203.0.113.0/24'}},
            {'timestamp': 10, 'scenario_id': 'test', 'entry': {'t': 10, 'type': 'traffic_flow', 'bps': 1000}},
            {'timestamp': 15, 'scenario_id': 'test',
             'entry': {'t': 15, 'type': 'bgp_withdraw', 'prefix': '203.0.113.0/24'}},
            {'timestamp': 20, 'scenario_id': 'test', 'entry': {'t': 20, 'type': 'end'}},
        ]

        for event in events_to_publish:
            event_bus.publish(event)

        # ===== INTEGRATION ASSERTIONS =====

        # 1. Verify all consumers received all events
        assert len(logged_events) == 5
        assert logged_events[0] == "0: start"
        assert logged_events[-1] == "20: end"

        # 2. Verify stats aggregator collected correct statistics
        assert stats['count'] == 5
        assert stats['types'] == {'start', 'bgp_announce', 'traffic_flow', 'bgp_withdraw', 'end'}

        # 3. Verify dashboard only got relevant events
        assert len(dashboard_updates) == 2
        assert dashboard_updates[0]['event'] == 'bgp_announce'
        assert dashboard_updates[0]['prefix'] == '203.0.113.0/24'
        assert dashboard_updates[1]['event'] == 'bgp_withdraw'

        # 4. Verify EventBus maintains separation of concerns
        # Each consumer processes events independently
        assert file_logger != stats_aggregator != dashboard_updater

        # 5. Verify EventBus still functional after all events
        # Add another consumer dynamically
        late_consumer_data = []

        def late_consumer(event):
            late_consumer_data.append(event['entry']['type'])

        event_bus.subscribe(late_consumer)

        # Publish one more event
        event_bus.publish({'timestamp': 25, 'scenario_id': 'test',
                           'entry': {'t': 25, 'type': 'late_event'}})

        # Late consumer should only get the late event
        assert late_consumer_data == ['late_event']
        # Original consumers should get it too
        assert len(logged_events) == 6
        assert stats['count'] == 6

    def test_eventbus_error_handling_in_integration(self):
        """Test how EventBus error propagation affects integrated systems."""
        event_bus = EventBus()

        # Component 1: Reliable Logger (never fails)
        log_entries = []

        def reliable_logger(event):
            log_entries.append(f"LOG: {event['entry']['type']}")

        # Component 2: Unreliable Processor (may fail)
        processed_events = []

        def unreliable_processor(event):
            if event['entry']['type'] == 'problematic':
                raise RuntimeError("Processor failed!")
            processed_events.append(event['entry']['type'])

        # Component 3: Critical Monitor
        monitored_events = []

        def critical_monitor(event):
            monitored_events.append(event['entry']['type'])

        # Subscribe components
        event_bus.subscribe(reliable_logger)
        event_bus.subscribe(unreliable_processor)  # This one might fail
        event_bus.subscribe(critical_monitor)

        # Test 1: Normal event should reach all components
        normal_event = {'timestamp': 1, 'scenario_id': 'test',
                        'entry': {'t': 1, 'type': 'normal'}}
        event_bus.publish(normal_event)

        assert len(log_entries) == 1
        assert len(processed_events) == 1
        assert len(monitored_events) == 1

        # Test 2: Problematic event should fail and stop propagation
        problematic_event = {'timestamp': 2, 'scenario_id': 'test',
                             'entry': {'t': 2, 'type': 'problematic'}}

        with pytest.raises(RuntimeError, match="Processor failed!"):
            event_bus.publish(problematic_event)

        # Logger should have been called (it's before the failing processor)
        assert len(log_entries) == 2

        # But critical monitor should NOT be called (it's after the failing processor)
        assert len(monitored_events) == 1  # Still only the first event

        # Test 3: Events after failure should still work
        another_event = {'timestamp': 3, 'scenario_id': 'test',
                         'entry': {'t': 3, 'type': 'recovery'}}
        event_bus.publish(another_event)

        # All components should receive this
        assert len(log_entries) == 3
        assert len(processed_events) == 2  # problematic wasn't processed
        assert len(monitored_events) == 2  # recovery event was monitored

        # Verify integration: Error in one component doesn't break entire system
        assert 'normal' in processed_events
        assert 'recovery' in processed_events
        assert 'problematic' not in processed_events

    def test_eventbus_performance_integration(self):
        """Test EventBus performance characteristics with many subscribers."""
        event_bus = EventBus()

        # Create many subscribers (simulating large system)
        subscriber_results = []
        for i in range(100):  # 100 subscribers
            def make_subscriber(idx):
                def subscriber(event):
                    subscriber_results.append((idx, event['entry']['type']))

                return subscriber

            event_bus.subscribe(make_subscriber(i))

        # Add a few specialized subscribers
        bgp_events = []

        def bgp_specialist(event):
            if 'bgp' in event['entry']['type']:
                bgp_events.append(event['entry']['type'])

        traffic_events = []

        def traffic_specialist(event):
            if 'traffic' in event['entry']['type']:
                traffic_events.append(event['entry']['type'])

        event_bus.subscribe(bgp_specialist)
        event_bus.subscribe(traffic_specialist)

        # Publish a mix of events
        events = [
            {'timestamp': i, 'scenario_id': 'perf-test',
             'entry': {'t': i, 'type': f'event_{i}'}}
            for i in range(10)
        ]

        # Insert some specialized events
        events[3]['entry']['type'] = 'bgp_announce'
        events[7]['entry']['type'] = 'traffic_flow'

        # Publish all events
        for event in events:
            event_bus.publish(event)

        # ===== INTEGRATION ASSERTIONS =====

        # 1. Verify all subscribers got all events
        # 102 subscribers × 10 events = 1020 total calls
        assert len(subscriber_results) == 100 * 10  # 100 general subscribers

        # 2. Verify specialized subscribers only got relevant events
        assert len(bgp_events) == 1
        assert bgp_events[0] == 'bgp_announce'

        assert len(traffic_events) == 1
        assert traffic_events[0] == 'traffic_flow'

        # 3. Verify order is maintained across all subscribers
        # First event should be received by all subscribers first
        first_event_indices = [idx for idx, typ in subscriber_results if typ == 'event_0']
        assert len(first_event_indices) == 100  # All 100 subscribers

        # 4. Verify EventBus can handle load
        # No errors should occur
        assert event_bus._closed is False

        # 5. Test closing bus with many subscribers
        event_bus.close()
        assert event_bus._closed is True

        # Verify new subscriptions are rejected
        with pytest.raises(RuntimeError):
            event_bus.subscribe(lambda e: None)
