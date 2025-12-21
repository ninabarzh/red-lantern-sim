"""
Unit tests for simulator/engine/event_bus.py
"""
import inspect

import pytest

from simulator.engine.event_bus import EventBus


class TestEventBus:
    """Test suite for the EventBus class."""

    def test_initialization(self):
        """Test that EventBus initializes with empty subscribers and not closed."""
        bus = EventBus()
        assert bus._subscribers == []
        assert bus._closed is False

    def test_subscribe_adds_handler(self):
        """Test that subscribe adds a handler to the subscribers list."""
        bus = EventBus()

        def handler1(_):
            pass

        def handler2(_):
            pass

        bus.subscribe(handler1)
        assert len(bus._subscribers) == 1
        assert bus._subscribers[0] is handler1

        bus.subscribe(handler2)
        assert len(bus._subscribers) == 2
        assert bus._subscribers[1] is handler2

    def test_subscribe_raises_error_when_closed(self):
        """Test that subscribe raises RuntimeError when bus is closed."""
        bus = EventBus()
        bus.close()

        def handler(_):
            pass

        with pytest.raises(RuntimeError) as exc_info:
            bus.subscribe(handler)

        assert "Cannot subscribe to a closed event bus" in str(exc_info.value)

    def test_publish_delivers_to_all_subscribers(self):
        """Test that publish calls all subscribed handlers with the event."""
        bus = EventBus()

        received_events = []

        def handler1(event):
            received_events.append(("handler1", event))

        def handler2(event):
            received_events.append(("handler2", event))

        bus.subscribe(handler1)
        bus.subscribe(handler2)

        test_event = {"type": "test_event", "data": "test_data"}
        bus.publish(test_event)

        assert len(received_events) == 2
        assert received_events[0] == ("handler1", test_event)
        assert received_events[1] == ("handler2", test_event)

    def test_publish_calls_subscribers_in_order(self):
        """Test that publish calls subscribers in the order they were registered."""
        bus = EventBus()

        call_order = []

        def make_handler(name):
            def handler(_):
                call_order.append(name)
            return handler

        handler_a = make_handler("A")
        handler_b = make_handler("B")
        handler_c = make_handler("C")

        bus.subscribe(handler_a)
        bus.subscribe(handler_b)
        bus.subscribe(handler_c)

        bus.publish({"type": "order_test"})

        assert call_order == ["A", "B", "C"]

    def test_publish_with_no_subscribers(self):
        """Test that publish works correctly when there are no subscribers."""
        bus = EventBus()

        # Should not raise any exception
        bus.publish({"type": "test"})

    def test_publish_raises_error_when_closed(self):
        """Test that publish raises RuntimeError when bus is closed."""
        bus = EventBus()

        def handler(_):
            pass

        bus.subscribe(handler)
        bus.close()

        with pytest.raises(RuntimeError) as exc_info:
            bus.publish({"type": "test"})

        assert "Cannot publish to a closed event bus" in str(exc_info.value)

    def test_publish_propagates_subscriber_exceptions(self):
        """Test that exceptions from subscribers are propagated to the caller."""
        bus = EventBus()

        def failing_handler(_):
            raise ValueError("Handler failed")

        def successful_handler(_):
            pass  # This should never be called

        bus.subscribe(failing_handler)
        bus.subscribe(successful_handler)

        with pytest.raises(ValueError) as exc_info:
            bus.publish({"type": "test"})

        assert "Handler failed" in str(exc_info.value)

    def test_publish_stops_on_first_exception(self):
        """Test that publish stops calling subscribers when one raises an exception."""
        bus = EventBus()

        call_log = []

        def handler1(_):
            call_log.append("handler1")
            raise RuntimeError("First handler failed")

        def handler2(_):
            call_log.append("handler2")  # Should not be called

        bus.subscribe(handler1)
        bus.subscribe(handler2)

        with pytest.raises(RuntimeError):
            bus.publish({"type": "test"})

        assert call_log == ["handler1"]

    def test_close_sets_closed_flag(self):
        """Test that close sets the _closed flag to True."""
        bus = EventBus()
        assert bus._closed is False

        bus.close()
        assert bus._closed is True

    def test_close_is_idempotent(self):
        """Test that calling close multiple times doesn't cause issues."""
        bus = EventBus()

        bus.close()
        assert bus._closed is True

        # Should not raise an error
        bus.close()
        assert bus._closed is True

    def test_close_does_not_clear_subscribers(self):
        """Test that close doesn't remove existing subscribers."""
        bus = EventBus()

        def handler(_):
            pass

        bus.subscribe(handler)
        bus.close()

        # Subscribers should still be there
        assert len(bus._subscribers) == 1
        assert bus._subscribers[0] is handler


class TestEventBusIntegration:
    """Integration tests for EventBus usage patterns."""

    def test_multiple_events_multiple_subscribers(self):
        """Test complex scenario with multiple events and subscribers."""
        bus = EventBus()

        all_received = []

        def handler1(event):
            all_received.append(("handler1", event["type"], event.get("value")))

        def handler2(event):
            all_received.append(("handler2", event["type"], event.get("value")))

        bus.subscribe(handler1)
        bus.subscribe(handler2)

        # Publish multiple events
        bus.publish({"type": "start", "value": 1})
        bus.publish({"type": "progress", "value": 50})
        bus.publish({"type": "complete", "value": 100})

        expected = [
            ("handler1", "start", 1),
            ("handler2", "start", 1),
            ("handler1", "progress", 50),
            ("handler2", "progress", 50),
            ("handler1", "complete", 100),
            ("handler2", "complete", 100),
        ]

        assert all_received == expected

    def test_lambda_subscribers(self):
        """Test that lambda functions can be used as subscribers."""
        bus = EventBus()

        results = []

        bus.subscribe(lambda e: results.append(("lambda1", e["id"])))
        bus.subscribe(lambda e: results.append(("lambda2", e["id"])))

        bus.publish({"id": "test1", "type": "event"})
        bus.publish({"id": "test2", "type": "event"})

        assert results == [
            ("lambda1", "test1"),
            ("lambda2", "test1"),
            ("lambda1", "test2"),
            ("lambda2", "test2"),
        ]

    def test_class_method_as_subscriber(self):
        """Test using class methods as subscribers."""
        bus = EventBus()

        class EventReceiver:
            def __init__(self):
                self.received = []

            def handle_event(self, event):
                self.received.append(event["type"])

        receiver1 = EventReceiver()
        receiver2 = EventReceiver()

        bus.subscribe(receiver1.handle_event)
        bus.subscribe(receiver2.handle_event)

        bus.publish({"type": "event1"})
        bus.publish({"type": "event2"})

        assert receiver1.received == ["event1", "event2"]
        assert receiver2.received == ["event1", "event2"]

    def test_subscriber_modifies_event(self):
        """Test that subscribers can modify the event (though not recommended)."""
        bus = EventBus()

        modified_events = []

        def modifier(event):
            event["modified"] = True
            modified_events.append(event.copy())

        bus.subscribe(modifier)

        test_event = {"type": "test", "original": True}
        bus.publish(test_event)

        # Check that the event was modified
        assert len(modified_events) == 1
        assert modified_events[0]["modified"] is True
        assert modified_events[0]["original"] is True


def test_event_bus_lifecycle():
    """Test the complete lifecycle of an EventBus."""
    bus = EventBus()

    events_log = []

    def logger(event):
        events_log.append(event["type"])

    # Phase 1: Subscribe and publish
    bus.subscribe(logger)
    bus.publish({"type": "event1"})
    bus.publish({"type": "event2"})

    # Phase 2: Close
    bus.close()

    # Phase 3: Attempt operations after close (should fail)
    with pytest.raises(RuntimeError) as exc_info1:
        bus.subscribe(logger)
    assert "Cannot subscribe" in str(exc_info1.value)

    with pytest.raises(RuntimeError) as exc_info2:
        bus.publish({"type": "event3"})
    assert "Cannot publish" in str(exc_info2.value)

    # Verify what succeeded
    assert events_log == ["event1", "event2"]


def test_type_hints():
    """Test that type hints are properly declared."""
    # Check EventBus method signatures
    sig = inspect.signature(EventBus.subscribe)
    assert "handler" in sig.parameters
    param = sig.parameters["handler"]

    # The annotation should be a Callable that takes a dict[str, Any] and returns None
    annotation_str = str(param.annotation)
    # Check it's a Callable type
    assert "Callable" in annotation_str
    # Check it returns None
    assert "None" in annotation_str

    sig = inspect.signature(EventBus.publish)
    assert "event" in sig.parameters
    param = sig.parameters["event"]
    annotation_str = str(param.annotation)
    # Should be dict[str, Any] or Event
    assert "dict[str," in annotation_str or "Event" in annotation_str


def test_module_imports():
    """Test that the module exports the expected names."""
    import simulator.engine.event_bus as event_bus_module

    # Check that the module exports the expected names
    assert hasattr(event_bus_module, 'EventBus')
    assert hasattr(event_bus_module, 'Event')
    assert hasattr(event_bus_module, 'Subscriber')

    # EventBus should be a class
    assert isinstance(event_bus_module.EventBus, type)


def test_closure_captures_state():
    """Test that closures in subscribers capture their state correctly."""
    bus = EventBus()

    results = []

    for i in range(3):
        # Each closure captures a different value of i
        def make_handler(index):
            def handler(_):
                results.append(index)
            return handler

        bus.subscribe(make_handler(i))

    bus.publish({"type": "test"})

    assert results == [0, 1, 2]
