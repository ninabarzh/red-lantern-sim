"""
Event bus for the Red Lantern BGP attack-chain simulator.

The event bus is the only mechanism by which scenario events leave the
simulator core. It provides a narrow, explicit boundary between scenario
execution and whatever consumes the emitted events.

The bus does not interpret events. It does not transform them. It does
not decide what they mean. It simply delivers them to registered
subscribers.
"""

from collections.abc import Callable
from typing import Any, Dict, List

Event = dict[str, Any]
Subscriber = Callable[[Event], None]


class EventBus:
    """
    Simple publish-subscribe event bus.

    Subscribers are called synchronously, in the order they were
    registered. If a subscriber raises an exception, propagation stops
    and the error is surfaced to the caller.
    """

    def __init__(self) -> None:
        self._subscribers: list[Subscriber] = []
        self._closed: bool = False

    def subscribe(self, handler: Subscriber) -> None:
        """
        Register a new event handler.
        """
        if self._closed:
            raise RuntimeError("Cannot subscribe to a closed event bus")

        self._subscribers.append(handler)

    def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribers.
        """
        if self._closed:
            raise RuntimeError("Cannot publish to a closed event bus")

        for handler in self._subscribers:
            handler(event)

    def close(self) -> None:
        """
        Close the event bus.

        After closing, no further subscriptions or publications are
        permitted. This provides a clear lifecycle boundary for
        simulations.
        """
        self._closed = True
