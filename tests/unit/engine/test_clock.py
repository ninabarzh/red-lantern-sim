"""
Unit tests for simulator/engine/clock.py
"""

import pytest

from simulator.engine.clock import SimulationClock


class TestSimulationClock:
    """Test suite for the SimulationClock class."""

    def test_initialization(self):
        """Test that clock initializes with time zero."""
        clock = SimulationClock()
        assert clock.now() == 0, "Clock should start at time 0"

    def test_now_returns_current_time(self):
        """Test that now() returns the current simulated time."""
        clock = SimulationClock()
        # Accessing private attribute for testing
        clock._current_time = 42
        assert clock.now() == 42, "now() should return the current time"

    def test_advance_to_positive_time(self):
        """Test advancing the clock to a future time."""
        clock = SimulationClock()
        clock.advance_to(10)
        assert clock.now() == 10, "Clock should advance to the specified time"

    def test_advance_to_float_converts_to_int(self):
        """Test that advance_to converts float inputs to integers."""
        clock = SimulationClock()
        clock.advance_to(5.7)
        assert clock.now() == 5, "Float inputs should be converted to int"
        assert isinstance(clock.now(), int), "Time should remain integer"

    def test_advance_to_same_time(self):
        """Test advancing to the current time (no-op)."""
        clock = SimulationClock()
        clock.advance_to(10)
        clock.advance_to(10)  # Should not raise an error
        assert clock.now() == 10, "Clock should remain at same time"

    def test_advance_to_backwards_raises_error(self):
        """Test that attempting to move backwards raises ValueError."""
        clock = SimulationClock()
        clock.advance_to(10)

        with pytest.raises(ValueError) as exc_info:
            clock.advance_to(5)

        assert "Cannot move clock backwards" in str(exc_info.value)
        assert clock.now() == 10, "Clock time should not change after error"

    def test_advance_to_backwards_with_float(self):
        """Test backwards movement detection with float input."""
        clock = SimulationClock()
        clock.advance_to(10.3)  # Becomes 10

        with pytest.raises(ValueError) as exc_info:
            clock.advance_to(9.8)  # Becomes 9

        assert "Cannot move clock backwards" in str(exc_info.value)
        assert "from 10 to 9" in str(exc_info.value)

    def test_multiple_advancements(self):
        """Test multiple sequential advancements."""
        clock = SimulationClock()

        clock.advance_to(5)
        assert clock.now() == 5

        clock.advance_to(15)
        assert clock.now() == 15

        clock.advance_to(100)
        assert clock.now() == 100

    def test_reset_functionality(self):
        """Test that reset returns clock to time zero."""
        clock = SimulationClock()
        clock.advance_to(42)
        clock.advance_to(100)

        clock.reset()
        assert clock.now() == 0, "Reset should return clock to time 0"

    def test_reset_after_reset(self):
        """Test that reset works multiple times."""
        clock = SimulationClock()

        clock.advance_to(50)
        clock.reset()
        assert clock.now() == 0

        clock.advance_to(30)
        clock.reset()
        assert clock.now() == 0

    def test_large_time_values(self):
        """Test with large time values."""
        clock = SimulationClock()
        large_time = 10**9  # 1 billion seconds

        clock.advance_to(large_time)
        assert clock.now() == large_time

    def test_negative_target_time(self):
        """Test advancing to negative time from zero."""
        clock = SimulationClock()

        with pytest.raises(ValueError) as exc_info:
            clock.advance_to(-1)

        assert "Cannot move clock backwards from 0 to -1" in str(exc_info.value)

    def test_error_message_format(self):
        """Test the format of the error message for backwards movement."""
        clock = SimulationClock()
        clock.advance_to(100)

        try:
            clock.advance_to(50)
        except ValueError as e:
            error_msg = str(e)
            assert "Cannot move clock backwards" in error_msg
            assert "from 100 to 50" in error_msg
            assert error_msg.startswith("Cannot move clock backwards")

    def test_type_hints_present(self):
        """Test that type hints are properly declared."""
        import inspect

        sig = inspect.signature(SimulationClock.now)
        assert sig.return_annotation is int, "now() should return int"

        sig = inspect.signature(SimulationClock.advance_to)
        param = sig.parameters["target_time"]
        # Type annotation might be displayed differently
        annotation = str(param.annotation)
        assert (
            "int" in annotation and "float" in annotation
        ), "advance_to should accept int|float"


# Additional edge case tests
def test_clock_is_deterministic():
    """Test that clock behaves deterministically."""
    clock1 = SimulationClock()
    clock2 = SimulationClock()

    # Same operations should produce same results
    clock1.advance_to(10)
    clock1.advance_to(20)

    clock2.advance_to(10)
    clock2.advance_to(20)

    assert clock1.now() == clock2.now()


def test_clock_interface_stability():
    """Test that the public interface matches expectations."""
    clock = SimulationClock()

    # Test that expected methods exist
    assert hasattr(clock, "now")
    assert hasattr(clock, "advance_to")
    assert hasattr(clock, "reset")

    # Test they are callable
    assert callable(clock.now)
    assert callable(clock.advance_to)
    assert callable(clock.reset)


# Tests for documentation examples
def test_example_usage():
    """Test typical usage patterns from documentation."""
    clock = SimulationClock()

    # Initial state
    assert clock.now() == 0

    # Advance time
    clock.advance_to(5)
    assert clock.now() == 5

    # Advance further
    clock.advance_to(15)
    assert clock.now() == 15

    # Reset
    clock.reset()
    assert clock.now() == 0

    # Start over
    clock.advance_to(100)
    assert clock.now() == 100


def test_zero_advancement():
    """Test advancing to time zero from zero."""
    clock = SimulationClock()
    clock.advance_to(0)  # Should not raise an error
    assert clock.now() == 0


def test_very_small_float_advancement():
    """Test with very small float values."""
    clock = SimulationClock()
    clock.advance_to(0.1)  # Should become 0
    assert clock.now() == 0

    clock.advance_to(1.999)  # Should become 1
    assert clock.now() == 1
