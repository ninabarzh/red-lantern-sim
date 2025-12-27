"""Unit tests for the base Adapter class."""
from typing import Iterable

import pytest

from simulator.output.base import Adapter


class TestAdapterBaseClass:
    """Test the Adapter base class functionality."""

    def test_adapter_can_be_instantiated(self):
        """Test that the Adapter base class can be instantiated."""
        adapter = Adapter()
        assert isinstance(adapter, Adapter)

    def test_transform_method_exists(self):
        """Test that the transform method exists on Adapter."""
        adapter = Adapter()
        assert hasattr(adapter, 'transform')
        assert callable(adapter.transform)

    def test_transform_default_returns_empty_iterable(self):
        """Test that the default transform method returns an empty iterable."""
        adapter = Adapter()
        result = adapter.transform({"event_type": "test", "data": "value"})

        # Should return an empty iterable
        assert hasattr(result, '__iter__')
        result_list = list(result)
        assert result_list == []

    def test_transform_with_empty_event(self):
        """Test transform with empty event dictionary."""
        adapter = Adapter()
        result = adapter.transform({})
        assert list(result) == []

    def test_transform_with_none_event(self):
        """Test transform with None event."""
        adapter = Adapter()
        result = adapter.transform(None)  # type: ignore
        # Should handle None gracefully or raise TypeError
        # Base implementation returns empty iterable regardless
        assert list(result) == []

    def test_adapter_is_abstract_in_spirit(self):
        """Test that Adapter is meant to be subclassed (though not formally abstract)."""
        adapter = Adapter()

        # Calling transform should work but return empty
        event = {"event_type": "test"}
        result = adapter.transform(event)
        assert list(result) == []

    def test_subclass_can_override_transform(self):
        """Test that subclasses can properly override the transform method."""

        class TestAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                return [f"Transformed: {event.get('data', 'no-data')}"]

        adapter = TestAdapter()
        result = adapter.transform({"data": "test_value"})
        result_list = list(result)

        assert result_list == ["Transformed: test_value"]

    def test_subclass_returns_iterator(self):
        """Test that subclasses can return different iterable types."""

        class ListAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                return ["line1", "line2"]  # Returns list

        class GeneratorAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                yield "line1"
                yield "line2"

        class TupleAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                return "line1", "line2"  # Returns tuple

        # Test all return types work
        list_adapter = ListAdapter()
        gen_adapter = GeneratorAdapter()
        tuple_adapter = TupleAdapter()

        assert list(list_adapter.transform({})) == ["line1", "line2"]
        assert list(gen_adapter.transform({})) == ["line1", "line2"]
        assert list(tuple_adapter.transform({})) == ["line1", "line2"]

    def test_transform_signature(self):
        """Test that transform accepts a dict parameter."""
        adapter = Adapter()

        # Should accept dict
        result = adapter.transform({"key": "value"})
        assert list(result) == []

        # Should also accept dict with any structure
        complex_event = {
            "event_type": "complex",
            "timestamp": 1234567890,
            "attributes": {"nested": "data"},
            "source": "test"
        }
        result = adapter.transform(complex_event)
        assert list(result) == []

    @pytest.mark.parametrize("event_input", [
        {"simple": "event"},
        {"nested": {"deep": "data"}},
        {"list_data": [1, 2, 3]},
        {"mixed": {"str": "value", "int": 42, "bool": True}},
        {},  # Empty dict
    ])
    def test_transform_with_various_inputs(self, event_input):
        """Test transform with various event dictionary structures."""
        adapter = Adapter()
        result = adapter.transform(event_input)
        # Base implementation should handle any dict
        assert list(result) == []


class TestAdapterInheritance:
    """Test Adapter class inheritance behavior."""

    def test_is_instance_check(self):
        """Test that subclasses are instances of Adapter."""

        class CustomAdapter(Adapter):
            pass

        custom = CustomAdapter()
        assert isinstance(custom, Adapter)
        assert isinstance(custom, CustomAdapter)

    def test_method_resolution(self):
        """Test method resolution order for transform method."""

        class ParentAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                return ["parent"]

        class ChildAdapter(ParentAdapter):
            def transform(self, event: dict) -> Iterable[str]:
                return ["child"]

        parent = ParentAdapter()
        child = ChildAdapter()

        assert list(parent.transform({})) == ["parent"]
        assert list(child.transform({})) == ["child"]

    def test_adapter_with_additional_methods(self):
        """Test that subclasses can add additional methods."""

        class EnhancedAdapter(Adapter):
            def transform(self, event: dict) -> Iterable[str]:
                return [self._enhance(event.get("data", ""))]

            @staticmethod
            def _enhance(text: str) -> str:
                return f"ENHANCED: {text.upper()}"

        adapter = EnhancedAdapter()
        result = adapter.transform({"data": "hello"})

        assert list(result) == ["ENHANCED: HELLO"]


def test_adapter_type_annotations():
    """Test that Adapter has proper type annotations."""
    from typing import get_type_hints

    # get_type_hints resolves string annotations to actual types
    hints = get_type_hints(Adapter.transform)

    # Return type should be Iterable[str]
    assert hints.get('return') == Iterable[str]

    # Event parameter should be dict type
    assert hints.get('event') == dict


def test_adapter_as_interface():
    """Test that Adapter serves as a proper interface for all adapters."""

    # This is more of a design verification test

    class TestAdapter1(Adapter):
        def transform(self, event: dict) -> Iterable[str]:
            return []

    class TestAdapter2(Adapter):
        def transform(self, event: dict) -> Iterable[str]:
            yield from []

    # Both should be usable interchangeably
    adapters = [TestAdapter1(), TestAdapter2()]

    for adapter in adapters:
        result = adapter.transform({"test": "event"})
        assert hasattr(result, '__iter__')
        lines = list(result)
        assert isinstance(lines, list)
        assert all(isinstance(line, str) for line in lines)
