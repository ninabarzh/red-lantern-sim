"""
Unit tests for simulator/feeds/bgp/mock_feed.py
"""

import pytest

from simulator.feeds.bgp.mock_feed import MockBGPFeed


class TestMockBGPFeed:
    """Test suite for the MockBGPFeed class."""

    def test_initialization(self):
        """Test that MockBGPFeed initializes with empty routes."""
        feed = MockBGPFeed()
        assert feed._routes == {}

    def test_add_route_basic(self):
        """Test adding a basic route."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="192.0.2.0/24", origin_as=65530, as_path=[65530, 65531, 65532]
        )

        assert "192.0.2.0/24" in feed._routes
        route = feed._routes["192.0.2.0/24"]
        assert route["origin_as"] == 65530
        assert route["as_path"] == [65530, 65531, 65532]
        assert route["collectors"] == ["routeviews", "ris"]

    def test_add_route_with_custom_collectors(self):
        """Test adding a route with custom collectors."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="203.0.113.0/24",
            origin_as=64512,
            as_path=[64512],
            collectors=["routeviews", "ris", "custom_collector"],
        )

        route = feed._routes["203.0.113.0/24"]
        assert route["origin_as"] == 64512
        assert route["as_path"] == [64512]
        assert route["collectors"] == ["routeviews", "ris", "custom_collector"]

    def test_add_route_empty_collectors_default(self):
        """Test that None collectors uses default value."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="198.51.100.0/24",
            origin_as=64496,
            as_path=[64496, 64497],
            collectors=None,
        )

        route = feed._routes["198.51.100.0/24"]
        assert route["collectors"] == ["routeviews", "ris"]

    def test_add_route_overwrites_existing(self):
        """Test that adding a route with same prefix overwrites previous."""
        feed = MockBGPFeed()

        # Add first route
        feed.add_route(prefix="192.0.2.0/24", origin_as=65530, as_path=[65530, 65531])

        # Overwrite with new route
        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65540,
            as_path=[65540],
            collectors=["custom"],
        )

        route = feed._routes["192.0.2.0/24"]
        assert route["origin_as"] == 65540  # New value
        assert route["as_path"] == [65540]  # New value
        assert route["collectors"] == ["custom"]  # New value

    def test_expected_origin_existing_prefix(self):
        """Test expected_origin for existing prefix."""
        feed = MockBGPFeed()
        feed.add_route(prefix="192.0.2.0/24", origin_as=65530, as_path=[65530, 65531])

        result = feed.expected_origin("192.0.2.0/24")
        assert result == 65530

    def test_expected_origin_nonexistent_prefix(self):
        """Test expected_origin for non-existent prefix."""
        feed = MockBGPFeed()

        result = feed.expected_origin("10.0.0.0/8")
        assert result is None

    def test_expected_as_path_existing_prefix(self):
        """Test expected_as_path for existing prefix."""
        feed = MockBGPFeed()
        expected_path = [65530, 65531, 65532]
        feed.add_route(prefix="192.0.2.0/24", origin_as=65530, as_path=expected_path)

        result = feed.expected_as_path("192.0.2.0/24")
        assert result == expected_path

    def test_expected_as_path_nonexistent_prefix(self):
        """Test expected_as_path for non-existent prefix."""
        feed = MockBGPFeed()

        result = feed.expected_as_path("10.0.0.0/8")
        assert result is None

    def test_visibility_existing_prefix(self):
        """Test visibility for existing prefix."""
        feed = MockBGPFeed()
        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65530,
            as_path=[65530],
            collectors=["routeviews", "ris", "collector3", "collector4"],
        )

        result = feed.visibility("192.0.2.0/24")
        assert result == 4

    def test_visibility_default_collectors(self):
        """Test visibility with default collectors."""
        feed = MockBGPFeed()
        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65530,
            as_path=[65530],  # Default collectors will be used
        )

        result = feed.visibility("192.0.2.0/24")
        assert result == 2  # ["routeviews", "ris"]

    def test_visibility_nonexistent_prefix(self):
        """Test visibility for non-existent prefix."""
        feed = MockBGPFeed()

        result = feed.visibility("10.0.0.0/8")
        assert result == 0

    def test_is_known_prefix_existing(self):
        """Test is_known_prefix for existing prefix."""
        feed = MockBGPFeed()
        feed.add_route(prefix="192.0.2.0/24", origin_as=65530, as_path=[65530])

        assert feed.is_known_prefix("192.0.2.0/24") is True

    def test_is_known_prefix_nonexistent(self):
        """Test is_known_prefix for non-existent prefix."""
        feed = MockBGPFeed()
        feed.add_route(prefix="192.0.2.0/24", origin_as=65530, as_path=[65530])

        assert feed.is_known_prefix("10.0.0.0/8") is False

    def test_multiple_routes_independent(self):
        """Test that multiple routes are stored independently."""
        feed = MockBGPFeed()

        # Add first route
        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65530,
            as_path=[65530, 65531],
            collectors=["routeviews"],
        )

        # Add second route
        feed.add_route(
            prefix="203.0.113.0/24",
            origin_as=64512,
            as_path=[64512, 64513, 64514],
            collectors=["routeviews", "ris"],
        )

        # Verify first route unchanged
        assert feed.is_known_prefix("192.0.2.0/24") is True
        assert feed.expected_origin("192.0.2.0/24") == 65530
        assert feed.expected_as_path("192.0.2.0/24") == [65530, 65531]
        assert feed.visibility("192.0.2.0/24") == 1

        # Verify second route
        assert feed.is_known_prefix("203.0.113.0/24") is True
        assert feed.expected_origin("203.0.113.0/24") == 64512
        assert feed.expected_as_path("203.0.113.0/24") == [64512, 64513, 64514]
        assert feed.visibility("203.0.113.0/24") == 2

    def test_empty_as_path(self):
        """Test adding a route with empty AS path."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="192.0.2.0/24", origin_as=65530, as_path=[]  # Empty AS path
        )

        result = feed.expected_as_path("192.0.2.0/24")
        assert result == []

    def test_single_collector(self):
        """Test adding a route with single collector."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65530,
            as_path=[65530],
            collectors=["single_collector"],
        )

        result = feed.visibility("192.0.2.0/24")
        assert result == 1

    def test_empty_collectors_list(self):
        """Test adding a route with empty collectors list."""
        feed = MockBGPFeed()

        feed.add_route(
            prefix="192.0.2.0/24",
            origin_as=65530,
            as_path=[65530],
            collectors=[],  # Empty list
        )

        result = feed.visibility("192.0.2.0/24")
        # With the 'or' operator in the implementation, empty list is falsy,
        # so it uses the default collectors ["routeviews", "ris"]
        assert result == 2

    def test_type_annotations(self):
        """Test that methods return correct types."""
        import inspect

        feed = MockBGPFeed()

        # Check add_route signature
        sig = inspect.signature(feed.add_route)
        assert "prefix" in sig.parameters
        assert "origin_as" in sig.parameters
        assert "as_path" in sig.parameters
        assert "collectors" in sig.parameters

        # Check return type annotations
        sig = inspect.signature(feed.expected_origin)
        annotation_str = str(sig.return_annotation)
        # Should be "int | None" or similar
        assert "int" in annotation_str and (
            "None" in annotation_str or "Optional" in annotation_str
        )

        sig = inspect.signature(feed.expected_as_path)
        annotation_str = str(sig.return_annotation)
        # Should be "list[int] | None" or similar
        assert "list" in annotation_str and (
            "None" in annotation_str or "Optional" in annotation_str
        )

        sig = inspect.signature(feed.visibility)
        # visibility returns int
        assert sig.return_annotation is int

        sig = inspect.signature(feed.is_known_prefix)
        # is_known_prefix returns bool
        assert sig.return_annotation is bool


def test_module_imports():
    """Test that the module exports the expected names."""
    import simulator.feeds.bgp.mock_feed as mock_feed_module

    assert hasattr(mock_feed_module, "MockBGPFeed")
    assert isinstance(mock_feed_module.MockBGPFeed, type)


def test_edge_case_prefixes():
    """Test with various edge case prefix formats."""
    feed = MockBGPFeed()

    # Test IPv6 prefix
    feed.add_route(prefix="2001:db8::/32", origin_as=65530, as_path=[65530])
    assert feed.is_known_prefix("2001:db8::/32") is True
    assert feed.expected_origin("2001:db8::/32") == 65530

    # Test small prefix
    feed.add_route(prefix="0.0.0.0/0", origin_as=0, as_path=[0])
    assert feed.is_known_prefix("0.0.0.0/0") is True

    # Test large prefix
    feed.add_route(prefix="255.255.255.255/32", origin_as=65535, as_path=[65535])
    assert feed.is_known_prefix("255.255.255.255/32") is True


def test_negative_as_numbers():
    """Test with negative AS numbers (edge case)."""
    feed = MockBGPFeed()

    # AS numbers are typically positive, but test edge case
    feed.add_route(
        prefix="192.0.2.0/24",
        origin_as=-1,  # Unusual but valid for testing
        as_path=[-1, 65530],
    )

    assert feed.expected_origin("192.0.2.0/24") == -1
    assert feed.expected_as_path("192.0.2.0/24") == [-1, 65530]
