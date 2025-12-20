"""Simple test to verify pytest works."""


def test_import_simulator():
    """Test that we can import simulator modules."""
    try:
        from simulator.feeds.bgp import routeviews_feed
        from simulator.feeds.change_mgmt import mock_cmdb

        assert True
    except ImportError as e:
        raise AssertionError(f"Import failed: {e}") from None


def test_basic_math():
    """Simple test to verify pytest runs."""
    assert 1 + 1 == 2
