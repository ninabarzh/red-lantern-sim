# Feeds

Feeds provide external context to the simulator.

They represent data sources such as:

- BGP collectors (RouteViews, RIPE RIS)
- Configuration management databases (CMDB)
- Any other system that informs how the network normally behaves

Feeds do NOT emit telemetry directly. They are queried by scenario telemetry to enrich events with context.

## Directory structure

```
feeds/
├── bgp/
│   ├── mock_feed.py
│   ├── routeviews_feed.py
│   ├── ris_feed.py
│   └── ...
└── change_mgmt/
    ├── mock_cmdb.py
    └── ...
````

## How feeds are used

Scenario telemetry files may import feeds and query them when constructing telemetry events.

Typical uses:

- Determine expected origin `AS` for a prefix
- Compare observed `AS` paths with baseline paths
- Assess how widely a route is visible
- Correlate configuration changes with routing events

Feeds are optional. If a scenario does not import a feed, nothing breaks.

## Example usage in telemetry

```python
from simulator.feeds.bgp.mock_feed import MockBGPFeed

feed = MockBGPFeed()
feed.add_route(
    prefix="203.0.113.0/24",
    origin_as=65001,
    as_path=[64512, 65001],
)

expected = feed.expected_origin("203.0.113.0/24")
````

## Adding a new feed to mock with

1. Create a new Python module under `feeds/`
2. Implement a small, query-focused API
3. Do NOT emit telemetry from the feed
4. Import and use the feed from scenario telemetry

Feeds should be:

* Deterministic
* Side-effect free
* Lightweight

Good feeds answer questions. Telemetry decides what to emit.

## Why feeds exist

Feeds allow scenarios to model *realistic detection conditions*.

Instead of detecting: *“An update happened”*

You can detect: *“An update violated expectations”*

This distinction is critical for realistic Wazuh rules and SOC training.
