"""
Red Lantern BGP attack-chain simulator core package.

This package contains the simulator engine and the telemetry generators.
The engine provides:
- ScenarioRunner
- SimulationClock
- EventBus

Telemetry generators produce structured events (BGP, syslog, latency)
for use in attack-chain simulations.
"""

# Expose core engine components
from simulator.engine.scenario_runner import ScenarioRunner
from simulator.engine.clock import SimulationClock
from simulator.engine.event_bus import EventBus
