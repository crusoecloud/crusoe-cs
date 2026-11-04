"""The scenario registry: declarative, capability-gated scenarios.

A scenario is a function taking (target, image); the registry carries
its target affinity (ANY_TARGET = runs on every image including
alpine; else the boot-unit capability gate applies). Adding a
scenario = write the function + one register() line — the dispatch,
the usage help, and the `all` list derive from the registry.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from .docker_target import image_to_target, target_capability

ScenarioFn = Callable[..., None]


@dataclass
class Scenario:
    name: str  # the CLI name (kebab-case)
    fn: ScenarioFn
    any_target: bool = False  # the pod-native family: runs on alpine too
    in_all: bool = True  # `all` includes it
    help_note: str = ""


@dataclass
class Registry:
    scenarios: dict[str, Scenario] = field(default_factory=dict)

    def register(
        self,
        name: str,
        *,
        any_target: bool = False,
        in_all: bool = True,
        help_note: str = "",
    ) -> Callable:
        def deco(fn: ScenarioFn) -> ScenarioFn:
            self.scenarios[name] = Scenario(
                name=name,
                fn=fn,
                any_target=any_target,
                in_all=in_all,
                help_note=help_note,
            )
            return fn

        return deco

    def get(self, name: str) -> Scenario:
        if name not in self.scenarios:
            known = "|".join(self.scenarios)
            raise KeyError(f"unknown scenario: {name} ({known})")
        return self.scenarios[name]

    def runs_on(self, scenario: Scenario, image: str) -> bool:
        """The capability gate: any_target scenarios run everywhere;
        others need the boot-unit capability (systemd)."""
        if scenario.any_target:
            return True
        return target_capability(image_to_target(image), "boot-unit")

    def all_names(self) -> list[str]:
        return [n for n, s in self.scenarios.items() if s.in_all]
