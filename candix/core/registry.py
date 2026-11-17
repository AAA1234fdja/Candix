"""Generic plugin registry.

Detectors, reporters and fuzzers register themselves by a stable identifier so
the CLI, the API and tests can select them without importing every module.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Generic, Iterable, Iterator, TypeVar

T = TypeVar("T")


@dataclass
class Registry(Generic[T]):
    name: str = "registry"
    allow_overwrite: bool = False
    _items: dict[str, T] = field(default_factory=dict)
    _order: list[str] = field(default_factory=list)

    def register(self, key: str, item: T) -> T:
        if key in self._items and not self.allow_overwrite:
            raise ValueError(f"{self.name}: duplicate key {key!r}")
        self._items[key] = item
        self._order.append(key)
        return item

    def register_many(self, items: dict[str, T]) -> None:
        for key, item in items.items():
            self.register(key, item)

    def get(self, key: str, default: T | None = None) -> T | None:
        return self._items.get(key, default)

    def require(self, key: str) -> T:
        if key not in self._items:
            raise KeyError(f"{self.name}: unknown key {key!r}")
        return self._items[key]

    def __contains__(self, key: object) -> bool:
        return key in self._items

    def __iter__(self) -> Iterator[str]:
        return iter(self._order)

    def __len__(self) -> int:
        return len(self._items)

    def keys(self) -> list[str]:
        return list(self._order)

    def values(self) -> list[T]:
        return [self._items[key] for key in self._order]

    def items(self) -> list[tuple[str, T]]:
        return [(key, self._items[key]) for key in self._order]

    def select(self, predicate: Callable[[T], bool]) -> list[T]:
        return [item for item in self.values() if predicate(item)]

    def remove(self, key: str) -> None:
        self._items.pop(key, None)
        if key in self._order:
            self._order.remove(key)

    def clear(self) -> None:
        self._items.clear()
        self._order.clear()

    def to_dict(self) -> dict[str, Any]:
        return {key: item for key, item in self._items.items()}


class LazyRegistry(Registry[T]):
    """Registry that imports modules on first use."""

    def __init__(self, name: str, import_paths: Iterable[str]) -> None:
        super().__init__(name)
        self.import_paths = list(import_paths)
        self._loaded = False

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        import importlib
        import pkgutil

        for path in self.import_paths:
            try:
                package = importlib.import_module(path)
            except ImportError:
                continue
            if not hasattr(package, "__path__"):
                continue
            for module in pkgutil.iter_modules(package.__path__):
                if module.name.startswith("_"):
                    continue
                try:
                    importlib.import_module(f"{path}.{module.name}")
                except Exception as exc:  # pragma: no cover - broken third-party plugin
                    import sys

                    print(f"candix: failed to import {path}.{module.name}: {exc}", file=sys.stderr)

    def get(self, key: str, default: T | None = None) -> T | None:
        self._ensure_loaded()
        return super().get(key, default)

    def __iter__(self) -> Iterator[str]:
        self._ensure_loaded()
        return super().__iter__()

    def __len__(self) -> int:
        self._ensure_loaded()
        return super().__len__()

    def keys(self) -> list[str]:
        self._ensure_loaded()
        return super().keys()

    def values(self) -> list[T]:
        self._ensure_loaded()
        return super().values()

    def items(self) -> list[tuple[str, T]]:
        self._ensure_loaded()
        return super().items()

    def select(self, predicate: Callable[[T], bool]) -> list[T]:
        self._ensure_loaded()
        return super().select(predicate)

    def to_dict(self) -> dict[str, Any]:
        self._ensure_loaded()
        return super().to_dict()

    def __contains__(self, key: object) -> bool:
        self._ensure_loaded()
        return super().__contains__(key)
