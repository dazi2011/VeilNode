from __future__ import annotations

from pathlib import Path
from typing import Any

from .model import train_heuristic_model


def train(dataset: str | Path, out: str | Path) -> dict[str, Any]:
    return train_heuristic_model(dataset, out)
