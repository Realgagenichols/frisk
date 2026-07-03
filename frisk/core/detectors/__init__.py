"""Detector registry — D1–D7 register here as they are implemented (R23)."""

from __future__ import annotations

from frisk.core.detectors.d1_injection import InstructionInjection
from frisk.core.detectors.d2_hidden import HiddenContent
from frisk.core.detectors.d3_sensitive_params import SensitiveParams
from frisk.core.detectors.d4_scope import ScopeMismatch
from frisk.core.engine import Detector

ALL_DETECTORS: list[Detector] = [
    InstructionInjection(),
    HiddenContent(),
    SensitiveParams(),
    ScopeMismatch(),
]
