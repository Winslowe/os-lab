"""Isolated two-stage 'clean dropper' lab package (PENT-15).

All artifacts in this package operate strictly on loopback (127.0.0.1 / localhost)
and use inert marker strings to teach static and behavioral detection of
deferred remote-code loaders.
"""

from .stage2_server import (
    BENIGN_STAGE2_CODE,
    BENIGN_STAGE2_MARKER,
    Stage2LabServer,
    assert_loopback_host,
    build_stage2_packet,
    run_lab_rehearsal,
)

__all__ = [
    "BENIGN_STAGE2_CODE",
    "BENIGN_STAGE2_MARKER",
    "Stage2LabServer",
    "assert_loopback_host",
    "build_stage2_packet",
    "run_lab_rehearsal",
]
