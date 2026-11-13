"""Private control-plane settings; no secrets are logged."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class ControlSettings:
    """Explicit worker paths and peer identities from the approved manifest."""

    operator_socket: Path
    admission_socket: Path
    operator_peer_uid: int
    admission_peer_uid: int

    @classmethod
    def from_env(cls) -> ControlSettings:
        return cls(
            operator_socket=Path(
                os.environ.get(
                    "MTMF_CONTROL_OPERATOR_SOCKET",
                    "/run/mtmf-control/operator/operator.sock",
                )
            ),
            admission_socket=Path(
                os.environ.get(
                    "MTMF_CONTROL_ADMISSION_SOCKET",
                    "/run/mtmf-control/admission/admission.sock",
                )
            ),
            operator_peer_uid=int(os.environ.get("MTMF_CONTROL_OPERATOR_PEER_UID", "24502")),
            admission_peer_uid=int(os.environ.get("MTMF_CONTROL_ADMISSION_PEER_UID", "24503")),
        )
