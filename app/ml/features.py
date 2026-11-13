"""Feature construction for time-windowed API behavior."""

from dataclasses import dataclass
from math import log1p

import numpy as np


@dataclass(frozen=True)
class TrafficWindow:
    method: str
    route: str
    requests_per_minute: float
    failed_logins_per_minute: float
    unique_routes: int
    average_request_bytes: float
    average_response_bytes: float
    error_rate: float
    client_profile: str = "consumer"
    hour_of_day: int = 12
    session_age_minutes: float = 30
    new_routes: int = 0
    location_changed: int = 0

    def semantic_summary(self) -> str:
        """Create safe text for the Hugging Face embedding model."""
        return (
            f"profile={self.client_profile} method={self.method} route={self.route} "
            f"hour={self.hour_of_day} new_routes={self.new_routes} "
            f"location_changed={self.location_changed}"
        )


def to_behavior_features(window: TrafficWindow) -> np.ndarray:
    """Convert traffic behavior into a small numeric feature vector."""
    profile_features = [
        float(self_profile == window.client_profile)
        for self_profile in ("consumer", "employee", "service")
    ]
    return np.array(
        [
            log1p(window.requests_per_minute),
            log1p(window.failed_logins_per_minute),
            log1p(window.unique_routes),
            log1p(window.average_request_bytes),
            log1p(window.average_response_bytes),
            window.error_rate,
            np.sin(2 * np.pi * window.hour_of_day / 24),
            np.cos(2 * np.pi * window.hour_of_day / 24),
            log1p(window.session_age_minutes),
            log1p(window.new_routes),
            float(window.location_changed),
            *profile_features,
        ],
        dtype=np.float32,
    )
