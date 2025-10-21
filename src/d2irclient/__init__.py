"""
D2IR Client - A Python client for the Direct to INN-Reach (D2IR) API.

This module provides a basic client for interacting with the D2IR API
for resource sharing between library systems.
"""

from .D2IRClient import D2IRClient
from ._httpx import D2IRAuth, D2IRParameters

__version__ = "0.1.0"
__all__ = ["D2IRClient", "D2IRAuth", "D2IRParameters"]
