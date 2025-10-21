"""This module provides an httpx Auth class for handling D2IR authentication."""

import base64
import datetime
import logging
import threading
from dataclasses import dataclass
from http import HTTPStatus
from typing import AsyncGenerator, Generator, NamedTuple, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class D2IRParameters:
    """Parameters required for D2IR authentication and requests."""

    d2ir_auth_url: str
    d2ir_root_url: str
    d2ir_key: str
    d2ir_secret: str
    d2ir_from_code: str
    d2ir_to_code: str
    d2ir_timeout: Optional[httpx.Timeout] = None


class D2IRAuth(httpx.Auth):
    """An httpx Auth class for handling D2IR authentication."""

    class _Token(NamedTuple):
        """A simple structure to hold the token and its expiry."""

        token: str
        expiry: datetime.datetime

    def __init__(self, params: D2IRParameters) -> None:
        self._params = params
        self._base_headers = {
            "Content-Type": "application/json",
            "accept": "application/json",
            "X-From-Code": self._params.d2ir_from_code,
            "X-To-Code": self._params.d2ir_to_code,
        }
        self._lock = threading.RLock()
        self._token: D2IRAuth._Token = self._do_sync_auth()

    def _token_is_expired(self) -> bool:
        return bool(
            self._token.expiry
            and datetime.datetime.now(tz=datetime.timezone.utc) >= self._token.expiry
        )

    def sync_auth_flow(
        self, request: httpx.Request
    ) -> "Generator[httpx.Request, httpx.Response, None]":
        """A synchronous authentication flow for httpx.

        This method sets the Authorization header with the current token,
        checks for token expiry, and refreshes the token if necessary. If a request
        fails with a 401 Unauthorized status, it attempts to refresh the token and
        retry the request once.
        """
        with self._lock:
            if not self._token or self._token_is_expired():
                self._token = self._do_sync_auth()
        logger.debug("Initial request headers: %s", request.headers)
        request.headers["Authorization"] = f"Bearer {self._token.token}"
        request.headers.update(self._base_headers)
        logger.debug("Updated request headers: %s", request.headers)
        response = yield request
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            with self._lock:
                self._token = self._do_sync_auth()
            logger.debug("Retrying request with new token.")
            request.headers["Authorization"] = f"Bearer {self._token.token}"
            request.headers.update(self._base_headers)
            logger.debug("Retry request headers: %s", request.headers)

            retry_response = yield request

            if retry_response.status_code == HTTPStatus.UNAUTHORIZED:
                raise httpx.HTTPStatusError(
                    "Authentication failed after token refresh. Check your D2IR credentials.",
                    request=retry_response.request,
                    response=retry_response,
                )

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> "AsyncGenerator[httpx.Request, httpx.Response]":
        """An asynchronous authentication flow for httpx.

        This method sets the Authorization header with the current token,
        checks for token expiry, and refreshes the token if necessary. If a request
        fails with a 401 Unauthorized status, it attempts to refresh the token and
        retry the request once.
        """
        with self._lock:
            if not self._token or self._token_is_expired():
                self._token = await self._do_async_auth()
        logger.debug("Initial request headers: %s", request.headers)
        request.headers["Authorization"] = f"Bearer {self._token.token}"
        request.headers.update(self._base_headers)
        logger.debug("Updated request headers: %s", request.headers)
        response = yield request
        if response.status_code == HTTPStatus.UNAUTHORIZED:
            with self._lock:
                self._token = await self._do_async_auth()
            logger.debug("Retrying request with new token.")
            request.headers["Authorization"] = f"Bearer {self._token.token}"
            request.headers.update(self._base_headers)
            logger.debug("Retry request headers: %s", request.headers)

            retry_response = yield request

            if retry_response.status_code == HTTPStatus.UNAUTHORIZED:
                raise httpx.HTTPStatusError(
                    "Authentication failed after token refresh. Check your D2IR credentials.",
                    request=retry_response.request,
                    response=retry_response,
                )

    def _do_sync_auth(self) -> _Token:
        return self._login()

    async def _do_async_auth(self) -> _Token:
        return self._login()

    def _login(self) -> "D2IRAuth._Token":
        digest_token = base64.b64encode(
            f"{self._params.d2ir_key}:{self._params.d2ir_secret}".encode("utf-8")
        ).decode("utf-8")
        headers = {
            "Authorization": "Basic " + digest_token,
        }
        headers.update(self._base_headers)
        with httpx.Client(timeout=self._params.d2ir_timeout) as client:
            response = client.post(
                self._params.d2ir_auth_url,
                headers=headers,
                params={"grant_type": "client_credentials", "scope": "innreach_tp"},
            )
        response.raise_for_status()
        response_json = response.json()

        # Basic validation of required fields
        access_token = response_json.get("access_token")
        expires_in = response_json.get("expires_in")

        if not access_token:
            raise httpx.RequestError("Missing access_token in auth response")

        if expires_in is None:
            raise httpx.RequestError("Missing expires_in in auth response")

        try:
            expires_in = int(expires_in)
        except (ValueError, TypeError) as e:
            raise httpx.RequestError(f"Invalid expires_in value: {expires_in}") from e

        return self._Token(
            token=access_token,
            expiry=datetime.datetime.now(tz=datetime.timezone.utc)
            + datetime.timedelta(seconds=expires_in - 60),
        )
