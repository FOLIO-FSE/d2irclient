"""
Client for interacting with the Direct to INN-Reach (D2IR) API for resource sharing.
"""

import logging
import os
from typing import cast

import httpx

from ._httpx import D2IRAuth, D2IRParameters

logger = logging.getLogger("D2IRClient")

# Simple timeout constant for all FolioClient instances if env var is set
try:
    timeout_str = os.environ.get("D2IR_HTTP_TIMEOUT")
    HTTPX_TIMEOUT = float(timeout_str) if timeout_str is not None else None
except (TypeError, ValueError):
    HTTPX_TIMEOUT = None


# Sentinel value for detecting unset timeout parameter
class _TimeoutUnsetType:
    def __repr__(self):
        return "_TIMEOUT_UNSET"


_TIMEOUT_UNSET = _TimeoutUnsetType()


# Timeout configuration with granular control
def _get_timeout_config() -> dict:
    """Get timeout configuration from environment variables or defaults.

    Returns:
        dict: Timeout configuration dictionary with connect, read, write, and pool timeouts.
    """
    # Granular timeout configuration - these override the default when set
    return {
        "connect": float(os.environ["D2IRCLIENT_CONNECT_TIMEOUT"])
        if "D2IRCLIENT_CONNECT_TIMEOUT" in os.environ
        else None,
        "read": float(os.environ["D2IRCLIENT_READ_TIMEOUT"])
        if "D2IRCLIENT_READ_TIMEOUT" in os.environ
        else None,
        "write": float(os.environ["D2IRCLIENT_WRITE_TIMEOUT"])
        if "D2IRCLIENT_WRITE_TIMEOUT" in os.environ
        else None,
        "pool": float(os.environ["D2IRCLIENT_POOL_TIMEOUT"])
        if "D2IRCLIENT_POOL_TIMEOUT" in os.environ
        else None,
    }


TIMEOUT_CONFIG = _get_timeout_config()


class D2IRClient:
    def __init__(
        self,
        d2ir_auth_url: str,
        d2ir_root_url: str,
        d2ir_key: str,
        d2ir_secret: str,
        from_server_code: str,
        to_server_code: str,
        timeout: httpx.Timeout | dict[str, float] | None = None,
    ) -> None:
        # Determine timeout value to use
        if timeout is _TIMEOUT_UNSET:
            # User didn't specify timeout, use environment variables
            timeout_value: httpx.Timeout = self._construct_timeout_from_env()
        elif timeout is None:
            # User explicitly passed None, ignore environment variables
            timeout_value = httpx.Timeout(None)
        else:
            # User passed specific value (float, dict, or httpx.Timeout)
            timeout_value = self._construct_timeout(cast(float | dict | httpx.Timeout, timeout))

        self.d2ir_params = D2IRParameters(
            d2ir_auth_url=d2ir_auth_url,
            d2ir_root_url=ensure_trailing_slash(d2ir_root_url),
            d2ir_key=d2ir_key,
            d2ir_secret=d2ir_secret,
            d2ir_from_code=from_server_code,
            d2ir_to_code=to_server_code,
            d2ir_timeout=timeout_value,
        )
        self.d2ir_auth = D2IRAuth(self.d2ir_params)

    async def __aenter__(self):
        self.async_http_client: httpx.AsyncClient = httpx.AsyncClient(
            base_url=self.d2ir_params.d2ir_root_url, auth=self.d2ir_auth, timeout=None
        )
        return self

    async def __aexit__(self, exc_type, exc_value, traceback):
        await self.async_http_client.aclose()

    def __enter__(self):
        self.http_client: httpx.Client = httpx.Client(
            base_url=self.d2ir_params.d2ir_root_url, auth=self.d2ir_auth, timeout=None
        )
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.http_client.close()

    @staticmethod
    def _construct_timeout_from_env() -> httpx.Timeout:
        """Construct httpx.Timeout object from environment variables only.

        Returns:
            httpx.Timeout: Configured timeout object from environment variables.
                          If no environment configuration is found, returns httpx.Timeout(None).
        """
        default_timeout_config = {k: v for k, v in TIMEOUT_CONFIG.items() if v is not None}

        if not default_timeout_config and HTTPX_TIMEOUT is None:
            return httpx.Timeout(None)

        return httpx.Timeout(HTTPX_TIMEOUT, **default_timeout_config)

    @staticmethod
    def _construct_timeout(timeout: float | dict | httpx.Timeout) -> httpx.Timeout:
        """Construct httpx.Timeout object from user-provided timeout parameter.

        If timeout is a dict, any unspecified values will be replaced by the environment
        default values. If you want full control over every timeout value, set them explicitly
        in the dict.

        Args:
            timeout: Timeout configuration - can be float, dict, or httpx.Timeout.

        Returns:
            httpx.Timeout: Configured timeout object.
        """
        if isinstance(timeout, httpx.Timeout):
            return timeout
        elif isinstance(timeout, dict):
            # For user-provided dict, merge with environment defaults
            default_timeout_config = {k: v for k, v in TIMEOUT_CONFIG.items() if v is not None}
            merged_timeout = {**default_timeout_config, **timeout}
            return httpx.Timeout(HTTPX_TIMEOUT, **merged_timeout)
        else:
            # Handle float/int timeout
            return httpx.Timeout(timeout)

    async def d2ir_get_async(self, endpoint, params=None):
        response = await self.async_http_client.get(
            endpoint,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def d2ir_get(self, endpoint, params=None):
        response = self.http_client.get(
            endpoint,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    async def d2ir_post_async(self, endpoint, json=None, params=None):
        response = await self.async_http_client.post(
            endpoint,
            json=json,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def d2ir_post(self, endpoint: str, json=None, params=None):
        response = self.http_client.post(
            endpoint,
            json=json,
            params=params,
        )
        response.raise_for_status()
        return response.json()  # pragma: no cover

    async def d2ir_put_async(self, endpoint, json=None, params=None):
        response = await self.async_http_client.put(
            endpoint,
            json=json,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def d2ir_put(self, endpoint, json=None, params=None):
        response = self.http_client.put(
            endpoint,
            json=json,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    async def d2ir_delete_async(self, endpoint, params=None):
        response = await self.async_http_client.delete(
            endpoint,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    def d2ir_delete(self, endpoint: str, params: dict | None = None):
        response = self.http_client.delete(
            endpoint,
            params=params,
        )
        response.raise_for_status()
        return response.json()

    async def update_item_status_async(self, item_id, item_status_obj):
        endpoint = f"v2/contribution/itemstatus/{item_id}"
        try:
            return await self.d2ir_post(endpoint, json=item_status_obj)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error updating item status for {item_id}: {e.response.text}")
            raise e
        except Exception as e:
            logger.info(f"Unexpected error updating item status for {item_id}: {str(e)}")
            raise e

    def update_item_status(self, item_id, item_status_obj):
        endpoint = f"v2/contribution/itemstatus/{item_id}"
        try:
            return self.d2ir_post(endpoint, json=item_status_obj)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error updating item status for {item_id}: {e.response.text}")
            raise e
        except Exception as e:
            logger.info(f"Unexpected error updating item status for {item_id}: {str(e)}")
            raise e

    async def decontribute_item_async(self, item_id):
        endpoint = f"v2/contribution/item/{item_id}"
        try:
            return await self.d2ir_delete(endpoint)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error decontributing item {item_id}: {e.response.text}")
        except Exception as e:
            logger.info(f"Unexpected error decontributing item {item_id}: {str(e)}")
            raise e

    def decontribute_item(self, item_id):
        endpoint = f"v2/contribution/item/{item_id}"
        try:
            return self.d2ir_delete(endpoint)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error decontributing item {item_id}: {e.response.text}")
        except Exception as e:
            logger.info(f"Unexpected error decontributing item {item_id}: {str(e)}")
            raise e

    async def decontribute_bib_async(self, bib_id):
        endpoint = f"v2/contribution/bib/{bib_id}"
        try:
            return await self.d2ir_delete(endpoint)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error decontributing bib {bib_id}: {e.response.text}")
        except Exception as e:
            logger.info(f"Unexpected error decontributing bib {bib_id}: {str(e)}")
            raise e

    def decontribute_bib(self, bib_id):
        endpoint = f"v2/contribution/bib/{bib_id}"
        try:
            return self.d2ir_delete(endpoint)
        except httpx.HTTPStatusError as e:
            logger.info(f"Error decontributing bib {bib_id}: {e.response.text}")
        except Exception as e:
            logger.info(f"Unexpected error decontributing bib {bib_id}: {str(e)}")
            raise e


def ensure_trailing_slash(url_string: str) -> str:
    """
    Adds a trailing slash to a URL string if one is not already present.
    """
    if not url_string.endswith("/"):
        return url_string + "/"
    return url_string
