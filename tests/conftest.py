"""
Test configuration and shared utilities for D2IRClient tests.

This module provides:
- Common fixtures for all tests
- Shared DummyAuth implementations
- Mock helpers and utilities
- Pytest configuration
"""

import inspect
import pytest
import httpx
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock
from typing import Generator, Any, Dict, Optional

# Import all the modules under test
from d2irclient.D2IRClient import D2IRClient
from d2irclient._httpx import D2IRAuth, D2IRParameters


class DummyAuth(httpx.Auth):
    """
    Standard DummyAuth class for mocking D2IRAuth in tests.
    
    This class provides a complete authentication interface without making
    real HTTP calls, ensuring test isolation and speed.
    """
    
    def __init__(self, *args, **kwargs):
        """Accept any arguments to match D2IRAuth signature."""
        pass
    
    def _login(self):
        """Mock login that returns a dummy token."""
        class Token:
            token = 'dummy_token'
            expiry = None
        return Token()
    
    def _do_sync_auth(self):
        """Mock sync authentication."""
        return self._login()
    
    def auth_flow(self, request):
        """Mock auth flow for httpx.Auth interface."""
        yield request


class DummyParams:
    """Mock D2IRParameters for testing."""
    
    def __init__(self):
        self.d2ir_auth_url = 'http://dummy/oauth/token'
        self.d2ir_root_url = 'http://dummy/'
        self.d2ir_key = 'dummy_key'
        self.d2ir_secret = 'dummy_secret'
        self.d2ir_from_code = 'FROM'
        self.d2ir_to_code = 'TO'
        self.d2ir_timeout = None


# Pytest fixtures
@pytest.fixture
def dummy_auth():
    """Provide a DummyAuth instance for tests."""
    return DummyAuth()


@pytest.fixture
def dummy_params():
    """Provide mock D2IRParameters for tests."""
    return DummyParams()


@pytest.fixture
def mock_d2ir_client():
    """Provide a D2IRClient with mocked authentication."""
    with patch('d2irclient.D2IRClient.D2IRAuth', DummyAuth):
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
        yield client


@pytest.fixture
def mock_http_response():
    """Create a mock HTTP response object."""
    response = MagicMock()
    response.raise_for_status.return_value = None
    response.json.return_value = {'ok': True}
    response.text = 'mock response text'
    response.status_code = 200
    return response


@pytest.fixture
def mock_error_response():
    """Create a mock HTTP error response."""
    response = MagicMock()
    response.text = 'error text'
    response.status_code = 400
    return response


# Test utilities
def patch_auth_decorator(func):
    """
    Decorator to automatically patch D2IRAuth for a test function.
    
    Usage:
        @patch_auth_decorator
        def test_something():
            client = D2IRClient(...)  # Will use DummyAuth
    """
    return patch('d2irclient.D2IRClient.D2IRAuth', DummyAuth)(func)


def create_mock_client_with_response(response_data: Dict[str, Any], 
                                   method: str = 'get',
                                   should_raise: Optional[Exception] = None) -> D2IRClient:
    """
    Create a D2IRClient with a specific mocked HTTP response.
    
    Args:
        response_data: The JSON data the mock response should return
        method: HTTP method to mock ('get', 'post', 'put', 'delete')
        should_raise: Exception to raise instead of returning response
        
    Returns:
        D2IRClient with mocked HTTP client
    """
    with patch('d2irclient.D2IRClient.D2IRAuth', DummyAuth):
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
        
        # Create mock response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = response_data
        
        # Create a mock HTTP client
        mock_http_client = MagicMock()
        
        # Setup the specific HTTP method
        if should_raise:
            mock_method = MagicMock(side_effect=should_raise)
        else:
            mock_method = MagicMock(return_value=mock_response)
            
        setattr(mock_http_client, method, mock_method)
        
        # Monkey patch the client to use our mock
        client.http_client = mock_http_client
        
        return client


async def create_mock_async_client_with_response(response_data: Dict[str, Any],
                                               method: str = 'get',
                                               should_raise: Optional[Exception] = None) -> D2IRClient:
    """
    Create a D2IRClient with a specific mocked async HTTP response.
    
    Args:
        response_data: The JSON data the mock response should return
        method: HTTP method to mock ('get', 'post', 'put', 'delete')
        should_raise: Exception to raise instead of returning response
        
    Returns:
        D2IRClient with mocked async HTTP client
    """
    with patch('d2irclient.D2IRClient.D2IRAuth', DummyAuth):
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
        
        # Create mock response
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.return_value = response_data
        
        # Create a mock async HTTP client
        mock_async_client = AsyncMock()
        
        # Setup the specific async HTTP method
        if should_raise:
            mock_method = AsyncMock(side_effect=should_raise)
        else:
            mock_method = AsyncMock(return_value=mock_response)
            
        setattr(mock_async_client, method, mock_method)
        
        # Monkey patch the client to use our mock
        client.async_http_client = mock_async_client
        
        return client


# Common test data
SAMPLE_RESPONSE_DATA = {
    'success': {'ok': True, 'result': 'success'},
    'error': {'ok': False, 'error': 'Something went wrong'},
    'item_status': {'status': 'available', 'item_id': 'test123'},
    'empty': {}
}


# Pytest configuration
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Automatically mark async tests."""
    for item in items:
        if inspect.iscoroutinefunction(item.function):
            item.add_marker(pytest.mark.asyncio)
