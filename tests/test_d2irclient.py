"""
Consolidated D2IRClient Tests

This file replaces:
- test_d2irclient.py
- test_d2irclient_async.py  
- test_d2irclient_context.py
- test_d2irclient_errors.py
- test_d2irclient_misc.py
- test_d2irclient_timeout.py
- test_misc_coverage.py (D2IRClient parts)

All D2IRClient functionality is tested here with shared utilities.
"""

import pytest
import httpx
import asyncio
import os
from unittest.mock import MagicMock, AsyncMock, patch

from d2irclient.D2IRClient import (
    D2IRClient, 
    ensure_trailing_slash, 
    HTTPX_TIMEOUT, 
    TIMEOUT_CONFIG,
    _TIMEOUT_UNSET
)
from conftest import (
    patch_auth_decorator,
    create_mock_client_with_response,
    create_mock_async_client_with_response,
    SAMPLE_RESPONSE_DATA,
    DummyAuth
)


class TestUtilityFunctions:
    """Test utility functions in D2IRClient module."""
    
    @pytest.mark.parametrize('url,expected', [
        ('http://foo', 'http://foo/'),
        ('http://foo/', 'http://foo/'),
        ('', '/'),
        ('https://example.com', 'https://example.com/'),
        ('https://example.com/', 'https://example.com/'),
    ])
    def test_ensure_trailing_slash(self, url, expected):
        """Test URL trailing slash utility function."""
        assert ensure_trailing_slash(url) == expected


class TestClientInitialization:
    """Test D2IRClient initialization and configuration."""
    
    def test_client_initialization_basic(self, mock_d2ir_client):
        """Test basic client initialization with mocked auth."""
        assert mock_d2ir_client is not None
        assert hasattr(mock_d2ir_client, 'd2ir_auth')
        assert hasattr(mock_d2ir_client, 'd2ir_params')
    
    @patch_auth_decorator
    def test_client_initialization_with_timeout(self):
        """Test client initialization with custom timeout."""
        client = D2IRClient(
            'http://circ', 'http://d2ir', 'key', 'secret', 'from', 'to',
            timeout=45
        )
        # Timeout should be wrapped in httpx.Timeout object with all components set to 45
        assert client.d2ir_params.d2ir_timeout.connect == 45
        assert client.d2ir_params.d2ir_timeout.read == 45
        assert client.d2ir_params.d2ir_timeout.write == 45
        assert client.d2ir_params.d2ir_timeout.pool == 45
    
    @patch_auth_decorator
    def test_client_initialization_with_env_timeout(self):
        """Test client initialization with environment timeout."""
        with patch.dict(os.environ, {'D2IR_HTTP_TIMEOUT': '60'}):
            # Need to patch the HTTPX_TIMEOUT constant since it's set at import time
            with patch('d2irclient.D2IRClient.HTTPX_TIMEOUT', 60.0):
                client = D2IRClient(
                    'http://circ', 'http://d2ir', 'key', 'secret', 'from', 'to'
                )
                # Environment timeout should be set in httpx.Timeout object
                assert client.d2ir_params.d2ir_timeout.connect == 60.0
                assert client.d2ir_params.d2ir_timeout.read == 60.0
    
    @patch_auth_decorator
    def test_client_initialization_invalid_env_timeout(self):
        """Test client initialization with invalid environment timeout."""
        with patch.dict(os.environ, {'D2IR_HTTP_TIMEOUT': 'invalid'}):
            client = D2IRClient(
                'http://circ', 'http://d2ir', 'key', 'secret', 'from', 'to'
            )
            # Should use default timeout when env value is invalid
            # HTTPX_TIMEOUT should be None due to invalid env value
            assert client.d2ir_params.d2ir_timeout.connect is None
            assert client.d2ir_params.d2ir_timeout.read is None


class TestContextManagers:
    """Test sync and async context manager functionality."""
    
    def test_sync_context_manager(self, mock_d2ir_client):
        """Test sync context manager functionality."""
        with mock_d2ir_client as client:
            assert client is mock_d2ir_client
            assert hasattr(client, 'http_client')
            assert client.http_client is not None
    
    def test_sync_context_manager_exit(self, mock_d2ir_client):
        """Test sync context manager properly closes client."""
        with mock_d2ir_client as client:
            # Mock the close method to verify it's called
            client.http_client = MagicMock()
            client.http_client.close = MagicMock()
        
        # After exiting context, close should have been called
        client.http_client.close.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_async_context_manager(self, mock_d2ir_client):
        """Test async context manager functionality."""
        async with mock_d2ir_client as client:
            assert client is mock_d2ir_client
            assert hasattr(client, 'async_http_client')
            assert client.async_http_client is not None
    
    @pytest.mark.asyncio
    async def test_async_context_manager_exit(self, mock_d2ir_client):
        """Test async context manager properly closes client."""
        async with mock_d2ir_client as client:
            # Mock the aclose method to verify it's called  
            client.async_http_client = AsyncMock()
            client.async_http_client.aclose = AsyncMock()
        
        # After exiting context, aclose should have been called
        client.async_http_client.aclose.assert_called_once()


class TestSyncHTTPMethods:
    """Test synchronous HTTP methods."""
    
    def test_d2ir_get_success(self):
        """Test successful D2IR GET request."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='get')
        result = client.d2ir_get('/test/endpoint')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.get.assert_called_once()
    
    def test_d2ir_get_with_params(self):
        """Test D2IR GET request with parameters."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='get')
        result = client.d2ir_get('/test/endpoint', params={'key': 'value'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.get.assert_called_once_with('/test/endpoint', params={'key': 'value'})
    
    def test_d2ir_post_success(self):
        """Test successful D2IR POST request."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='post')
        result = client.d2ir_post('/test/endpoint', json={'test': 'data'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.post.assert_called_once()
    
    def test_d2ir_put_success(self):
        """Test successful D2IR PUT request."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='put')
        result = client.d2ir_put('/test/endpoint', json={'test': 'data'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.put.assert_called_once()
    
    def test_d2ir_delete_success(self):
        """Test successful D2IR DELETE request."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = client.d2ir_delete('/test/endpoint')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.delete.assert_called_once()


class TestAsyncHTTPMethods:
    """Test asynchronous HTTP methods."""
    
    @pytest.mark.asyncio
    async def test_d2ir_get_async_success(self):
        """Test successful async D2IR GET request."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='get')
        result = await client.d2ir_get_async('/test/endpoint')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.get.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_d2ir_get_async_with_params(self):
        """Test async D2IR GET request with parameters."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='get')
        result = await client.d2ir_get_async('/test/endpoint', params={'key': 'value'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.get.assert_called_once_with('/test/endpoint', params={'key': 'value'})
    
    @pytest.mark.asyncio
    async def test_d2ir_post_async_success(self):
        """Test successful async D2IR POST request."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='post')
        result = await client.d2ir_post_async('/test/endpoint', json={'test': 'data'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_d2ir_put_async_success(self):
        """Test successful async D2IR PUT request."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='put')
        result = await client.d2ir_put_async('/test/endpoint', json={'test': 'data'})
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.put.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_d2ir_delete_async_success(self):
        """Test successful async D2IR DELETE request."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = await client.d2ir_delete_async('/test/endpoint')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.delete.assert_called_once()


class TestErrorHandling:
    """Test error handling scenarios for both sync and async methods."""
    
    def test_sync_http_error_handling(self):
        """Test handling of HTTP errors in sync operations."""
        mock_response = MagicMock()
        mock_response.text = 'Bad Request'
        error = httpx.HTTPStatusError('Bad Request', request=MagicMock(), response=mock_response)
        client = create_mock_client_with_response({}, method='get', should_raise=error)
        
        with pytest.raises(httpx.HTTPStatusError):
            client.d2ir_get('/test/endpoint')
    
    @pytest.mark.asyncio
    async def test_async_http_error_handling(self):
        """Test handling of HTTP errors in async operations."""
        mock_response = MagicMock()
        mock_response.text = 'Bad Request'
        error = httpx.HTTPStatusError('Bad Request', request=MagicMock(), response=mock_response)
        client = await create_mock_async_client_with_response({}, method='get', should_raise=error)
        
        with pytest.raises(httpx.HTTPStatusError):
            await client.d2ir_get_async('/test/endpoint')
    
    def test_sync_generic_error_handling(self):
        """Test handling of generic exceptions in sync operations."""
        error = Exception('Generic error')
        client = create_mock_client_with_response({}, method='post', should_raise=error)
        
        with pytest.raises(Exception):
            client.d2ir_post('/test/endpoint', json={'test': 'data'})
    
    @pytest.mark.asyncio
    async def test_async_generic_error_handling(self):
        """Test handling of generic exceptions in async operations."""
        error = Exception('Generic error')
        client = await create_mock_async_client_with_response({}, method='post', should_raise=error)
        
        with pytest.raises(Exception):
            await client.d2ir_post_async('/test/endpoint', json={'test': 'data'})
    
    def test_sync_connection_error(self):
        """Test handling of connection errors in sync operations."""
        error = httpx.ConnectError('Connection failed')
        client = create_mock_client_with_response({}, method='get', should_raise=error)
        
        with pytest.raises(httpx.ConnectError):
            client.d2ir_get('/test/endpoint')
    
    @pytest.mark.asyncio
    async def test_async_connection_error(self):
        """Test handling of connection errors in async operations."""
        error = httpx.ConnectError('Connection failed')
        client = await create_mock_async_client_with_response({}, method='get', should_raise=error)
        
        with pytest.raises(httpx.ConnectError):
            await client.d2ir_get_async('/test/endpoint')


class TestSpecificAPIMethods:
    """Test specific D2IR API methods."""
    
    def test_update_item_status_sync(self):
        """Test updating item status synchronously."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['item_status'], method='post')
        result = client.update_item_status('test123', {'status': 'available'})
        assert result == SAMPLE_RESPONSE_DATA['item_status']
        client.http_client.post.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_update_item_status_async(self):
        """Test updating item status asynchronously."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['item_status'], method='post')
        result = await client.update_item_status_async('test123', {'status': 'available'})
        assert result == SAMPLE_RESPONSE_DATA['item_status']
        client.async_http_client.post.assert_called_once()
    
    def test_update_item_status_sync_error(self):
        """Test update item status sync error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Update failed'
        error = httpx.HTTPStatusError('Update failed', request=MagicMock(), response=mock_response)
        client = create_mock_client_with_response({}, method='post', should_raise=error)
        
        with pytest.raises(httpx.HTTPStatusError):
            client.update_item_status('test123', {'status': 'bad'})
    
    @pytest.mark.asyncio
    async def test_update_item_status_async_error(self):
        """Test update item status async error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Update failed'  
        error = httpx.HTTPStatusError('Update failed', request=MagicMock(), response=mock_response)
        client = await create_mock_async_client_with_response({}, method='post', should_raise=error)
        
        with pytest.raises(httpx.HTTPStatusError):
            await client.update_item_status_async('test123', {'status': 'bad'})
    
    def test_decontribute_item_sync(self):
        """Test decontributing item synchronously."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = client.decontribute_item('test123')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_decontribute_item_async(self):
        """Test decontributing item asynchronously."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = await client.decontribute_item_async('test123')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.delete.assert_called_once()
    
    def test_decontribute_item_sync_error(self):
        """Test decontribute item sync error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Decontribute failed'
        error = httpx.HTTPStatusError('Decontribute failed', request=MagicMock(), response=mock_response)
        client = create_mock_client_with_response({}, method='delete', should_raise=error)
        
        # decontribute_item catches HTTPStatusError and returns None
        result = client.decontribute_item('test123')
        assert result is None
    
    @pytest.mark.asyncio
    async def test_decontribute_item_async_error(self):
        """Test decontribute item async error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Decontribute failed'
        error = httpx.HTTPStatusError('Decontribute failed', request=MagicMock(), response=mock_response)
        client = await create_mock_async_client_with_response({}, method='delete', should_raise=error)
        
        # decontribute_item_async catches HTTPStatusError and returns None
        result = await client.decontribute_item_async('test123')
        assert result is None
    
    def test_decontribute_bib_sync(self):
        """Test decontributing bib synchronously."""
        client = create_mock_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = client.decontribute_bib('bib123')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.http_client.delete.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_decontribute_bib_async(self):
        """Test decontributing bib asynchronously."""
        client = await create_mock_async_client_with_response(SAMPLE_RESPONSE_DATA['success'], method='delete')
        result = await client.decontribute_bib_async('bib123')
        assert result == SAMPLE_RESPONSE_DATA['success']
        client.async_http_client.delete.assert_called_once()
    
    def test_decontribute_bib_sync_error(self):
        """Test decontribute bib sync error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Decontribute bib failed'
        error = httpx.HTTPStatusError('Decontribute bib failed', request=MagicMock(), response=mock_response)
        client = create_mock_client_with_response({}, method='delete', should_raise=error)
        
        # decontribute_bib catches HTTPStatusError and returns None
        result = client.decontribute_bib('bib123')
        assert result is None
    
    @pytest.mark.asyncio
    async def test_decontribute_bib_async_error(self):
        """Test decontribute bib async error handling."""
        mock_response = MagicMock()
        mock_response.text = 'Decontribute bib failed'
        error = httpx.HTTPStatusError('Decontribute bib failed', request=MagicMock(), response=mock_response)
        client = await create_mock_async_client_with_response({}, method='delete', should_raise=error)
        
        # decontribute_bib_async catches HTTPStatusError and returns None
        result = await client.decontribute_bib_async('bib123')
        assert result is None


class TestTimeoutConfiguration:
    """Test timeout configuration and handling."""
    
    @patch_auth_decorator  
    def test_timeout_unset_branch(self):
        """Test behavior when timeout is unset."""
        with patch.dict(os.environ, {}, clear=True):
            client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
            # Should use httpx.Timeout(None) when no env vars set
            assert client.d2ir_params.d2ir_timeout.connect is None
            assert client.d2ir_params.d2ir_timeout.read is None
    
    @patch_auth_decorator
    def test_timeout_none_branch(self):
        """Test behavior when timeout is explicitly None."""
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f', timeout=None)
        assert client.d2ir_params.d2ir_timeout.connect is None
        assert client.d2ir_params.d2ir_timeout.read is None
    
    @patch_auth_decorator
    def test_timeout_user_branch(self):
        """Test behavior when user provides timeout."""
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f', timeout=45)
        assert client.d2ir_params.d2ir_timeout.connect == 45
        assert client.d2ir_params.d2ir_timeout.read == 45
    
    @patch_auth_decorator
    def test_timeout_env_branch(self):
        """Test behavior when timeout is set via environment."""
        with patch.dict(os.environ, {'D2IR_HTTP_TIMEOUT': '60'}):
            # Need to patch the HTTPX_TIMEOUT constant since it's set at import time
            with patch('d2irclient.D2IRClient.HTTPX_TIMEOUT', 60.0):
                client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
                assert client.d2ir_params.d2ir_timeout.connect == 60.0
                assert client.d2ir_params.d2ir_timeout.read == 60.0
    
    @patch_auth_decorator
    def test_timeout_env_invalid(self):
        """Test behavior when environment timeout is invalid."""
        with patch.dict(os.environ, {'D2IR_HTTP_TIMEOUT': 'invalid'}):
            client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
            # Invalid env value should result in None timeout
            assert client.d2ir_params.d2ir_timeout.connect is None
            assert client.d2ir_params.d2ir_timeout.read is None


@pytest.mark.integration
class TestIntegrationScenarios:
    """Integration-style tests that test multiple components together."""
    
    @patch_auth_decorator
    def test_full_sync_workflow(self):
        """Test a complete sync workflow."""
        client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
        
        # Mock the entire HTTP client
        mock_http_client = MagicMock()
        
        # Setup responses for different endpoints
        mock_response = MagicMock()
        mock_response.json.return_value = {'workflow': 'complete'}
        mock_response.raise_for_status.return_value = None
        
        mock_http_client.get.return_value = mock_response
        mock_http_client.post.return_value = mock_response
        mock_http_client.put.return_value = mock_response
        mock_http_client.delete.return_value = mock_response
        
        client.http_client = mock_http_client
        
        # Perform a sequence of operations
        get_result = client.d2ir_get('/items')
        post_result = client.d2ir_post('/items', json={'new': 'item'})
        put_result = client.d2ir_put('/items/123', json={'updated': 'item'})
        delete_result = client.d2ir_delete('/items/123')
        
        # Verify all operations succeeded
        assert get_result == {'workflow': 'complete'}
        assert post_result == {'workflow': 'complete'}
        assert put_result == {'workflow': 'complete'}
        assert delete_result == {'workflow': 'complete'}
        
        # Verify all HTTP methods were called
        assert mock_http_client.get.call_count == 1
        assert mock_http_client.post.call_count == 1
        assert mock_http_client.put.call_count == 1
        assert mock_http_client.delete.call_count == 1
    
    @pytest.mark.asyncio
    async def test_full_async_workflow(self):
        """Test a complete async workflow."""
        with patch('d2irclient.D2IRClient.D2IRAuth', DummyAuth):
            client = D2IRClient('http://a', 'http://b', 'c', 'd', 'e', 'f')
            
            # Mock the entire async HTTP client
            mock_async_client = AsyncMock()
            
            # Setup responses for different endpoints
            mock_response = MagicMock()
            mock_response.json.return_value = {'async_workflow': 'complete'}
            mock_response.raise_for_status.return_value = None
            
            mock_async_client.get.return_value = mock_response
            mock_async_client.post.return_value = mock_response
            mock_async_client.put.return_value = mock_response
            mock_async_client.delete.return_value = mock_response
            
            client.async_http_client = mock_async_client
            
            # Perform a sequence of async operations
            get_result = await client.d2ir_get_async('/items')
            post_result = await client.d2ir_post_async('/items', json={'new': 'item'})
            put_result = await client.d2ir_put_async('/items/123', json={'updated': 'item'})
            delete_result = await client.d2ir_delete_async('/items/123')
            
            # Verify all operations succeeded
            assert get_result == {'async_workflow': 'complete'}
            assert post_result == {'async_workflow': 'complete'}
            assert put_result == {'async_workflow': 'complete'}
            assert delete_result == {'async_workflow': 'complete'}
            
            # Verify all async HTTP methods were called
            assert mock_async_client.get.call_count == 1
            assert mock_async_client.post.call_count == 1
            assert mock_async_client.put.call_count == 1
            assert mock_async_client.delete.call_count == 1


@pytest.mark.slow  
class TestEdgeCases:
    """Test edge cases and unusual scenarios."""
    
    def test_empty_response_handling(self):
        """Test handling of empty responses."""
        client = create_mock_client_with_response({}, method='get')
        result = client.d2ir_get('/empty')
        assert result == {}
    
    @pytest.mark.asyncio
    async def test_async_empty_response_handling(self):
        """Test handling of empty responses in async operations."""
        client = await create_mock_async_client_with_response({}, method='get')
        result = await client.d2ir_get_async('/empty')
        assert result == {}
    
    def test_large_response_handling(self):
        """Test handling of large responses."""
        large_data = {'data': ['item'] * 1000}
        client = create_mock_client_with_response(large_data, method='get')
        result = client.d2ir_get('/large')
        assert len(result['data']) == 1000
    
    @pytest.mark.asyncio
    async def test_async_large_response_handling(self):
        """Test handling of large responses in async operations."""
        large_data = {'data': ['item'] * 1000}
        client = await create_mock_async_client_with_response(large_data, method='get')
        result = await client.d2ir_get_async('/large')
        assert len(result['data']) == 1000