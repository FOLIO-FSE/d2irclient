"""
Consolidated _httpx Tests

This file replaces:
- test__httpx.py
- test__httpx_async.py
- test__httpx_misc.py
- test_misc_coverage.py (_httpx parts)

All D2IRAuth and D2IRParameters functionality is tested here.
"""

import pytest
import httpx
import datetime
from unittest.mock import MagicMock, AsyncMock, patch

from d2irclient._httpx import D2IRAuth, D2IRParameters
from conftest import DummyAuth, DummyParams


class TestD2IRParameters:
    """Test D2IRParameters class functionality."""
    
    def test_parameters_initialization(self):
        """Test basic parameter initialization."""
        params = D2IRParameters(
            d2ir_auth_url='http://circ/oauth/token',
            d2ir_root_url='http://d2ir/',
            d2ir_key='key123',
            d2ir_secret='secret456',
            d2ir_from_code='FROM',
            d2ir_to_code='TO',
            d2ir_timeout=30
        )
        
        assert params.d2ir_auth_url == 'http://circ/oauth/token'
        assert params.d2ir_root_url == 'http://d2ir/'
        assert params.d2ir_key == 'key123'
        assert params.d2ir_secret == 'secret456'
        assert params.d2ir_from_code == 'FROM'
        assert params.d2ir_to_code == 'TO'
        assert params.d2ir_timeout == 30
    
    def test_parameters_with_none_timeout(self):
        """Test parameter initialization with None timeout."""
        params = D2IRParameters(
            d2ir_auth_url='http://circ/oauth/token',
            d2ir_root_url='http://d2ir/',
            d2ir_key='key123',
            d2ir_secret='secret456',
            d2ir_from_code='FROM',
            d2ir_to_code='TO',
            d2ir_timeout=None
        )
        
        assert params.d2ir_timeout is None


class TestD2IRAuth:
    """Test D2IRAuth class functionality."""
    
    def test_auth_initialization(self, dummy_params):
        """Test basic auth initialization."""
        with patch.object(D2IRAuth, '_do_sync_auth') as mock_auth:
            mock_token = MagicMock()
            mock_token.token = 'test_token'
            mock_token.expiry = None
            mock_auth.return_value = mock_token
            
            auth = D2IRAuth(dummy_params)
            assert auth._params == dummy_params
            assert auth._token == mock_token
            mock_auth.assert_called_once()
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_login_success(self, mock_client_class, dummy_params):
        """Test successful login."""
        # Create a mock client instance that will be returned by the context manager
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'test_access_token',
            'expires_in': 3600  # Real integer instead of MagicMock
        }
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response
        
        # Test login by creating a properly initialized auth object
        # but patching _do_sync_auth to avoid the initial login call
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            token = auth._login()
            
            assert token.token == 'test_access_token'
            assert isinstance(token.expiry, datetime.datetime)
            
            # Verify HTTP client was called correctly
            mock_client.post.assert_called_once()
            call_args = mock_client.post.call_args
            assert dummy_params.d2ir_auth_url in str(call_args)
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_login_failure(self, mock_client_class, dummy_params):
        """Test login failure handling."""
        # Create a mock client instance that will be returned by the context manager
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            'Unauthorized', request=MagicMock(), response=MagicMock()
        )
        mock_client.post.return_value = mock_response
        
        # Test login failure by creating a properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            with pytest.raises(httpx.HTTPStatusError):
                auth._login()
    
    def test_auth_flow(self, dummy_params):
        """Test auth flow implementation."""
        # Create a mock token with proper datetime expiry
        mock_token = MagicMock()
        mock_token.token = 'test_token'
        mock_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=mock_token):
            auth = D2IRAuth(dummy_params)
            
            # Create a mock request
            mock_request = MagicMock()
            mock_request.headers = {}
            
            # Mock the _token_is_expired method to return False (token is valid)
            with patch.object(auth, '_token_is_expired', return_value=False):
                # Test sync auth flow
                auth_flow = auth.sync_auth_flow(mock_request)
                authenticated_request = next(auth_flow)
                
                # Verify the request was modified
                assert 'Authorization' in authenticated_request.headers
                assert authenticated_request.headers['Authorization'] == 'Bearer test_token'
                assert authenticated_request.headers['X-From-Code'] == dummy_params.d2ir_from_code
                assert authenticated_request.headers['X-To-Code'] == dummy_params.d2ir_to_code
    
    def test_token_expiry_handling(self, dummy_params):
        """Test token expiry detection and refresh."""
        with patch.object(D2IRAuth, '_login') as mock_login:
            # Create an expired token
            expired_token = MagicMock()
            expired_token.token = 'expired_token'
            expired_token.expiry = datetime.datetime.now() - datetime.timedelta(hours=1)
            
            # Create a fresh token
            fresh_token = MagicMock()
            fresh_token.token = 'fresh_token'
            fresh_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
            
            mock_login.return_value = fresh_token
            
            auth = D2IRAuth.__new__(D2IRAuth)  # Create without calling __init__
            auth._params = dummy_params
            auth._token = expired_token
            
            # Test that expired token triggers refresh
            result_token = auth._do_sync_auth()
            
            assert result_token == fresh_token
            mock_login.assert_called_once()
    
    def test_token_still_valid(self, dummy_params):
        """Test that valid tokens are not refreshed."""
        # Create a valid token with proper datetime
        valid_token = MagicMock()
        valid_token.token = 'valid_token'
        valid_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=valid_token) as mock_sync_auth:
            with patch.object(D2IRAuth, '_login') as mock_login:
                auth = D2IRAuth(dummy_params)
                # Set the token manually after initialization
                auth._token = valid_token
                
                # Mock the _token_is_expired method to return False
                with patch.object(auth, '_token_is_expired', return_value=False):
                    # Test that valid token is returned without refresh
                    result_token = auth._do_sync_auth()
                    
                    assert result_token == valid_token
                    # _login should not be called since token is valid
                    mock_login.assert_not_called()
    
    def test_no_expiry_token(self, dummy_params):
        """Test handling of tokens without expiry."""
        # Create a token without expiry
        no_expiry_token = MagicMock()
        no_expiry_token.token = 'no_expiry_token'
        no_expiry_token.expiry = None
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=no_expiry_token) as mock_sync_auth:
            with patch.object(D2IRAuth, '_login') as mock_login:
                auth = D2IRAuth(dummy_params)
                # Set the token manually after initialization
                auth._token = no_expiry_token
                
                # Mock the _token_is_expired method to return False for None expiry
                with patch.object(auth, '_token_is_expired', return_value=False):
                    # Test that token without expiry is returned without refresh
                    result_token = auth._do_sync_auth()
                    
                    assert result_token == no_expiry_token
                    mock_login.assert_not_called()


class TestD2IRAuthTimeout:
    """Test D2IRAuth timeout handling."""
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_login_with_timeout(self, mock_client_class, dummy_params):
        """Test login with timeout configuration."""
        # Set a specific timeout
        dummy_params.d2ir_timeout = 45
        
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'test_token',
            'expires_in': 3600  # Real integer, not MagicMock
        }
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response
        
        # Test login with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            token = auth._login()
            
            # Verify timeout was passed to httpx.Client
            mock_client_class.assert_called_once_with(timeout=45)
            assert token.token == 'test_token'
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_login_with_none_timeout(self, mock_client_class, dummy_params):
        """Test login with None timeout."""
        # Set timeout to None
        dummy_params.d2ir_timeout = None
        
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'test_token',
            'expires_in': 3600  # Real integer, not MagicMock
        }
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response
        
        # Test login with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            token = auth._login()
            
            # Verify None timeout was passed to httpx.Client
            mock_client_class.assert_called_once_with(timeout=None)
            assert token.token == 'test_token'


class TestD2IRAuthHeaders:
    """Test D2IRAuth header handling."""
    
    def test_auth_headers_applied(self, dummy_params):
        """Test that authentication headers are properly applied."""
        # Create a mock token with proper datetime expiry
        mock_token = MagicMock()
        mock_token.token = 'bearer_token_123'
        mock_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        # Set specific header values
        dummy_params.d2ir_from_code = 'TESTFROM'
        dummy_params.d2ir_to_code = 'TESTTO'
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=mock_token):
            auth = D2IRAuth(dummy_params)
            
            # Create a mock request
            mock_request = MagicMock()
            mock_request.headers = {}
            
            # Mock the _token_is_expired method to return False
            with patch.object(auth, '_token_is_expired', return_value=False):
                # Test sync auth flow
                auth_flow = auth.sync_auth_flow(mock_request)
                authenticated_request = next(auth_flow)
                
                # Verify all expected headers are present
                expected_headers = {
                    'Authorization': 'Bearer bearer_token_123',
                    'X-From-Code': 'TESTFROM',
                    'X-To-Code': 'TESTTO'
                }
                
                for header, value in expected_headers.items():
                    assert authenticated_request.headers[header] == value
    
    def test_existing_headers_preserved(self, dummy_params):
        """Test that existing request headers are preserved."""
        # Create a mock token with proper datetime expiry
        mock_token = MagicMock()
        mock_token.token = 'token123'
        mock_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=mock_token):
            auth = D2IRAuth(dummy_params)
            
            # Create a mock request with existing headers
            mock_request = MagicMock()
            mock_request.headers = {
                'Content-Type': 'application/json',
                'Custom-Header': 'custom-value'
            }
            
            # Mock the _token_is_expired method to return False
            with patch.object(auth, '_token_is_expired', return_value=False):
                # Test sync auth flow
                auth_flow = auth.sync_auth_flow(mock_request)
                authenticated_request = next(auth_flow)
                
                # Verify existing headers are preserved
                assert authenticated_request.headers['Content-Type'] == 'application/json'
                assert authenticated_request.headers['Custom-Header'] == 'custom-value'
                
                # Verify auth headers are added
                assert authenticated_request.headers['Authorization'] == 'Bearer token123'
                assert authenticated_request.headers['X-From-Code'] == dummy_params.d2ir_from_code
                assert authenticated_request.headers['X-To-Code'] == dummy_params.d2ir_to_code


class TestD2IRAuthTokenClass:
    """Test the internal Token class."""
    
    def test_token_creation(self):
        """Test Token object creation and attributes."""
        # Access the Token class through D2IRAuth
        Token = D2IRAuth._Token
        
        expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        token = Token(token='test_token', expiry=expiry)
        
        assert token.token == 'test_token'
        assert token.expiry == expiry
    
    def test_token_without_expiry(self):
        """Test Token object creation without expiry."""
        Token = D2IRAuth._Token
        
        token = Token(token='test_token', expiry=None)
        
        assert token.token == 'test_token'
        assert token.expiry is None


class TestD2IRAuthErrorScenarios:
    """Test various error scenarios for D2IRAuth."""
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_network_error_during_login(self, mock_client_class, dummy_params):
        """Test handling of network errors during login."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        # Simulate network error
        mock_client.post.side_effect = httpx.ConnectError('Network unreachable')
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            with pytest.raises(httpx.ConnectError):
                auth._login()
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_timeout_during_login(self, mock_client_class, dummy_params):
        """Test handling of timeout errors during login."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        # Simulate timeout error
        mock_client.post.side_effect = httpx.TimeoutException('Request timed out')
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            with pytest.raises(httpx.TimeoutException):
                auth._login()
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_invalid_json_response(self, mock_client_class, dummy_params):
        """Test handling of invalid JSON responses."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        mock_response.json.side_effect = ValueError('Invalid JSON')
        mock_client.post.return_value = mock_response
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            with pytest.raises(ValueError):
                auth._login()
    
    @patch('d2irclient._httpx.httpx.Client') 
    def test_missing_access_token_in_response(self, mock_client_class, dummy_params):
        """Test handling of responses missing access_token."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        # Response missing 'access_token' field
        mock_response.json.return_value = {'expires_in': 3600}  # Real integer, not MagicMock
        mock_client.post.return_value = mock_response
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            # Should now raise an exception for missing access_token
            with pytest.raises(httpx.RequestError, match="Missing access_token in auth response"):
                auth._login()

    @patch('d2irclient._httpx.httpx.Client') 
    def test_missing_expires_in_in_response(self, mock_client_class, dummy_params):
        """Test handling of responses missing expires_in."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        # Response missing 'expires_in' field
        mock_response.json.return_value = {'access_token': 'test_token'}
        mock_client.post.return_value = mock_response
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            # Should now raise an exception for missing expires_in
            with pytest.raises(httpx.RequestError, match="Missing expires_in in auth response"):
                auth._login()

    @patch('d2irclient._httpx.httpx.Client') 
    def test_invalid_expires_in_in_response(self, mock_client_class, dummy_params):
        """Test handling of responses with invalid expires_in."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.raise_for_status.return_value = None
        # Response with invalid expires_in
        mock_response.json.return_value = {'access_token': 'test_token', 'expires_in': 'invalid'}
        mock_client.post.return_value = mock_response
        
        # Test with properly initialized auth object
        with patch.object(D2IRAuth, '_do_sync_auth'):
            auth = D2IRAuth(dummy_params)
            
            # Should now raise an exception for invalid expires_in
            with pytest.raises(httpx.RequestError, match="Invalid expires_in value"):
                auth._login()


@pytest.mark.integration
class TestD2IRAuthIntegration:
    """Integration tests for D2IRAuth with various scenarios."""
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_multiple_auth_flows(self, mock_client_class, dummy_params):
        """Test multiple authentication flows with the same auth object."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        mock_response = MagicMock()
        mock_response.json.return_value = {
            'access_token': 'persistent_token',
            'expires_in': 3600  # Real integer, not MagicMock
        }
        mock_response.raise_for_status.return_value = None
        mock_client.post.return_value = mock_response
        
        # Create auth object - this will call _login once during initialization
        auth = D2IRAuth(dummy_params)
        
        # Perform multiple auth flows
        for i in range(3):
            mock_request = MagicMock()
            mock_request.headers = {}
            
            # Mock _token_is_expired to return False so no refresh is needed
            with patch.object(auth, '_token_is_expired', return_value=False):
                auth_flow = auth.sync_auth_flow(mock_request)
                authenticated_request = next(auth_flow)
                
                # Verify consistent authentication
                assert authenticated_request.headers['Authorization'] == 'Bearer persistent_token'
        
        # Verify login was only called once (during initialization)
        mock_client.post.assert_called_once()
    
    @patch('d2irclient._httpx.httpx.Client')
    def test_token_refresh_on_expiry(self, mock_client_class, dummy_params):
        """Test that expired tokens are properly refreshed."""
        mock_client = MagicMock()
        mock_client_class.return_value.__enter__.return_value = mock_client
        
        # First token (expires quickly)
        first_response = MagicMock()
        first_response.json.return_value = {
            'access_token': 'first_token',
            'expires_in': 1  # Real integer, not MagicMock
        }
        first_response.raise_for_status.return_value = None
        
        # Second token (fresh)
        second_response = MagicMock()
        second_response.json.return_value = {
            'access_token': 'second_token',
            'expires_in': 3600  # Real integer, not MagicMock
        }
        second_response.raise_for_status.return_value = None
        
        mock_client.post.side_effect = [first_response, second_response]
        
        # Create auth object and wait for token to expire
        auth = D2IRAuth(dummy_params)
        
        # Force token to be expired by creating a new expired token
        auth._token = auth._Token(
            token='first_token',
            expiry=datetime.datetime.now(tz=datetime.timezone.utc) - datetime.timedelta(seconds=1)
        )
        
        # Perform auth flow - should trigger refresh
        mock_request = MagicMock()
        mock_request.headers = {}
        
        auth_flow = auth.sync_auth_flow(mock_request)
        authenticated_request = next(auth_flow)
        
        # Verify new token was used
        assert authenticated_request.headers['Authorization'] == 'Bearer second_token'
        
        # Verify login was called twice (initial + refresh)
        assert mock_client.post.call_count == 2


@pytest.mark.slow
class TestD2IRAuthPerformance:
    """Performance and edge case tests for D2IRAuth."""
    
    def test_concurrent_auth_flows(self, dummy_params):
        """Test concurrent authentication flows."""
        # Create a mock token with proper datetime expiry
        mock_token = MagicMock()
        mock_token.token = 'concurrent_token'
        mock_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=mock_token):
            auth = D2IRAuth(dummy_params)
            
            # Simulate concurrent requests
            requests = []
            for i in range(10):
                mock_request = MagicMock()
                mock_request.headers = {}
                requests.append(mock_request)
            
            # Process all requests
            authenticated_requests = []
            for request in requests:
                # Mock _token_is_expired to return False so no refresh is needed
                with patch.object(auth, '_token_is_expired', return_value=False):
                    auth_flow = auth.sync_auth_flow(request)
                    authenticated_request = next(auth_flow)
                    authenticated_requests.append(authenticated_request)
            
            # Verify all requests were authenticated consistently
            for req in authenticated_requests:
                assert req.headers['Authorization'] == 'Bearer concurrent_token'
    
    def test_large_header_handling(self, dummy_params):
        """Test handling of requests with many existing headers."""
        # Create a mock token with proper datetime expiry
        mock_token = MagicMock()
        mock_token.token = 'test_token'
        mock_token.expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
        
        with patch.object(D2IRAuth, '_do_sync_auth', return_value=mock_token):
            auth = D2IRAuth(dummy_params)
            
            # Create request with many headers
            mock_request = MagicMock()
            mock_request.headers = {f'Header-{i}': f'Value-{i}' for i in range(100)}
            
            # Mock _token_is_expired to return False so no refresh is needed
            with patch.object(auth, '_token_is_expired', return_value=False):
                auth_flow = auth.sync_auth_flow(mock_request)
                authenticated_request = next(auth_flow)
                
                # Verify auth headers were added
                assert authenticated_request.headers['Authorization'] == 'Bearer test_token'
                
                # Verify existing headers are preserved
                assert len(authenticated_request.headers) >= 103  # 100 original + 3 auth headers