# File: tests/test_auth_flows.py

import pytest
from django.test import TestCase, Client
from django.urls import reverse
from unittest.mock import patch, MagicMock
import json
import uuid

from users.models import Profile
from auth_integration.supabase_client import SupabaseClient


class AuthFlowTestCase(TestCase):
    """
    Test authentication flows: signup, login, password reset.
    """
    
    def setUp(self):
        self.client = Client()
        self.signup_url = reverse('auth_integration:signup')
        self.login_url = reverse('auth_integration:login')
        self.forgot_password_url = reverse('auth_integration:forgot_password')
        self.reset_password_url = reverse('auth_integration:reset_password')
        
        self.valid_signup_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'phone': '+1234567890',
            'company': 'Test Company',
            'business_type': 'Technology & Electronics',
            'city': 'New York',
            'state': 'NY',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123'
        }
        
        self.valid_login_data = {
            'email': 'john.doe@example.com',
            'password': 'SecurePass123'
        }
    
    @patch('auth_integration.views.SupabaseClient')
    def test_signup_success(self, mock_supabase_client):
        """Test successful user signup."""
        # Mock Supabase client
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        # Mock successful user creation
        user_id = str(uuid.uuid4())
        mock_client_instance.create_user.return_value = {
            'success': True,
            'user': {
                'id': user_id,
                'email': 'john.doe@example.com'
            }
        }
        
        # Make request
        response = self.client.post(
            self.signup_url,
            data=json.dumps(self.valid_signup_data),
            content_type='application/json'
        )
        
        # Assertions
        self.assertEqual(response.status_code, 201)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['user']['email'], 'john.doe@example.com')
        
        # Verify Profile was created
        profile = Profile.objects.get(email='john.doe@example.com')
        self.assertEqual(profile.first_name, 'John')
        self.assertEqual(profile.last_name, 'Doe')
        self.assertEqual(profile.company, 'Test Company')
    
    def test_signup_validation_errors(self):
        """Test signup with validation errors."""
        invalid_data = self.valid_signup_data.copy()
        invalid_data['email'] = 'invalid-email'
        invalid_data['password'] = '123'  # Too short
        invalid_data['confirm_password'] = '456'  # Doesn't match
        
        response = self.client.post(
            self.signup_url,
            data=json.dumps(invalid_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('errors', response_data)
        self.assertIn('email', response_data['errors'])
        self.assertIn('password', response_data['errors'])
    
    def test_signup_custom_business_type(self):
        """Test signup with custom business type."""
        custom_data = self.valid_signup_data.copy()
        custom_data['business_type'] = 'Other'
        custom_data['custom_business_type'] = 'Consulting Services'
        
        with patch('auth_integration.views.SupabaseClient') as mock_supabase_client:
            mock_client_instance = MagicMock()
            mock_supabase_client.return_value = mock_client_instance
            
            user_id = str(uuid.uuid4())
            mock_client_instance.create_user.return_value = {
                'success': True,
                'user': {'id': user_id, 'email': 'john.doe@example.com'}
            }
            
            response = self.client.post(
                self.signup_url,
                data=json.dumps(custom_data),
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 201)
            
            # Verify custom business type was used
            profile = Profile.objects.get(email='john.doe@example.com')
            self.assertEqual(profile.business_type, 'Consulting Services')
    
    @patch('auth_integration.views.SupabaseClient')
    def test_login_success(self, mock_supabase_client):
        """Test successful login."""
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        user_id = str(uuid.uuid4())
        mock_client_instance.sign_in.return_value = {
            'success': True,
            'user': {
                'id': user_id,
                'email': 'john.doe@example.com',
                'email_confirmed_at': '2024-01-01T00:00:00Z'
            },
            'session': {
                'access_token': 'mock-access-token',
                'refresh_token': 'mock-refresh-token',
                'expires_in': 3600,
                'expires_at': 1234567890
            }
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(self.valid_login_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('session', response_data)
        self.assertEqual(response_data['user']['email'], 'john.doe@example.com')
    
    @patch('auth_integration.views.SupabaseClient')
    def test_login_invalid_credentials(self, mock_supabase_client):
        """Test login with invalid credentials."""
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        mock_client_instance.sign_in.return_value = {
            'success': False,
            'error': 'INVALID_CREDENTIALS'
        }
        
        response = self.client.post(
            self.login_url,
            data=json.dumps(self.valid_login_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 401)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'INVALID_CREDENTIALS')
    
    @patch('auth_integration.views.SupabaseClient')
    def test_forgot_password(self, mock_supabase_client):
        """Test forgot password request."""
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        mock_client_instance.send_password_reset_email.return_value = {
            'success': True
        }
        
        response = self.client.post(
            self.forgot_password_url,
            data=json.dumps({'email': 'john.doe@example.com'}),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('receive password reset instructions', response_data['message'])
    
    @patch('auth_integration.views.SupabaseClient')
    def test_reset_password_success(self, mock_supabase_client):
        """Test successful password reset."""
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        mock_client_instance.reset_password.return_value = {
            'success': True
        }
        
        reset_data = {
            'access_token': 'valid-reset-token',
            'password': 'NewSecurePass123',
            'confirm_password': 'NewSecurePass123'
        }
        
        response = self.client.post(
            self.reset_password_url,
            data=json.dumps(reset_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertIn('Password reset successful', response_data['message'])
    
    def test_reset_password_validation(self):
        """Test password reset with validation errors."""
        reset_data = {
            'access_token': 'valid-reset-token',
            'password': 'weak',  # Too weak
            'confirm_password': 'different'  # Doesn't match
        }
        
        response = self.client.post(
            self.reset_password_url,
            data=json.dumps(reset_data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('errors', response_data)


class JWTMiddlewareTestCase(TestCase):
    """
    Test JWT middleware functionality.
    """
    
    def setUp(self):
        self.client = Client()
        self.protected_url = reverse('auth_integration:user_profile')
        self.valid_jwt_payload = {
            'sub': str(uuid.uuid4()),
            'email': 'test@example.com',
            'email_confirmed_at': '2024-01-01T00:00:00Z',
            'role': 'authenticated',
            'exp': 9999999999,  # Far future
            'iat': 1234567890,
            'iss': 'https://test.supabase.co/auth/v1'
        }
    
    @patch('auth_integration.middleware.jwt.decode')
    def test_valid_jwt_authentication(self, mock_jwt_decode):
        """Test valid JWT token authentication."""
        mock_jwt_decode.return_value = self.valid_jwt_payload
        
        # Create profile for the user
        Profile.objects.create(
            id=self.valid_jwt_payload['sub'],
            first_name='Test',
            last_name='User',
            email='test@example.com',
            phone='+1234567890',
            company='Test Co',
            business_type='Other',
            city='Test City',
            state='Test State',
            is_verified=True
        )
        
        response = self.client.get(
            self.protected_url,
            HTTP_AUTHORIZATION='Bearer valid-jwt-token'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
    
    def test_missing_authorization_header(self):
        """Test request without authorization header."""
        response = self.client.get(self.protected_url)
        
        self.assertEqual(response.status_code, 401)
    
    @patch('auth_integration.middleware.jwt.decode')
    def test_unverified_email_rejection(self, mock_jwt_decode):
        """Test that unverified emails are rejected."""
        payload = self.valid_jwt_payload.copy()
        payload['email_confirmed_at'] = None  # Email not verified
        mock_jwt_decode.return_value = payload
        
        response = self.client.get(
            self.protected_url,
            HTTP_AUTHORIZATION='Bearer unverified-jwt-token'
        )
        
        self.assertEqual(response.status_code, 403)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'EMAIL_NOT_VERIFIED')
    
    @patch('auth_integration.middleware.jwt.decode')
    def test_expired_jwt_token(self, mock_jwt_decode):
        """Test expired JWT token handling."""
        from jwt import ExpiredSignatureError
        mock_jwt_decode.side_effect = ExpiredSignatureError()
        
        response = self.client.get(
            self.protected_url,
            HTTP_AUTHORIZATION='Bearer expired-jwt-token'
        )
        
        self.assertEqual(response.status_code, 401)
        response_data = response.json()
        self.assertEqual(response_data['code'], 'TOKEN_EXPIRED')


class IntegrationTestCase(TestCase):
    """
    Integration tests for complete auth flows.
    """
    
    @patch('auth_integration.views.SupabaseClient')
    @patch('auth_integration.middleware.jwt.decode')
    def test_signup_login_protected_endpoint_flow(self, mock_jwt_decode, mock_supabase_client):
        """Test complete flow: signup -> login -> access protected endpoint."""
        
        # Step 1: Signup
        mock_client_instance = MagicMock()
        mock_supabase_client.return_value = mock_client_instance
        
        user_id = str(uuid.uuid4())
        mock_client_instance.create_user.return_value = {
            'success': True,
            'user': {
                'id': user_id,
                'email': 'integration@example.com'
            }
        }
        
        signup_data = {
            'first_name': 'Integration',
            'last_name': 'Test',
            'email': 'integration@example.com',
            'phone': '+1234567890',
            'company': 'Test Company',
            'business_type': 'Technology & Electronics',
            'city': 'Test City',
            'state': 'Test State',
            'password': 'SecurePass123',
            'confirm_password': 'SecurePass123'
        }
        
        signup_response = self.client.post(
            reverse('auth_integration:signup'),
            data=json.dumps(signup_data),
            content_type='application/json'
        )
        
        self.assertEqual(signup_response.status_code, 201)
        
        # Step 2: Login
        mock_client_instance.sign_in.return_value = {
            'success': True,
            'user': {
                'id': user_id,
                'email': 'integration@example.com',
                'email_confirmed_at': '2024-01-01T00:00:00Z'
            },
            'session': {
                'access_token': 'integration-jwt-token',
                'refresh_token': 'integration-refresh-token',
                'expires_in': 3600,
                'expires_at': 9999999999
            }
        }
        
        login_response = self.client.post(
            reverse('auth_integration:login'),
            data=json.dumps({
                'email': 'integration@example.com',
                'password': 'SecurePass123'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(login_response.status_code, 200)
        login_data = login_response.json()
        access_token = login_data['session']['access_token']
        
        # Step 3: Access protected endpoint
        mock_jwt_decode.return_value = {
            'sub': user_id,
            'email': 'integration@example.com',
            'email_confirmed_at': '2024-01-01T00:00:00Z',
            'role': 'authenticated',
            'exp': 9999999999,
            'iat': 1234567890
        }
        
        # Mark profile as verified for the test
        profile = Profile.objects.get(id=user_id)
        profile.is_verified = True
        profile.save()
        
        protected_response = self.client.get(
            reverse('auth_integration:user_profile'),
            HTTP_AUTHORIZATION=f'Bearer {access_token}'
        )
        
        self.assertEqual(protected_response.status_code, 200)
        profile_data = protected_response.json()
        self.assertTrue(profile_data['success'])
        self.assertEqual(profile_data['user']['email'], 'integration@example.com')
        self.assertEqual(profile_data['user']['first_name'], 'Integration')