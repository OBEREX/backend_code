import json
import uuid
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.urls import reverse
from django.core.cache import cache
from django.test.utils import override_settings


class ResendOTPTestCase(TestCase):
    """
    Test cases for the ResendOTPView endpoint.
    """
    
    def setUp(self):
        """Set up test data."""
        self.resend_otp_url = reverse('auth_integration:resend_otp')
        self.test_email = 'test@example.com'
        self.test_phone = '+1234567890'
        
        # Clear cache before each test
        cache.clear()
    
    def tearDown(self):
        """Clean up after each test."""
        cache.clear()
    
    # ==========================================
    # VALIDATION TESTS
    # ==========================================
    
    def test_resend_otp_missing_email_and_phone(self):
        """Test validation error when both email and phone are missing."""
        data = {'type': 'registration'}
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertIn('errors', response_data)
    
    def test_resend_otp_both_email_and_phone(self):
        """Test validation error when both email and phone are provided."""
        data = {
            'email': self.test_email,
            'phone': self.test_phone,
            'type': 'registration'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
        response_data = response.json()
        self.assertFalse(response_data['success'])
    
    def test_resend_otp_invalid_email(self):
        """Test validation error with invalid email."""
        data = {
            'email': 'invalid-email',
            'type': 'registration'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    def test_resend_otp_invalid_type(self):
        """Test validation error with invalid verification type."""
        data = {
            'email': self.test_email,
            'type': 'invalid_type'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 400)
    
    # ==========================================
    # SUCCESSFUL RESEND TESTS
    # ==========================================
    
    @patch('auth_integration.views.ResendOTPView._send_email_otp')
    @patch('auth_integration.views.ResendOTPView._check_user_exists')
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_registration_otp_success(self, mock_supabase, mock_user_exists, mock_send_email):
        """Test successful registration OTP resend."""
        # Setup mocks
        mock_user_exists.return_value = True
        mock_send_email.return_value = True
        
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = {
            'otp': '123456',
            'expires_in': 600
        }
        
        data = {
            'email': self.test_email,
            'type': 'registration'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['type'], 'registration')
        self.assertEqual(response_data['sent_to'], self.test_email)
        self.assertEqual(response_data['expires_in'], 600)
        
        # Verify function calls
        mock_user_exists.assert_called_once_with(self.test_email)
        mock_client_instance.generate_otp.assert_called_once_with(
            email=self.test_email,
            phone=None,
            type='registration'
        )
        mock_send_email.assert_called_once_with(self.test_email, '123456', 'registration')
    
    @patch('auth_integration.views.ResendOTPView._send_email_otp')
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_password_reset_otp_success(self, mock_supabase, mock_send_email):
        """Test successful password reset OTP resend."""
        # Setup mocks
        mock_send_email.return_value = True
        
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = '654321'
        
        data = {
            'email': self.test_email,
            'type': 'password_reset'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['type'], 'password_reset')
        
        # Password reset doesn't check user exists (different flow)
        mock_client_instance.generate_otp.assert_called_once_with(
            email=self.test_email,
            phone=None,
            type='password_reset'
        )
    
    @patch('auth_integration.views.ResendOTPView._send_sms_otp')
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_phone_verification_otp_success(self, mock_supabase, mock_send_sms):
        """Test successful phone verification OTP resend."""
        # Setup mocks
        mock_send_sms.return_value = True
        
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = '789123'
        
        data = {
            'phone': self.test_phone,
            'type': 'phone_verification'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['sent_to'], self.test_phone)
        
        mock_send_sms.assert_called_once_with(self.test_phone, '789123', 'phone_verification')
    
    # ==========================================
    # ERROR HANDLING TESTS
    # ==========================================
    
    @patch('auth_integration.views.ResendOTPView._check_user_exists')
    def test_resend_registration_otp_user_not_found(self, mock_user_exists):
        """Test registration OTP resend when user doesn't exist."""
        mock_user_exists.return_value = False
        
        data = {
            'email': self.test_email,
            'type': 'registration'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 404)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'USER_NOT_FOUND')
    
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_otp_generation_failed(self, mock_supabase):
        """Test OTP resend when generation fails."""
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = None  # Generation failed
        
        data = {
            'email': self.test_email,
            'type': 'email_verification'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'OTP_GENERATION_FAILED')
    
    @patch('auth_integration.views.ResendOTPView._send_email_otp')
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_otp_delivery_failed(self, mock_supabase, mock_send_email):
        """Test OTP resend when delivery fails."""
        # Setup mocks
        mock_send_email.return_value = False  # Delivery failed
        
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = '123456'
        
        data = {
            'email': self.test_email,
            'type': 'email_verification'
        }
        
        response = self.client.post(
            self.resend_otp_url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 500)
        response_data = response.json()
        self.assertFalse(response_data['success'])
        self.assertEqual(response_data['error'], 'DELIVERY_FAILED')
    
    # ==========================================
    # RATE LIMITING TESTS  
    # ==========================================
    
    @override_settings(CACHES={
        'default': {
            'BACKEND': 'django.core.cache.backends.locmem.LocMemCache',
        }
    })
    def test_resend_otp_rate_limiting(self):
        """Test rate limiting prevents too many requests."""
        # Mock successful generation and sending
        with patch('auth_integration.views.SupabaseClient') as mock_supabase, \
             patch('auth_integration.views.ResendOTPView._send_email_otp') as mock_send_email:
            
            mock_send_email.return_value = True
            mock_client_instance = MagicMock()
            mock_supabase.return_value = mock_client_instance
            mock_client_instance.generate_otp.return_value = '123456'
            
            data = {
                'email': self.test_email,
                'type': 'email_verification'
            }
            
            # First 3 requests should succeed
            for i in range(3):
                response = self.client.post(
                    self.resend_otp_url,
                    data=json.dumps(data),
                    content_type='application/json'
                )
                self.assertEqual(response.status_code, 200)
            
            # 4th request should be rate limited
            response = self.client.post(
                self.resend_otp_url,
                data=json.dumps(data),
                content_type='application/json'
            )
            
            self.assertEqual(response.status_code, 429)
            response_data = response.json()
            self.assertFalse(response_data['success'])
            self.assertEqual(response_data['error'], 'RATE_LIMITED')
    
    # ==========================================
    # INTEGRATION TESTS
    # ==========================================
    
    @patch('auth_integration.views.ResendOTPView._send_email_otp')
    @patch('auth_integration.views.ResendOTPView._check_user_exists')
    @patch('auth_integration.views.SupabaseClient')
    def test_resend_otp_full_integration(self, mock_supabase, mock_user_exists, mock_send_email):
        """Test full integration with all components."""
        # Setup mocks
        mock_user_exists.return_value = True
        mock_send_email.return_value = True
        
        mock_client_instance = MagicMock()
        mock_supabase.return_value = mock_client_instance
        mock_client_instance.generate_otp.return_value = '987654'
        
        # Test different verification types
        test_cases = [
            ('registration', self.test_email),
            ('password_reset', self.test_email),
            ('email_verification', self.test_email),
        ]
        
        for verification_type, contact in test_cases:
            with self.subTest(type=verification_type):
                cache.clear()  # Clear rate limiting
                
                data = {
                    'email': contact,
                    'type': verification_type
                }
                
                response = self.client.post(
                    self.resend_otp_url,
                    data=json.dumps(data),
                    content_type='application/json'
                )
                
                self.assertEqual(response.status_code, 200)
                response_data = response.json()
                self.assertTrue(response_data['success'])
                self.assertEqual(response_data['type'], verification_type)