# File: auth_integration/supabase_client.py

import logging
from typing import Dict, Any, Optional
from supabase import create_client, Client
from django.conf import settings
import requests

logger = logging.getLogger(__name__)


class SupabaseClient:
    """
    Wrapper class for Supabase operations.
    Handles authentication, user management, and custom functions.
    """
    
    def __init__(self):
        self.supabase_url = settings.SUPABASE_URL
        self.anon_key = settings.SUPABASE_ANON_KEY
        self.service_key = settings.SUPABASE_SERVICE_ROLE_KEY
        
        # Create clients
        self._anon_client = create_client(self.supabase_url, self.anon_key)
        self._service_client = create_client(self.supabase_url, self.service_key)
    
    @property
    def anon_client(self) -> Client:
        """Get anonymous client for public operations."""
        return self._anon_client
    
    @property
    def service_client(self) -> Client:
        """Get service client for admin operations."""
        return self._service_client
    
    def create_user(self, email: str, password: str, user_metadata: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Create a new user with Supabase Auth.
        
        Args:
            email: User email
            password: User password
            user_metadata: Additional user metadata
            
        Returns:
            Dict with success status and user data or error
        """
        try:
            response = self.anon_client.auth.sign_up({
                'email': email,
                'password': password,
                'options': {
                    'data': user_metadata or {}
                }
            })
            
            if response.user:
                logger.info(f"Successfully created user: {email}")
                return {
                    'success': True,
                    'user': response.user.dict(),
                    'session': response.session.dict() if response.session else None
                }
            else:
                return {
                    'success': False,
                    'error': 'USER_CREATION_FAILED',
                    'message': 'Failed to create user'
                }
                
        except Exception as e:
            logger.error(f"Error creating user {email}: {str(e)}")
            error_message = str(e)
            
            # Handle common Supabase errors
            if 'already registered' in error_message.lower():
                return {
                    'success': False,
                    'error': 'EMAIL_ALREADY_EXISTS',
                    'message': 'An account with this email already exists'
                }
            elif 'password' in error_message.lower():
                return {
                    'success': False,
                    'error': 'WEAK_PASSWORD',
                    'message': 'Password does not meet requirements'
                }
            else:
                return {
                    'success': False,
                    'error': 'SIGNUP_ERROR',
                    'message': 'An error occurred during signup'
                }
    
    def sign_in(self, email: str, password: str) -> Dict[str, Any]:
        """
        Sign in user with email and password.
        
        Args:
            email: User email
            password: User password
            
        Returns:
            Dict with success status and session data or error
        """
        try:
            response = self.anon_client.auth.sign_in_with_password({
                'email': email,
                'password': password
            })
            
            if response.user and response.session:
                logger.info(f"Successfully signed in user: {email}")
                return {
                    'success': True,
                    'user': response.user.dict(),
                    'session': response.session.dict()
                }
            else:
                return {
                    'success': False,
                    'error': 'INVALID_CREDENTIALS',
                    'message': 'Invalid email or password'
                }
                
        except Exception as e:
            logger.error(f"Error signing in user {email}: {str(e)}")
            error_message = str(e)
            
            # Handle common auth errors
            if 'invalid' in error_message.lower() or 'credentials' in error_message.lower():
                return {
                    'success': False,
                    'error': 'INVALID_CREDENTIALS',
                    'message': 'Invalid email or password'
                }
            elif 'not confirmed' in error_message.lower():
                return {
                    'success': False,
                    'error': 'EMAIL_NOT_CONFIRMED',
                    'message': 'Please verify your email before signing in'
                }
            else:
                return {
                    'success': False,
                    'error': 'LOGIN_ERROR',
                    'message': 'An error occurred during login'
                }
    
    def send_password_reset_email(self, email: str) -> Dict[str, Any]:
        """
        Send password reset email via Supabase Auth.
        
        Args:
            email: User email
            
        Returns:
            Dict with success status
        """
        try:
            self.anon_client.auth.reset_password_email(email)
            logger.info(f"Password reset email sent to: {email}")
            return {
                'success': True,
                'message': 'Password reset email sent'
            }
            
        except Exception as e:
            logger.error(f"Error sending password reset email to {email}: {str(e)}")
            # Always return success to avoid email enumeration
            return {
                'success': True,
                'message': 'Password reset email sent'
            }
    
    def reset_password(self, access_token: str, new_password: str) -> Dict[str, Any]:
        """
        Reset user password with access token.
        
        Args:
            access_token: Reset access token
            new_password: New password
            
        Returns:
            Dict with success status
        """
        try:
            # Set session with reset token
            self.anon_client.auth.set_session(access_token, refresh_token="")
            
            # Update password
            response = self.anon_client.auth.update_user({
                'password': new_password
            })
            
            if response.user:
                logger.info(f"Password reset successful for user: {response.user.id}")
                return {
                    'success': True,
                    'message': 'Password reset successful'
                }
            else:
                return {
                    'success': False,
                    'error': 'RESET_FAILED',
                    'message': 'Failed to reset password'
                }
                
        except Exception as e:
            logger.error(f"Error resetting password: {str(e)}")
            return {
                'success': False,
                'error': 'RESET_ERROR',
                'message': 'An error occurred while resetting password'
            }
    
    def verify_otp(self, email: str = None, phone: str = None, token: str = "", type: str = "email") -> Dict[str, Any]:
        """
        Verify OTP using custom Supabase function.
        
        Args:
            email: User email (if email verification)
            phone: User phone (if phone verification)
            token: OTP token
            type: Verification type
            
        Returns:
            Dict with success status
        """
        try:
            response = self.service_client.rpc('verify_otp', {
                'p_token': token,
                'p_email': email,
                'p_phone': phone,
                'p_type': type
            }).execute()
            
            result = response.data
            logger.info(f"OTP verification result: {result}")
            
            return result or {
                'success': False,
                'error': 'VERIFICATION_FAILED',
                'message': 'Failed to verify OTP'
            }
            
        except Exception as e:
            logger.error(f"Error verifying OTP: {str(e)}")
            return {
                'success': False,
                'error': 'VERIFICATION_ERROR',
                'message': 'An error occurred during verification'
            }
    
    def generate_otp(self, email: Optional[str] = None, phone: Optional[str] = None, type: str = "registration") -> Optional[str]:
        """
        Generate OTP using custom Supabase function.
        
        Args:
            email: User email (if email OTP)
            phone: User phone (if phone OTP)  
            type: OTP type
            
        Returns:
            The OTP token as a string, or None if generation failed
        """
        try:
            response = self.service_client.rpc('generate_otp', {
                'p_email': email,
                'p_phone': phone,
                'p_type': type
            }).execute()
            
            result = response.data
            logger.info(f"OTP generation result: {result}")
            
            # Assume result is the OTP token string or None
            return result if isinstance(result, str) else None
            
        except Exception as e:
            logger.error(f"Error generating OTP: {str(e)}")
            return None
    
    def update_last_login(self, user_id: str) -> bool:
        """
        Update last login timestamp using custom function.
        
        Args:
            user_id: Supabase user ID
            
        Returns:
            Success status
        """
        try:
            self.service_client.rpc('update_last_login', {
                'p_user_id': user_id
            }).execute()
            
            logger.debug(f"Updated last login for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error updating last login for {user_id}: {str(e)}")
            return False
    
    def upsert_profile(self, user_id: str, profile_data: Dict[str, Any]) -> bool:
        """
        Create or update user profile using custom function.
        
        Args:
            user_id: Supabase user ID
            profile_data: Profile data dictionary
            
        Returns:
            Success status
        """
        try:
            self.service_client.rpc('upsert_profile', {
                'p_user_id': user_id,
                'p_first_name': profile_data.get('first_name', ''),
                'p_last_name': profile_data.get('last_name', ''),
                'p_email': profile_data.get('email', ''),
                'p_phone': profile_data.get('phone', ''),
                'p_company': profile_data.get('company', ''),
                'p_business_type': profile_data.get('business_type', ''),
                'p_city': profile_data.get('city', ''),
                'p_state': profile_data.get('state', ''),
            }).execute()
            
            logger.info(f"Upserted profile for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error upserting profile for {user_id}: {str(e)}")
            return False
    
    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """
        Get user by ID using service role client.
        
        Args:
            user_id: Supabase user ID
            
        Returns:
            User data or None
        """
        try:
            response = self.service_client.auth.admin.get_user_by_id(user_id)
            return response.user.dict() if response.user else None
            
        except Exception as e:
            logger.error(f"Error getting user {user_id}: {str(e)}")
            return None
    
    def cleanup_expired_tokens(self) -> int:
        """
        Cleanup expired tokens using custom function.
        
        Returns:
            Number of deleted tokens
        """
        try:
            response = self.service_client.rpc('cleanup_expired_tokens').execute()
            deleted_count = response.data or 0
            logger.info(f"Cleaned up {deleted_count} expired tokens")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired tokens: {str(e)}")
            return 0
        


    def send_custom_otp_email(self, email: str, otp_token: str, otp_type: str = "registration") -> Dict[str, Any]:
        """
        Send OTP via Supabase's email system using custom template data.
        
        Args:
            email: User email
            otp_token: The custom generated OTP token
            otp_type: Type of OTP (registration, password_reset, email_verification)
            
        Returns:
            Dict with success status
        """
        try:
            # Map OTP types to Supabase email types
            email_type_mapping = {
                'registration': 'signup',
                'password_reset': 'recovery', 
                'email_verification': 'email_change',
                'phone_verification': 'phone_change'
            }
            
            supabase_email_type = email_type_mapping.get(otp_type, 'signup')
            
            # Use Supabase Admin API to send custom email with OTP
            # This requires using the REST API directly as the Python client 
            # doesn't expose all admin email functions
            
            headers = {
                'apikey': self.service_key,
                'Authorization': f'Bearer {self.service_key}',
                'Content-Type': 'application/json'
            }
            
            # Prepare template data with custom OTP
            template_data = {
                'otp_code': otp_token,
                'email': email,
                'expires_in': '10 minutes',
                'app_name': 'Pefoma',
                'verification_type': otp_type.replace('_', ' ').title()
            }
            
            # Send via Supabase Admin API
            import requests
            
            url = f'{self.supabase_url}/auth/v1/admin/generate_link'
            payload = {
                'type': supabase_email_type,
                'email': email,
                'data': template_data,
                'redirect_to': None  # We're sending OTP, not redirect link
            }
            
            response = requests.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                logger.info(f"Custom OTP email sent to {email} - Type: {otp_type}")
                return {
                    'success': True,
                    'message': 'OTP email sent successfully'
                }
            else:
                logger.error(f"Failed to send OTP email: {response.text}")
                return {
                    'success': False,
                    'error': 'EMAIL_SEND_FAILED',
                    'message': 'Failed to send OTP email'
                }
                
        except Exception as e:
            logger.error(f"Error sending custom OTP email to {email}: {str(e)}")
            return {
                'success': False,
                'error': 'EMAIL_ERROR',
                'message': 'An error occurred while sending email'
            }

    def send_otp_with_supabase_template(self, email: str, otp_token: str, otp_type: str) -> Dict[str, Any]:
        """
        Alternative approach: Use Supabase's built-in email templates but inject custom OTP.
        This method uses Edge Functions or Database Functions to send emails.
        """
        try:
            # Call a custom Supabase Edge Function that handles email sending
            response = self.service_client.rpc('send_custom_otp_email', {
                'p_email': email,
                'p_otp_token': otp_token,
                'p_email_type': otp_type
            }).execute()
            
            result = response.data
            logger.info(f"Supabase template email sent: {result}")
            
            return result or {
                'success': False,
                'error': 'EMAIL_SEND_FAILED',
                'message': 'Failed to send email via Supabase'
            }
            
        except Exception as e:
            logger.error(f"Error sending Supabase template email: {str(e)}")
            return {
                'success': False,
                'error': 'EMAIL_ERROR',
                'message': 'Email sending failed'
            }
    