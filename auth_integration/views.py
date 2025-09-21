# File: auth_integration/views.py

import logging
from typing import Dict, Any
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.conf import settings
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.http import JsonResponse
from django.views import View
import json
from django.utils import timezone

from .supabase_client import SupabaseClient
from .serializers import (
    SignUpSerializer, LoginSerializer, ForgotPasswordSerializer,
    VerifyOTPSerializer, ResetPasswordSerializer
)
from users.models import Profile

logger = logging.getLogger(__name__)


class SignUpView(APIView):
    """
    Handle user registration with Supabase Auth + local Profile creation.
    
    Flow:
    1. Validate input data
    2. Create user in Supabase Auth
    3. Create local Profile record
    4. Send verification email
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = SignUpSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        supabase_client = SupabaseClient()
        
        try:
            # Create user in Supabase Auth
            auth_result = supabase_client.create_user(
                email=data['email'],
                password=data['password'],
                user_metadata={
                    'first_name': data['first_name'],
                    'last_name': data['last_name'],
                    'phone': data['phone'],
                    'company': data['company'],
                    'business_type': data['business_type'],
                    'city': data['city'],
                    'state': data['state'],
                }
            )
            
            if not auth_result['success']:
                return Response({
                    'success': False,
                    'error': auth_result['error'],
                    'message': 'Failed to create user account'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            user_id = auth_result['user']['id']
            
            # Create local Profile
            try:
                profile = Profile.objects.create(
                    id=user_id,
                    first_name=data['first_name'],
                    last_name=data['last_name'],
                    email=data['email'],
                    phone=data['phone'],
                    company=data['company'],
                    business_type=data['business_type'],
                    city=data['city'],
                    state=data['state'],
                )
                logger.info(f"Created profile for user {user_id}")
                
            except Exception as e:
                logger.error(f"Failed to create profile for user {user_id}: {str(e)}")
                # Don't fail the signup, profile can be created later via webhook
            
            return Response({
                'success': True,
                'message': 'Account created successfully. Please check your email to verify your account.',
                'user': {
                    'id': user_id,
                    'email': data['email'],
                    'first_name': data['first_name'],
                    'last_name': data['last_name'],
                }
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            return Response({
                'success': False,
                'error': 'SIGNUP_ERROR',
                'message': 'An error occurred during signup. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LoginView(APIView):
    """
    Handle user login with Supabase Auth.
    
    Flow:
    1. Validate credentials with Supabase
    2. Return JWT tokens
    3. Update last login timestamp
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        supabase_client = SupabaseClient()
        
        try:
            # Authenticate with Supabase
            auth_result = supabase_client.sign_in(
                email=data['email'],
                password=data['password']
            )
            
            if not auth_result['success']:
                return Response({
                    'success': False,
                    'error': auth_result['error'],
                    'message': 'Invalid email or password'
                }, status=status.HTTP_401_UNAUTHORIZED)
            
            user = auth_result['user']
            session = auth_result['session']
            
            # Update last login
            try:
                supabase_client.update_last_login(user['id'])
                logger.info(f"Updated last login for user {user['id']}")
            except Exception as e:
                logger.warning(f"Failed to update last login: {str(e)}")
            
            return Response({
                'success': True,
                'message': 'Login successful',
                'user': {
                    'id': user['id'],
                    'email': user['email'],
                    'email_confirmed_at': user.get('email_confirmed_at'),
                    'phone': user.get('phone'),
                    'user_metadata': user.get('user_metadata', {}),
                },
                'session': {
                    'access_token': session['access_token'],
                    'refresh_token': session['refresh_token'],
                    'expires_in': session['expires_in'],
                    'expires_at': session['expires_at'],
                }
            })
            
        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            return Response({
                'success': False,
                'error': 'LOGIN_ERROR',
                'message': 'An error occurred during login. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ForgotPasswordView(APIView):
    """
    Handle password reset request.
    
    Flow:
    1. Validate email
    2. Send reset email via Supabase
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ForgotPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        email = serializer.validated_data['email']
        supabase_client = SupabaseClient()
        
        try:
            # Send reset email via Supabase
            result = supabase_client.send_password_reset_email(email)
            
            # Always return success to avoid email enumeration
            return Response({
                'success': True,
                'message': 'If this email exists in our system, you will receive password reset instructions.'
            })
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            return Response({
                'success': True,  # Still return success for security
                'message': 'If this email exists in our system, you will receive password reset instructions.'
            })


class ResetPasswordView(APIView):
    """
    Handle password reset confirmation.
    
    Flow:
    1. Validate reset token
    2. Update password via Supabase
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ResetPasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        supabase_client = SupabaseClient()
        
        try:
            # Reset password via Supabase
            result = supabase_client.reset_password(
                access_token=data['access_token'],
                new_password=data['password']
            )
            
            if not result['success']:
                return Response({
                    'success': False,
                    'error': result['error'],
                    'message': 'Failed to reset password. Token may be invalid or expired.'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'success': True,
                'message': 'Password reset successful. You can now sign in with your new password.'
            })
            
        except Exception as e:
            logger.error(f"Password reset confirmation error: {str(e)}")
            return Response({
                'success': False,
                'error': 'RESET_ERROR',
                'message': 'An error occurred while resetting your password. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class VerifyOTPView(APIView):
    """
    Handle OTP verification (for email/phone verification).
    
    Flow:
    1. Validate OTP
    2. Verify user account
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        supabase_client = SupabaseClient()
        
        try:
            # Verify OTP via Supabase function
            result = supabase_client.verify_otp(
                email=data.get('email'),
                phone=data.get('phone'),
                token=data['token'],
                type=data.get('type', 'email')
            )
            
            if not result['success']:
                return Response({
                    'success': False,
                    'error': result['error'],
                    'message': 'Invalid or expired verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({
                'success': True,
                'message': 'Verification successful'
            })
            
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            return Response({
                'success': False,
                'error': 'VERIFICATION_ERROR',
                'message': 'An error occurred during verification. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class HealthCheckView(APIView):
    """
    Health check endpoint for monitoring and load balancers.
    """
    permission_classes = []  # No authentication required
    
    def get(self, request):
        """Return health status with basic system checks."""
        try:
            # Test database connection
            from django.db import connection
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            db_status = "healthy"
        except Exception as e:
            db_status = f"unhealthy: {str(e)}"
        
        try:
            # Test cache connection
            from django.core.cache import cache
            cache.set('health_check', 'ok', 1)
            cache_status = "healthy" if cache.get('health_check') == 'ok' else "unhealthy"
        except Exception as e:
            cache_status = f"unhealthy: {str(e)}"
        
        health_status = {
            'status': 'healthy' if db_status == 'healthy' and cache_status == 'healthy' else 'unhealthy',
            'service': 'pefoma-backend',
            'version': '1.0.0',
            'timestamp': timezone.now().isoformat(),
            'checks': {
                'database': db_status,
                'cache': cache_status,
            }
        }
        
        status_code = 200 if health_status['status'] == 'healthy' else 503
        return Response(health_status, status=status_code)


class TokenRefreshView(APIView):
    """
    Refresh JWT tokens using refresh token.
    """
    permission_classes = []
    
    def post(self, request):
        from .serializers import RefreshTokenSerializer
        
        serializer = RefreshTokenSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        refresh_token = serializer.validated_data['refresh_token']
        supabase_client = SupabaseClient()
        
        try:
            # Refresh tokens via Supabase
            result = supabase_client.anon_client.auth.refresh_session(refresh_token)
            
            if result.session:
                return Response({
                    'success': True,
                    'session': {
                        'access_token': result.session.access_token,
                        'refresh_token': result.session.refresh_token,
                        'expires_in': result.session.expires_in,
                        'expires_at': result.session.expires_at,
                    }
                })
            else:
                return Response({
                    'success': False,
                    'error': 'INVALID_REFRESH_TOKEN',
                    'message': 'Refresh token is invalid or expired'
                }, status=status.HTTP_401_UNAUTHORIZED)
                
        except Exception as e:
            logger.error(f"Token refresh error: {str(e)}")
            return Response({
                'success': False,
                'error': 'REFRESH_ERROR',
                'message': 'An error occurred while refreshing tokens'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LogoutView(APIView):
    """
    Logout user and invalidate tokens.
    """
    def post(self, request):
        try:
            # Get the access token from the request
            auth_header = request.META.get('HTTP_AUTHORIZATION', '')
            if not auth_header.startswith('Bearer '):
                return Response({
                    'success': False,
                    'error': 'NO_TOKEN',
                    'message': 'No authentication token provided'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            access_token = auth_header[7:]
            supabase_client = SupabaseClient()
            
            # Sign out via Supabase
            supabase_client.anon_client.auth.sign_out()
            
            return Response({
                'success': True,
                'message': 'Logged out successfully'
            })
            
        except Exception as e:
            logger.error(f"Logout error: {str(e)}")
            return Response({
                'success': True,  # Still return success for security
                'message': 'Logged out successfully'
            })

@method_decorator(csrf_exempt, name='dispatch')
class SupabaseWebhookView(View):
    """
    Handle webhooks from Supabase for user events.
    
    This webhook keeps local Profile records in sync with Supabase Auth changes.
    """
    
    def post(self, request):
        try:
            # Verify webhook signature if configured
            webhook_secret = getattr(settings, 'SUPABASE_WEBHOOK_SECRET', '')
            if webhook_secret:
                signature = request.META.get('HTTP_X_SUPABASE_SIGNATURE', '')
                # Add signature verification logic here
                pass
            
            # Parse webhook payload
            payload = json.loads(request.body.decode('utf-8'))
            event_type = payload.get('type')
            user_data = payload.get('record', {})
            
            logger.info(f"Received Supabase webhook: {event_type} for user {user_data.get('id')}")
            
            if event_type == 'INSERT':
                # User created - ensure Profile exists
                self._handle_user_created(user_data)
            elif event_type == 'UPDATE':
                # User updated - sync Profile
                self._handle_user_updated(user_data)
            elif event_type == 'DELETE':
                # User deleted - cleanup Profile
                self._handle_user_deleted(user_data)
            
            return JsonResponse({'success': True})
            
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
            return JsonResponse({'success': False, 'error': str(e)}, status=500)
    
    def _handle_user_created(self, user_data: Dict[str, Any]):
        """Handle user creation event."""
        try:
            user_id = user_data['id']
            email = user_data['email']
            user_metadata = user_data.get('user_metadata', {})
            
            # Create or update Profile
            Profile.objects.update_or_create(
                id=user_id,
                defaults={
                    'email': email,
                    'first_name': user_metadata.get('first_name', ''),
                    'last_name': user_metadata.get('last_name', ''),
                    'phone': user_metadata.get('phone', ''),
                    'company': user_metadata.get('company', ''),
                    'business_type': user_metadata.get('business_type', ''),
                    'city': user_metadata.get('city', ''),
                    'state': user_metadata.get('state', ''),
                    'is_verified': bool(user_data.get('email_confirmed_at')),
                    'verified_at': user_data.get('email_confirmed_at'),
                }
            )
            logger.info(f"Created/updated profile for user {user_id} via webhook")
            
        except Exception as e:
            logger.error(f"Error handling user creation webhook: {str(e)}")
    
    def _handle_user_updated(self, user_data: Dict[str, Any]):
        """Handle user update event."""
        try:
            user_id = user_data['id']
            
            # Update Profile if exists
            try:
                profile = Profile.objects.get(id=user_id)
                profile.email = user_data['email']
                profile.is_verified = bool(user_data.get('email_confirmed_at'))
                if user_data.get('email_confirmed_at'):
                    profile.verified_at = user_data['email_confirmed_at']
                profile.save()
                logger.info(f"Updated profile for user {user_id} via webhook")
            except Profile.DoesNotExist:
                logger.warning(f"Profile not found for user {user_id} during update webhook")
                
        except Exception as e:
            logger.error(f"Error handling user update webhook: {str(e)}")
    
    def _handle_user_deleted(self, user_data: Dict[str, Any]):
        """Handle user deletion event."""
        try:
            user_id = user_data['id']
            
            # Delete Profile
            Profile.objects.filter(id=user_id).delete()
            logger.info(f"Deleted profile for user {user_id} via webhook")
            
        except Exception as e:
            logger.error(f"Error handling user deletion webhook: {str(e)}")


class UserProfileView(APIView):
    """
    Get current user's profile information.
    """
    
    def get(self, request):
        if not hasattr(request, 'supabase_user') or not request.supabase_user:
            return Response({
                'error': 'Not authenticated'
            }, status=status.HTTP_401_UNAUTHORIZED)
        
        try:
            profile = Profile.objects.get(id=request.supabase_user.user_id)
            
            return Response({
                'success': True,
                'user': {
                    'id': str(profile.id),
                    'first_name': profile.first_name,
                    'last_name': profile.last_name,
                    'email': profile.email,
                    'phone': profile.phone,
                    'company': profile.company,
                    'business_type': profile.business_type,
                    'city': profile.city,
                    'state': profile.state,
                    'is_verified': profile.is_verified,
                    'account_tier': profile.account_tier,
                    'last_login': profile.last_login,
                    'created_at': profile.created_at,
                }
            })
            
        except Profile.DoesNotExist:
            return Response({
                'error': 'Profile not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error fetching user profile: {str(e)}")
            return Response({
                'error': 'Internal server error'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)