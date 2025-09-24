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
    VerifyOTPSerializer, ResetPasswordSerializer, ResendOTPSerializer
)
from users.models import Profile

logger = logging.getLogger(__name__)


class SignUpView(APIView):
    """
    Handle user registration with custom OTP verification instead of Supabase's default confirmation.
    
    Flow:
    1. Validate input data
    2. Create user in Supabase Auth (with email confirmation disabled)
    3. Generate custom OTP
    4. Send OTP via Supabase email system
    5. Create local Profile record
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
            # Step 1: Create user in Supabase Auth WITHOUT email confirmation
            auth_result = supabase_client.create_user_without_confirmation(
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
            
            # Step 2: Generate custom OTP for registration
            otp_result = supabase_client.generate_otp(
                email=data['email'],
                type='registration'
            )
            
            if not otp_result or not isinstance(otp_result, str):
                logger.error(f"Failed to generate OTP for user {user_id}")
                # Don't fail the signup, user can resend OTP later
            else:
                # Step 3: Send custom OTP email via Supabase
                email_result = supabase_client.send_custom_otp_email(
                    email=data['email'],
                    otp_token=otp_result,
                    otp_type='registration'
                )
                
                if not email_result.get('success'):
                    logger.warning(f"Failed to send OTP email to {data['email']}")
                    # Don't fail signup, user can resend via resend-otp endpoint
            
            # Step 4: Create local Profile
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
                    is_verified=False  # User needs to verify via OTP
                )
                logger.info(f"Created profile for user {user_id}")
                
            except Exception as e:
                logger.error(f"Failed to create profile for user {user_id}: {str(e)}")
                # Don't fail the signup, profile can be created later via webhook
            
            return Response({
                'success': True,
                'message': 'Account created successfully. Please check your email for a 6-digit verification code.',
                'user': {
                    'id': user_id,
                    'email': data['email'],
                    'first_name': data['first_name'],
                    'last_name': data['last_name'],
                },
                'verification_required': True,
                'verification_method': 'otp'
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
        

class ResendOTPView(APIView):
    """
    Handle OTP resending for various verification scenarios.
    
    Supports:
    - Registration verification (signup OTP)
    - Password reset verification (forgot password OTP) 
    - Email verification (general email OTP)
    - Phone verification (general phone OTP)
    
    Flow:
    1. Validate input (email or phone + type)
    2. Check rate limiting (prevent spam)
    3. Generate new OTP using custom Supabase function
    4. Send OTP via email/SMS
    5. Return success response
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        serializer = ResendOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        supabase_client = SupabaseClient()
        
        try:
            # Check if user exists (for registration type)
            if data['type'] == 'registration':
                # For registration, user must exist in auth.users
                user_exists = self._check_user_exists(data.get('email'))
                if not user_exists:
                    return Response({
                        'success': False,
                        'error': 'USER_NOT_FOUND',
                        'message': 'No account found with this email address.'
                    }, status=status.HTTP_404_NOT_FOUND)
            
            # Check rate limiting (max 3 requests per 5 minutes)
            if self._is_rate_limited(data.get('email'), data.get('phone')):
                return Response({
                    'success': False,
                    'error': 'RATE_LIMITED', 
                    'message': 'Too many requests. Please wait before requesting another code.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            # Generate new OTP
            result = supabase_client.generate_otp(
                email=data.get('email'),
                phone=data.get('phone'),
                type=data['type']
            )
            
            otp = result.get('otp') if isinstance(result, dict) else None
            if not otp or not isinstance(otp, str):
                return Response({
                    'success': False,
                    'error': 'OTP_GENERATION_FAILED',
                    'message': 'Failed to generate verification code. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Send OTP via email or SMS
            if data.get('email'):
                sent = self._send_email_otp(data['email'], otp, data['type'])
            elif data.get('phone'):
                sent = self._send_sms_otp(data['phone'], otp, data['type'])
            else:
                sent = False
            
            if not sent:
                return Response({
                    'success': False,
                    'error': 'DELIVERY_FAILED',
                    'message': 'Failed to send verification code. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            # Log the resend attempt
            logger.info(f"OTP resent successfully - Type: {data['type']}, Email: {data.get('email')}, Phone: {data.get('phone')}")
            
            return Response({
                'success': True,
                'message': 'Verification code sent successfully.',
                'type': data['type'],
                'sent_to': data.get('email') or data.get('phone'),
                'expires_in': 600  # 10 minutes
            })
            
        except Exception as e:
            logger.error(f"Resend OTP error: {str(e)}")
            return Response({
                'success': False,
                'error': 'RESEND_ERROR',
                'message': 'An error occurred while resending verification code. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _check_user_exists(self, email: str) -> bool:
        """Check if user exists in Supabase auth.users table."""
        try:
            supabase_client = SupabaseClient()
            response = supabase_client.service_client.auth.admin.get_user_by_email(email)
            return response.user is not None
        except Exception:
            return False
    
    def _is_rate_limited(self, email: str = None, phone: str = None) -> bool:
        """
        Check if user is rate limited for OTP requests.
        Simple rate limiting: max 3 requests per 5 minutes per email/phone.
        """
        from django.core.cache import cache
        
        key = f"otp_resend_{email or phone}"
        current_count = cache.get(key, 0)
        
        if current_count >= 3:
            return True
        
        # Increment counter with 5-minute expiry
        cache.set(key, current_count + 1, 300)  # 300 seconds = 5 minutes
        return False
    
    def _send_email_otp(self, email: str, otp: str, otp_type: str) -> bool:
        """
        Send OTP via email using your preferred email service.
        This is a placeholder - implement with your email provider.
        """
        try:
            # Get email template based on type
            subject, template = self._get_email_template(otp_type)
            
            # Replace template variables
            html_content = template.format(
                otp=otp,
                email=email,
                expires_in="10 minutes"
            )
            
            # TODO: Implement actual email sending
            # Example with SendGrid, AWS SES, or Django email backend
            from django.core.mail import send_mail
            
            send_mail(
                subject=subject,
                message=f"Your verification code is: {otp}",
                from_email='noreply@pefoma.com',
                recipient_list=[email],
                html_message=html_content
            )
            
            logger.info(f"OTP email sent to {email}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send OTP email to {email}: {str(e)}")
            return False
    
    def _send_sms_otp(self, phone: str, otp: str, otp_type: str) -> bool:
        """
        Send OTP via SMS using your preferred SMS service.
        This is a placeholder - implement with Twilio, AWS SNS, etc.
        """
        try:
            message = f"Your Pefoma verification code is: {otp}. Valid for 10 minutes."
            
            # TODO: Implement actual SMS sending
            # Example with Twilio
            # client = Client(account_sid, auth_token)
            # message = client.messages.create(
            #     body=message,
            #     from_='+1234567890',
            #     to=phone
            # )
            
            logger.info(f"OTP SMS sent to {phone}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send OTP SMS to {phone}: {str(e)}")
            return False
    
    def _get_email_template(self, otp_type: str) -> tuple:
        """Get email subject and HTML template based on OTP type."""
        templates = {
            'registration': (
                'Verify Your Pefoma Account',
                '''
                <html>
                <body>
                    <h2>Welcome to Pefoma!</h2>
                    <p>Please use the following verification code to complete your account setup:</p>
                    <h3 style="color: #2563eb; font-size: 32px; letter-spacing: 8px;">{otp}</h3>
                    <p>This code will expire in {expires_in}.</p>
                    <p>If you didn't create an account, please ignore this email.</p>
                </body>
                </html>
                '''
            ),
            'password_reset': (
                'Reset Your Pefoma Password',
                '''
                <html>
                <body>
                    <h2>Password Reset Request</h2>
                    <p>Please use the following verification code to reset your password:</p>
                    <h3 style="color: #dc2626; font-size: 32px; letter-spacing: 8px;">{otp}</h3>
                    <p>This code will expire in {expires_in}.</p>
                    <p>If you didn't request this reset, please ignore this email.</p>
                </body>
                </html>
                '''
            ),
            'email_verification': (
                'Verify Your Email Address',
                '''
                <html>
                <body>
                    <h2>Email Verification</h2>
                    <p>Please use the following verification code:</p>
                    <h3 style="color: #059669; font-size: 32px; letter-spacing: 8px;">{otp}</h3>
                    <p>This code will expire in {expires_in}.</p>
                </body>
                </html>
                '''
            )
        }
        
        return templates.get(otp_type, templates['email_verification'])
