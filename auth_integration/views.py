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
from django.core.cache import cache


from .supabase_client import SupabaseClient
from .serializers import (
    SignUpSerializer, LoginSerializer, ForgotPasswordSerializer,
    VerifyOTPSerializer, ResetPasswordSerializer, ResendOTPSerializer
)
from rest_framework.permissions import AllowAny
from django.shortcuts import get_object_or_404
from users.models import Profile
from common.simple_email_service import simple_email_service as email_service


logger = logging.getLogger(__name__)


class SignUpView(APIView):
    """
    Enhanced signup view with Microsoft Graph email integration.
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
            
            # Generate and send OTP via Microsoft Graph
            otp_generated = self._generate_and_send_otp(
                email=data['email'],
                first_name=data['first_name']
            )
            
            if not otp_generated:
                logger.warning(f"Failed to send OTP to {data['email']}, but account was created")
            
            return Response({
                'success': True,
                'message': 'Account created successfully. Please check your email for the verification code.',
                'user': {
                    'id': user_id,
                    'email': data['email'],
                    'first_name': data['first_name'],
                    'last_name': data['last_name'], # type: ignore
                },
                'otp_sent': otp_generated
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Signup error: {str(e)}")
            return Response({
                'success': False,
                'error': 'SIGNUP_ERROR',
                'message': 'An error occurred during signup. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _generate_and_send_otp(self, email: str, first_name: str) -> bool:
        """Generate OTP and send via email service."""
        try:
            # Generate OTP using Supabase function
            supabase_client = SupabaseClient()
            response = supabase_client.service_client.rpc('generate_otp', {
                'p_email': email,
                'p_type': 'registration'
            }).execute()
            
            if response.data:
                # Extract OTP code
                if isinstance(response.data, dict):
                    otp_code = response.data.get('token') or response.data.get('otp')
                else:
                    otp_code = str(response.data)
                
                # Send via Microsoft Graph
                success = email_service.send_otp(
                    email=email,
                    otp_code=otp_code, # type: ignore
                    otp_type='registration',
                    metadata={'name': first_name}
                )
                
                if success:
                    logger.info(f"Registration OTP sent to {email}")
                    return True
                else:
                    logger.error(f"Failed to send registration OTP to {email}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error generating/sending OTP: {str(e)}")
            return False

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
                email=data['email'], # type: ignore
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
    Enhanced forgot password view with Microsoft Graph email integration.
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
        
        try:
            # Check if user exists (optional - for better UX)
            user_exists = self._check_user_exists(email)
            
            if user_exists:
                # Generate and send password reset OTP
                otp_sent = self._generate_and_send_reset_otp(email)
                
                if not otp_sent:
                    logger.error(f"Failed to send password reset OTP to {email}")
            
            # Always return success to avoid email enumeration
            return Response({
                'success': True,
                'message': 'If this email exists in our system, you will receive password reset instructions.',
                'email': email
            })
            
        except Exception as e:
            logger.error(f"Password reset error: {str(e)}")
            # Still return success for security
            return Response({
                'success': True,
                'message': 'If this email exists in our system, you will receive password reset instructions.'
            })
    
    def _check_user_exists(self, email: str) -> bool:
        """Check if user exists."""
        try:
            from users.models import Profile
            return Profile.objects.filter(email=email).exists()
        except:
            return False
    
    def _generate_and_send_reset_otp(self, email: str) -> bool:
        """Generate and send password reset OTP."""
        try:
            # Get user metadata
            metadata = {'name': 'User'}
            try:
                from users.models import Profile
                profile = Profile.objects.get(email=email)
                metadata['name'] = profile.first_name or 'User'
            except:
                pass
            
            # Generate OTP
            supabase_client = SupabaseClient()
            response = supabase_client.service_client.rpc('generate_otp', {
                'p_email': email,
                'p_type': 'password_reset'
            }).execute()
            
            if response.data:
                # Extract OTP code
                if isinstance(response.data, dict):
                    otp_code = response.data.get('token') or response.data.get('otp')
                else:
                    otp_code = str(response.data)
                
                # Send via Microsoft Graph
                success = email_service.send_otp(
                    email=email,
                    otp_code=otp_code,
                    otp_type='password_reset',
                    metadata=metadata
                )
                
                if success:
                    logger.info(f"Password reset OTP sent to {email}")
                    return True
                else:
                    logger.error(f"Failed to send password reset OTP to {email}")
                    return False
            
            return False
            
        except Exception as e:
            logger.error(f"Error in password reset OTP: {str(e)}")
            return False

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
    Enhanced OTP verification with email notifications.
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
            
            # If registration verification successful, send welcome email
            if data.get('type') == 'registration' and data.get('email'):
                self._send_welcome_email(data['email'])
            
            return Response({
                'success': True,
                'message': 'Verification successful',
                'user_id': result.get('user_id')
            })
            
        except Exception as e:
            logger.error(f"OTP verification error: {str(e)}")
            return Response({
                'success': False,
                'error': 'VERIFICATION_ERROR',
                'message': 'An error occurred during verification. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _send_welcome_email(self, email: str):
        """Send welcome email after successful registration."""
        try:
            # Get user name
            name = 'User'
            try:
                from users.models import Profile
                profile = Profile.objects.get(email=email)
                name = profile.first_name or 'User'
            except:
                pass
            
            # Send welcome email via email service
            email_service.send_welcome_email(email, name)
            logger.info(f"Welcome email sent to {email}")
            
        except Exception as e:
            logger.error(f"Failed to send welcome email: {str(e)}")

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
    Enhanced OTP resending view with Microsoft Graph email integration.
    
    Supports:
    - Registration verification
    - Password reset verification
    - Email verification
    - Phone verification (SMS - future implementation)
    """
    permission_classes = []  # Public endpoint
    
    def post(self, request):
        """Handle OTP resend request."""
        serializer = ResendOTPSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        data = serializer.validated_data
        
        try:
            # Check if user exists (for registration type)
            if data['type'] == 'registration':
                if not self._check_user_exists(data.get('email')):
                    return Response({
                        'success': False,
                        'error': 'USER_NOT_FOUND',
                        'message': 'No account found with this email address.'
                    }, status=status.HTTP_404_NOT_FOUND)
            
            # Check rate limiting
            if self._is_rate_limited(data.get('email'), data.get('phone')):
                return Response({
                    'success': False,
                    'error': 'RATE_LIMITED',
                    'message': 'Too many requests. Please wait 5 minutes before requesting another code.'
                }, status=status.HTTP_429_TOO_MANY_REQUESTS)
            
            # Generate OTP
            otp_result = self._generate_otp(
                email=data.get('email'),
                phone=data.get('phone'),
                type=data['type']
            )
            
            if not otp_result or not otp_result.get('success'):
                return Response({
                    'success': False,
                    'error': 'OTP_GENERATION_FAILED',
                    'message': 'Failed to generate verification code. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            otp_code = otp_result.get('otp')
            
            # Send OTP via email or SMS
            if data.get('email'):
                sent = self._send_email_otp(data['email'], otp_code, data['type'])
            elif data.get('phone'):
                sent = self._send_sms_otp(data['phone'], otp_code, data['type'])
            else:
                sent = False
            
            if not sent:
                return Response({
                    'success': False,
                    'error': 'DELIVERY_FAILED',
                    'message': 'Failed to send verification code. Please check your email address and try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            logger.info(f"OTP resent successfully - Type: {data['type']}, Email: {data.get('email')}")
            
            return Response({
                'success': True,
                'message': 'Verification code sent successfully. Please check your email.',
                'type': data['type'],
                'sent_to': data.get('email') or data.get('phone'),
                'expires_in': 600  # 10 minutes
            })
            
        except Exception as e:
            logger.error(f"Resend OTP error: {str(e)}")
            return Response({
                'success': False,
                'error': 'RESEND_ERROR',
                'message': 'An error occurred while sending verification code. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _check_user_exists(self, email: str) -> bool:
        """Check if user exists in Supabase or local database."""
        try:
            from users.models import Profile
            return Profile.objects.filter(email=email).exists()
        except Exception as e:
            logger.error(f"Error checking user existence: {str(e)}")
            
            # Fallback to Supabase check
            try:
                from .supabase_client import SupabaseClient
                client = SupabaseClient()
                response = client.service_client.auth.admin.get_user_by_email(email)
                return response.user is not None
            except:
                return False
    
    def _is_rate_limited(self, email: str = None, phone: str = None) -> bool:
        """
        Check if user is rate limited for OTP requests.
        Limit: max 3 requests per 5 minutes per email/phone.
        """
        key = f"otp_resend_{email or phone}"
        current_count = cache.get(key, 0)
        
        if current_count >= 3:
            return True
        
        # Increment counter with 5-minute expiry
        cache.set(key, current_count + 1, 300)  # 300 seconds = 5 minutes
        return False
    
    def _generate_otp(self, email: str = None, phone: str = None, type: str = "registration") -> Dict:
        """Generate OTP using Supabase function."""
        try:
            from .supabase_client import SupabaseClient
            client = SupabaseClient()
            
            response = client.service_client.rpc('generate_otp', {
                'p_email': email,
                'p_phone': phone,
                'p_type': type
            }).execute()
            
            if response.data:
                # Handle both direct OTP return and object return
                if isinstance(response.data, str):
                    return {'success': True, 'otp': response.data}
                elif isinstance(response.data, dict):
                    return response.data
                else:
                    # If it's a different format, try to extract the OTP
                    return {'success': True, 'otp': str(response.data)}
            
            return {'success': False}
            
        except Exception as e:
            logger.error(f"Error generating OTP: {str(e)}")
            return {'success': False}
    
    def _send_email_otp(self, email: str, otp_code: str, otp_type: str) -> bool:
        """
        Send OTP via Microsoft Graph email service.
        
        Args:
            email: Recipient email
            otp_code: Generated OTP code
            otp_type: Type of OTP (registration, password_reset, etc.)
        
        Returns:
            True if email sent successfully
        """
        try:
            # Get user metadata for personalization
            metadata = self._get_user_metadata(email)
            
            # Send using the email service
            success = email_service.send_otp(
                email=email,
                otp_code=otp_code,
                otp_type=otp_type,
                metadata=metadata
            )
            
            if success:
                logger.info(f"OTP email sent successfully to {email} via Microsoft Graph")
                
                # Log for analytics
                self._log_email_sent(email, otp_type, 'success')
            else:
                logger.error(f"Failed to send OTP email to {email}")
                self._log_email_sent(email, otp_type, 'failed')
            
            return success
            
        except Exception as e:
            logger.error(f"Error in _send_email_otp: {str(e)}")
            self._log_email_sent(email, otp_type, 'error', str(e))
            return False
    
    def _send_sms_otp(self, phone: str, otp_code: str, otp_type: str) -> bool:
        """
        Send OTP via SMS (placeholder for future implementation).
        
        Args:
            phone: Recipient phone number
            otp_code: Generated OTP code
            otp_type: Type of OTP
        
        Returns:
            True if SMS sent successfully
        """
        # TODO: Implement SMS sending via Twilio or similar service
        logger.warning(f"SMS OTP not implemented yet. Would send {otp_code} to {phone}")
        return False
    
    def _get_user_metadata(self, email: str) -> Dict[str, Any]:
        """Get user metadata for email personalization."""
        metadata = {}
        
        try:
            from users.models import Profile
            profile = Profile.objects.get(email=email)
            metadata['name'] = profile.first_name or 'User'
            metadata['user_id'] = str(profile.id)
            metadata['company'] = profile.company
        except:
            metadata['name'] = 'User'
        
        return metadata
    
    def _log_email_sent(self, email: str, otp_type: str, status: str, error: str = None):
        """Log email sending for analytics and debugging."""
        try:
            # You can implement email logging here
            # For now, just log to file
            log_data = {
                'email': email,
                'otp_type': otp_type,
                'status': status,
                'error': error,
                'timestamp': str(timezone.now())
            }
            
            if status == 'success':
                logger.info(f"Email log: {log_data}")
            else:
                logger.error(f"Email log: {log_data}")
                
        except Exception as e:
            logger.error(f"Failed to log email: {str(e)}")

class TestEmailView(APIView):
    """Test endpoint for email functionality (development only)."""
    
    permission_classes = []
    
    def post(self, request):
        """Send a test email."""
        if not settings.DEBUG:
            return Response({
                'error': 'This endpoint is only available in DEBUG mode'
            }, status=status.HTTP_403_FORBIDDEN)
        
        email = request.data.get('email')
        email_type = request.data.get('type', 'test')
        
        if not email:
            return Response({
                'error': 'Email address required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            if email_type == 'otp':
                # Test OTP email
                success = email_service.send_otp(
                    email=email,
                    otp_code='123456',
                    otp_type='registration',
                    metadata={'name': 'Test User'}
                )
            elif email_type == 'welcome':
                # Test welcome email
                success = email_service.send_welcome_email(
                    email=email,
                    name='Test User'
                )
            else:
                # Test generic email
                success = email_service.send_transactional(
                    email=email,
                    subject='Test Email from Pefoma',
                    html_content='<h2>This is a test email</h2><p>If you received this, the email system is working!</p>'
                )
            
            if success:
                return Response({
                    'success': True,
                    'message': f'Test {email_type} email sent to {email}'
                })
            else:
                return Response({
                    'success': False,
                    'message': 'Failed to send test email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except Exception as e:
            return Response({
                'success': False,
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class VerifyResetTokenView(APIView):
    """
    Verify if a password reset token is valid.
    This endpoint is called before showing the reset password form.
    """
    permission_classes = [AllowAny]
    
    def post(self, request):
        token = request.data.get('token')
        if not token:
            return Response({
                'valid': False,
                'message': 'Token is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            supabase_client = SupabaseClient()
            
            # You might need to implement this method in your SupabaseClient
            # or use Supabase's token verification
            result = supabase_client.verify_reset_token(token)
            
            return Response({
                'valid': result.get('success', False),
                'message': result.get('message', 'Token verification completed')
            })
            
        except Exception as e:
            logger.error(f"Token verification error: {str(e)}")
            return Response({
                'valid': False,
                'message': 'Token verification failed'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
