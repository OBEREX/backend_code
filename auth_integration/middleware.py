# File: auth_integration/middleware.py

import jwt
import logging
from django.conf import settings
from django.http import JsonResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser
from .models import SupabaseUser

logger = logging.getLogger(__name__)


class SupabaseJWTMiddleware(MiddlewareMixin):
    """
    Middleware to validate Supabase JWT tokens and attach user info to request.
    
    This middleware:
    1. Extracts JWT from Authorization header
    2. Validates the token using Supabase JWT secret
    3. Attaches user information to request.supabase_user
    4. Handles token refresh if needed
    """
    
    def __init__(self, get_response=None):
        super().__init__(get_response)
        self.jwt_secret = settings.SUPABASE_JWT_SECRET
        self.excluded_paths = [
            '/auth/signup/',
            '/auth/login/', 
            '/auth/forgot-password/',
            '/auth/verify-otp/',
            '/auth/reset-password/',
            '/auth/webhook/',
            '/health/',
            '/admin/',
        ]
    
    def process_request(self, request):
        """Process incoming request to validate JWT and attach user info."""
        
        # Skip processing for excluded paths
        if any(request.path.startswith(path) for path in self.excluded_paths):
            request.supabase_user = None
            return None
        
        # Extract token from Authorization header
        auth_header = request.META.get('HTTP_AUTHORIZATION', '')
        if not auth_header.startswith('Bearer '):
            request.supabase_user = None
            return None
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        try:
            # Decode and validate JWT
            payload = jwt.decode(
                token, 
                self.jwt_secret, 
                algorithms=['HS256'],
                options={'verify_aud': False}  # Supabase doesn't always include aud
            )
            
            # Validate required claims
            if not payload.get('sub') or not payload.get('email'):
                logger.warning(f"Invalid JWT payload: missing required claims")
                request.supabase_user = None
                return None
            
            # Check if user is verified (email_confirmed_at exists)
            if not payload.get('email_confirmed_at'):
                return JsonResponse({
                    'error': 'Email not verified',
                    'code': 'EMAIL_NOT_VERIFIED',
                    'message': 'Please verify your email before accessing this resource.'
                }, status=403)
            
            # Create SupabaseUser object
            request.supabase_user = SupabaseUser(
                user_id=payload['sub'],
                email=payload['email'],
                email_confirmed_at=payload.get('email_confirmed_at'),
                phone=payload.get('phone'),
                role=payload.get('role', 'authenticated'),
                app_metadata=payload.get('app_metadata', {}),
                user_metadata=payload.get('user_metadata', {}),
                aud=payload.get('aud', 'authenticated'),
                exp=payload.get('exp'),
                iat=payload.get('iat'),
                iss=payload.get('iss')
            )
            
            logger.debug(f"Successfully authenticated user: {payload['email']}")
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return JsonResponse({
                'error': 'Token expired',
                'code': 'TOKEN_EXPIRED',
                'message': 'Your session has expired. Please log in again.'
            }, status=401)
            
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            request.supabase_user = None
            return None
            
        except Exception as e:
            logger.error(f"Unexpected error processing JWT: {str(e)}")
            request.supabase_user = None
            return None
        
        return None
    
    def process_response(self, request, response):
        """Process response - could be used for token refresh logic."""
        return response
