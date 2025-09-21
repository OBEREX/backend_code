# File: auth_integration/authentication.py

from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser


class SupabaseAuthentication(BaseAuthentication):
    """
    DRF Authentication backend that uses Supabase JWT validation.
    Works in conjunction with SupabaseJWTMiddleware.
    """
    
    def authenticate(self, request):
        """
        Authenticate the request using Supabase user attached by middleware.
        
        Returns:
            tuple: (user, auth_token) or None if not authenticated
        """
        supabase_user = getattr(request, 'supabase_user', None)
        
        if not supabase_user or not supabase_user.is_authenticated:
            return None
        
        # Return the supabase_user as the user object
        # The token is not needed for DRF since we already validated it
        return (supabase_user, None)
    
    def authenticate_header(self, request):
        """Return authentication header for 401 responses."""
        return 'Bearer'


