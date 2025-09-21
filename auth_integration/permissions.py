# File: auth_integration/permissions.py

from rest_framework.permissions import BasePermission


class IsSupabaseAuthenticated(BasePermission):
    """
    Permission that checks if user is authenticated via Supabase.
    """
    
    def has_permission(self, request, view):
        supabase_user = getattr(request, 'supabase_user', None)
        return bool(supabase_user and supabase_user.is_authenticated)


class IsEmailVerified(BasePermission):
    """
    Permission that checks if user's email is verified.
    """
    
    def has_permission(self, request, view):
        supabase_user = getattr(request, 'supabase_user', None)
        return bool(
            supabase_user and 
            supabase_user.is_authenticated and 
            supabase_user.is_email_confirmed
        )