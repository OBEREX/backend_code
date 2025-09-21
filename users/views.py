# File: users/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.shortcuts import get_object_or_404
import logging

from auth_integration.permissions import IsSupabaseAuthenticated, IsEmailVerified
from .models import Profile
from auth_integration.serializers import UpdateProfileSerializer, ChangePasswordSerializer
from auth_integration.supabase_client import SupabaseClient

logger = logging.getLogger(__name__)


class ProfileDetailView(APIView):
    """
    Get user profile details.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        try:
            profile = get_object_or_404(Profile, id=request.supabase_user.user_id)
            
            return Response({
                'success': True,
                'profile': {
                    'id': str(profile.id),
                    'first_name': profile.first_name,
                    'last_name': profile.last_name,
                    'full_name': profile.full_name,
                    'email': profile.email,
                    'phone': profile.phone,
                    'company': profile.company,
                    'business_type': profile.business_type,
                    'city': profile.city,
                    'state': profile.state,
                    'is_verified': profile.is_verified,
                    'account_tier': profile.account_tier,
                    'avatar_url': profile.avatar_url,
                    'theme': profile.theme,
                    'language': profile.language,
                    'timezone': profile.timezone,
                    'last_login': profile.last_login,
                    'created_at': profile.created_at,
                    'queries_remaining_today': profile.queries_remaining_today,
                    'daily_query_limit': profile.daily_query_limit,
                }
            })
            
        except Exception as e:
            logger.error(f"Error fetching profile: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to fetch profile'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ProfileUpdateView(APIView):
    """
    Update user profile.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def put(self, request):
        serializer = UpdateProfileSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            profile = get_object_or_404(Profile, id=request.supabase_user.user_id)
            
            # Update profile fields
            for field, value in serializer.validated_data.items():
                if hasattr(profile, field) and value is not None:
                    setattr(profile, field, value)
            
            profile.save()
            
            # Sync with Supabase
            supabase_client = SupabaseClient()
            supabase_client.upsert_profile(str(profile.id), serializer.validated_data)
            
            logger.info(f"Updated profile for user {profile.id}")
            
            return Response({
                'success': True,
                'message': 'Profile updated successfully',
                'profile': {
                    'id': str(profile.id),
                    'first_name': profile.first_name,
                    'last_name': profile.last_name,
                    'phone': profile.phone,
                    'company': profile.company,
                    'business_type': profile.business_type,
                    'city': profile.city,
                    'state': profile.state,
                    'theme': profile.theme,
                    'language': profile.language,
                    'timezone': profile.timezone,
                }
            })
            
        except Exception as e:
            logger.error(f"Error updating profile: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to update profile'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ChangePasswordView(APIView):
    """
    Change user password.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            # Verify current password by attempting login
            supabase_client = SupabaseClient()
            
            # First verify current password
            login_result = supabase_client.sign_in(
                request.supabase_user.email,
                serializer.validated_data['current_password']
            )
            
            if not login_result['success']:
                return Response({
                    'success': False,
                    'errors': {
                        'current_password': ['Current password is incorrect']
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Update password using the session from login
            update_result = supabase_client.anon_client.auth.update_user({
                'password': serializer.validated_data['new_password']
            })
            
            if update_result.user:
                logger.info(f"Password changed for user {request.supabase_user.user_id}")
                return Response({
                    'success': True,
                    'message': 'Password changed successfully'
                })
            else:
                return Response({
                    'success': False,
                    'error': 'Failed to change password'
                }, status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f"Error changing password: {str(e)}")
            return Response({
                'success': False,
                'error': 'An error occurred while changing password'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class UserSettingsView(APIView):
    """
    Get and update user settings.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        try:
            profile = get_object_or_404(Profile, id=request.supabase_user.user_id)
            
            return Response({
                'success': True,
                'settings': {
                    'theme': profile.theme,
                    'language': profile.language,
                    'timezone': profile.timezone,
                    'account_tier': profile.account_tier,
                    'daily_query_limit': profile.daily_query_limit,
                    'queries_used_today': profile.queries_used_today,
                }
            })
            
        except Exception as e:
            logger.error(f"Error fetching settings: {str(e)}")
            return Response({
                'success': False,
                'error': 'Failed to fetch settings'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class NotificationSettingsView(APIView):
    """
    Placeholder for notification settings.
    Can be expanded later with proper notification preferences.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        return Response({
            'success': True,
            'notifications': {
                'email': True,
                'sms': False,
                'push': True,
                'billing': True,
                'usage': True,
            }
        })
    
    def post(self, request):
        # Placeholder for updating notification settings
        return Response({
            'success': True,
            'message': 'Notification settings updated'
        })