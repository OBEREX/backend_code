import logging
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from auth_integration.supabase_client import SupabaseClient
from django.shortcuts import get_object_or_404
from users.models import Profile

from auth_integration.permissions import IsSupabaseAuthenticated, IsEmailVerified
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
    
class DeleteUserView(APIView):
    """
    Delete a user from both Django and Supabase.
    This endpoint should be used carefully and ideally restricted to admin users.
    """
    permission_classes = [AllowAny]  # Change to [IsAdminUser] for production
    
    def delete(self, request, user_id=None):
        """
        Delete a user by ID or email.
        
        Usage:
        DELETE /auth/users/delete/
        Body: {"email": "user@example.com"} OR {"user_id": "uuid"}
        
        Or:
        DELETE /auth/users/delete/{user_id}/
        """
        try:
            # Get user identifier from URL parameter or request body
            if not user_id:
                user_id = request.data.get('user_id')
                email = request.data.get('email')
                
                if not user_id and not email:
                    return Response({
                        'success': False,
                        'error': 'USER_ID_OR_EMAIL_REQUIRED',
                        'message': 'Either user_id or email must be provided'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
                # Find user by email if user_id not provided
                if email and not user_id:
                    try:
                        profile = Profile.objects.get(email=email)
                        user_id = str(profile.id)
                    except Profile.DoesNotExist:
                        return Response({
                            'success': False,
                            'error': 'USER_NOT_FOUND',
                            'message': f'No user found with email: {email}'
                        }, status=status.HTTP_404_NOT_FOUND)
            
            # Get the profile to delete
            profile = get_object_or_404(Profile, id=user_id)
            user_email = profile.email
            
            logger.info(f"Attempting to delete user: {user_id} ({user_email})")
            
            # Delete from Supabase first
            supabase_client = SupabaseClient()
            supabase_deleted = self._delete_from_supabase(supabase_client, user_id)
            
            # Delete from Django (this will cascade delete related data)
            profile.delete()
            logger.info(f"Successfully deleted user from Django: {user_id}")
            
            return Response({
                'success': True,
                'message': f'User {user_email} deleted successfully',
                'user_id': user_id,
                'deleted_from_supabase': supabase_deleted
            }, status=status.HTTP_200_OK)
            
        except Profile.DoesNotExist:
            return Response({
                'success': False,
                'error': 'USER_NOT_FOUND',
                'message': f'No user found with ID: {user_id}'
            }, status=status.HTTP_404_NOT_FOUND)
            
        except Exception as e:
            logger.error(f"Error deleting user {user_id}: {str(e)}")
            return Response({
                'success': False,
                'error': 'DELETION_ERROR',
                'message': 'An error occurred while deleting the user'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _delete_from_supabase(self, supabase_client, user_id):
        """Delete user from Supabase auth."""
        try:
            # Use admin client to delete user
            response = supabase_client.service_client.auth.admin.delete_user(user_id)
            logger.info(f"Successfully deleted user from Supabase: {user_id}")
            return True
        except Exception as e:
            logger.warning(f"Failed to delete user from Supabase {user_id}: {str(e)}")
            # Don't fail the whole operation if Supabase deletion fails
            return False

class ListUsersView(APIView):
    """
    List all users for admin purposes.
    Helpful for seeing which users exist before deletion.
    """
    permission_classes = [AllowAny]  # Change to [IsAdminUser] for production
    
    def get(self, request):
        """List all users with basic info."""
        try:
            profiles = Profile.objects.all().order_by('-created_at')
            
            users_data = []
            for profile in profiles:
                users_data.append({
                    'id': str(profile.id),
                    'email': profile.email,
                    'full_name': profile.full_name,
                    'company': profile.company,
                    'is_verified': profile.is_verified,
                    'created_at': profile.created_at.isoformat(),
                    'last_login': profile.last_login.isoformat() if profile.last_login else None,
                })
            
            return Response({
                'success': True,
                'users': users_data,
                'total_count': len(users_data)
            })
            
        except Exception as e:
            logger.error(f"Error listing users: {str(e)}")
            return Response({
                'success': False,
                'error': 'LIST_ERROR',
                'message': 'An error occurred while listing users'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BulkDeleteUsersView(APIView):
    """
    Delete multiple users at once.
    Useful for cleaning up test data.
    """
    permission_classes = [AllowAny]  # Change to [IsAdminUser] for production
    
    def post(self, request):
        """
        Delete multiple users by email or ID.
        
        Body: {
            "emails": ["user1@example.com", "user2@example.com"],
            "user_ids": ["uuid1", "uuid2"],
            "confirm": true
        }
        """
        try:
            emails = request.data.get('emails', [])
            user_ids = request.data.get('user_ids', [])
            confirm = request.data.get('confirm', False)
            
            if not confirm:
                return Response({
                    'success': False,
                    'error': 'CONFIRMATION_REQUIRED',
                    'message': 'Set "confirm": true to proceed with bulk deletion'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not emails and not user_ids:
                return Response({
                    'success': False,
                    'error': 'NO_USERS_SPECIFIED',
                    'message': 'Provide either emails or user_ids array'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            deleted_users = []
            failed_deletions = []
            
            # Delete users by email
            for email in emails:
                try:
                    profile = Profile.objects.get(email=email)
                    self._delete_single_user(profile)
                    deleted_users.append({'email': email, 'id': str(profile.id)})
                except Profile.DoesNotExist:
                    failed_deletions.append({'email': email, 'reason': 'User not found'})
                except Exception as e:
                    failed_deletions.append({'email': email, 'reason': str(e)})
            
            # Delete users by ID
            for user_id in user_ids:
                try:
                    profile = Profile.objects.get(id=user_id)
                    self._delete_single_user(profile)
                    deleted_users.append({'email': profile.email, 'id': user_id})
                except Profile.DoesNotExist:
                    failed_deletions.append({'user_id': user_id, 'reason': 'User not found'})
                except Exception as e:
                    failed_deletions.append({'user_id': user_id, 'reason': str(e)})
            
            return Response({
                'success': True,
                'message': f'Bulk deletion completed. {len(deleted_users)} users deleted, {len(failed_deletions)} failed',
                'deleted_users': deleted_users,
                'failed_deletions': failed_deletions
            })
            
        except Exception as e:
            logger.error(f"Error in bulk user deletion: {str(e)}")
            return Response({
                'success': False,
                'error': 'BULK_DELETION_ERROR',
                'message': 'An error occurred during bulk deletion'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def _delete_single_user(self, profile):
        """Helper method to delete a single user."""
        user_id = str(profile.id)
        
        # Try to delete from Supabase
        try:
            supabase_client = SupabaseClient()
            supabase_client.service_client.auth.admin.delete_user(user_id)
        except Exception as e:
            logger.warning(f"Failed to delete user from Supabase {user_id}: {str(e)}")
        
        # Delete from Django
        profile.delete()
        logger.info(f"Deleted user: {profile.email} ({user_id})")