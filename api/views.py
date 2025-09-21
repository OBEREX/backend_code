# File: api/views.py

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from auth_integration.permissions import IsSupabaseAuthenticated, IsEmailVerified


class APIRootView(APIView):
    """
    API root endpoint that lists available API endpoints.
    """
    permission_classes = []
    
    def get(self, request):
        return Response({
            'api_version': 'v1',
            'service': 'pefoma-backend',
            'endpoints': {
                'authentication': {
                    'signup': '/api/v1/auth/signup/',
                    'login': '/api/v1/auth/login/',
                    'logout': '/api/v1/auth/logout/',
                    'forgot_password': '/api/v1/auth/forgot-password/',
                    'reset_password': '/api/v1/auth/reset-password/',
                    'verify_otp': '/api/v1/auth/verify-otp/',
                    'refresh_token': '/api/v1/auth/refresh/',
                    'profile': '/api/v1/auth/profile/',
                },
                'users': {
                    'profile_detail': '/api/v1/users/profile/',
                    'profile_update': '/api/v1/users/profile/update/',
                    'change_password': '/api/v1/users/change-password/',
                    'settings': '/api/v1/users/settings/',
                },
                'health': '/health/',
            }
        })


class ProtectedTestView(APIView):
    """
    Test endpoint for verifying authentication middleware.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        return Response({
            'success': True,
            'message': 'Authentication successful',
            'user': request.supabase_user.to_dict() if request.supabase_user else None,
            'timestamp': timezone.now().isoformat(),
        })