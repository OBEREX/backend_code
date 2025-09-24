from typing import Optional, Dict, Any
from django.db import transaction
from .supabase_client import SupabaseClient
from users.models import Profile

class AuthService:
    def __init__(self):
        self.supabase = SupabaseClient()
    
    @transaction.atomic
    def register_user(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Handle complete user registration flow."""
        # Create in Supabase
        auth_result = self.supabase.create_user(
            email=data['email'],
            password=data['password'],
            user_metadata=self._prepare_metadata(data) # type: ignore
        )
        
        if not auth_result['success']:
            return auth_result
        
        # Create local profile
        profile = self._create_profile(auth_result['user']['id'], data)
        
        # Send verification email
        self._send_verification_email(data['email'])
        
        return {
            'success': True,
            'user': auth_result['user'],
            'profile': profile
        }