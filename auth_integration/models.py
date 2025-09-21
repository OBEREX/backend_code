# File: auth_integration/models.py

from dataclasses import dataclass
from typing import Dict, Any, Optional
from datetime import datetime


@dataclass
class SupabaseUser:
    """
    Data class representing a Supabase user from JWT token.
    This is attached to request.supabase_user by the middleware.
    """
    user_id: str
    email: str
    email_confirmed_at: Optional[str] = None
    phone: Optional[str] = None
    role: str = 'authenticated'
    app_metadata: Dict[str, Any] = None
    user_metadata: Dict[str, Any] = None
    aud: str = 'authenticated'
    exp: Optional[int] = None
    iat: Optional[int] = None
    iss: Optional[str] = None
    
    def __post_init__(self):
        if self.app_metadata is None:
            self.app_metadata = {}
        if self.user_metadata is None:
            self.user_metadata = {}
    
    @property
    def is_authenticated(self) -> bool:
        """Check if user is authenticated."""
        return bool(self.user_id and self.email)
    
    @property
    def is_email_confirmed(self) -> bool:
        """Check if email is confirmed."""
        return bool(self.email_confirmed_at)
    
    @property
    def is_phone_confirmed(self) -> bool:
        """Check if phone is confirmed."""
        return bool(self.phone and self.user_metadata.get('phone_confirmed_at'))
    
    @property
    def full_name(self) -> str:
        """Get full name from metadata."""
        return self.user_metadata.get('full_name', '')
    
    @property
    def first_name(self) -> str:
        """Get first name from metadata."""
        return self.user_metadata.get('first_name', '')
    
    @property
    def last_name(self) -> str:
        """Get last name from metadata."""
        return self.user_metadata.get('last_name', '')
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            'user_id': self.user_id,
            'email': self.email,
            'email_confirmed_at': self.email_confirmed_at,
            'phone': self.phone,
            'role': self.role,
            'app_metadata': self.app_metadata,
            'user_metadata': self.user_metadata,
            'is_authenticated': self.is_authenticated,
            'is_email_confirmed': self.is_email_confirmed,
            'is_phone_confirmed': self.is_phone_confirmed,
        }


