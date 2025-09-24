# auth_integration/token_providers.py
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple
import jwt
import secrets
import hashlib
from datetime import datetime, timedelta
from django.conf import settings
from django.core.cache import cache
import logging

logger = logging.getLogger(__name__)


class TokenProvider(ABC):
    """Abstract base class for token providers."""
    
    @abstractmethod
    def create_access_token(self, user_id: str, email: str, metadata: Dict[str, Any] = None) -> str:
        """Create an access token."""
        pass
    
    @abstractmethod
    def create_refresh_token(self, user_id: str) -> str:
        """Create a refresh token."""
        pass
    
    @abstractmethod
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode an access token."""
        pass
    
    @abstractmethod
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify a refresh token."""
        pass
    
    @abstractmethod
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        pass
    
    @abstractmethod
    def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Refresh both access and refresh tokens."""
        pass


class SupabaseTokenProvider(TokenProvider):
    """Supabase JWT token provider."""
    
    def __init__(self, supabase_client):
        self.client = supabase_client
        self.jwt_secret = settings.SUPABASE_JWT_SECRET
    
    def create_access_token(self, user_id: str, email: str, metadata: Dict[str, Any] = None) -> str:
        """
        Note: Supabase creates tokens during auth operations.
        This method is for compatibility when switching providers.
        """
        # Supabase handles this internally during sign_in
        # This is a placeholder for interface compatibility
        raise NotImplementedError("Supabase creates tokens during authentication")
    
    def create_refresh_token(self, user_id: str) -> str:
        """Supabase creates refresh tokens during auth."""
        raise NotImplementedError("Supabase creates tokens during authentication")
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify Supabase JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=['HS256'],
                options={'verify_aud': False}
            )
            
            # Check required claims
            if not payload.get('sub') or not payload.get('email'):
                logger.warning("Invalid JWT payload: missing required claims")
                return None
            
            return {
                'user_id': payload['sub'],
                'email': payload['email'],
                'email_verified': bool(payload.get('email_confirmed_at')),
                'role': payload.get('role', 'authenticated'),
                'metadata': payload.get('user_metadata', {}),
                'exp': payload.get('exp'),
                'iat': payload.get('iat')
            }
            
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {str(e)}")
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token with Supabase."""
        try:
            response = self.client.auth.refresh_session(token)
            if response and response.user:
                return {
                    'user_id': response.user.id,
                    'email': response.user.email,
                    'valid': True
                }
            return None
        except Exception as e:
            logger.error(f"Failed to verify refresh token: {str(e)}")
            return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke token via Supabase."""
        try:
            self.client.auth.sign_out()
            return True
        except Exception as e:
            logger.error(f"Failed to revoke token: {str(e)}")
            return False
    
    def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Refresh tokens using Supabase."""
        try:
            response = self.client.auth.refresh_session(refresh_token)
            if response and response.session:
                return (
                    response.session.access_token,
                    response.session.refresh_token
                )
            return None
        except Exception as e:
            logger.error(f"Failed to refresh tokens: {str(e)}")
            return None


class DjangoTokenProvider(TokenProvider):
    """
    Custom Django JWT token provider.
    For when you want to move away from Supabase.
    """
    
    def __init__(self):
        self.secret_key = settings.SECRET_KEY
        self.access_token_ttl = timedelta(minutes=15)
        self.refresh_token_ttl = timedelta(days=7)
    
    def create_access_token(self, user_id: str, email: str, metadata: Dict[str, Any] = None) -> str:
        """Create a custom JWT access token."""
        now = datetime.utcnow()
        payload = {
            'sub': user_id,
            'email': email,
            'type': 'access',
            'iat': now,
            'exp': now + self.access_token_ttl,
            'iss': 'pefoma-backend',
            **(metadata or {})
        }
        
        return jwt.encode(payload, self.secret_key, algorithm='HS256')
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create a custom refresh token."""
        # Generate secure random token
        token = secrets.token_urlsafe(32)
        
        # Store in cache/database with expiry
        cache_key = f"refresh_token:{token}"
        cache.set(
            cache_key,
            {
                'user_id': user_id,
                'created_at': datetime.utcnow().isoformat(),
                'type': 'refresh'
            },
            timeout=int(self.refresh_token_ttl.total_seconds())
        )
        
        return token
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify custom JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=['HS256']
            )
            
            if payload.get('type') != 'access':
                return None
            
            return {
                'user_id': payload['sub'],
                'email': payload['email'],
                'email_verified': payload.get('email_verified', True),
                'role': payload.get('role', 'authenticated'),
                'metadata': {k: v for k, v in payload.items() 
                           if k not in ['sub', 'email', 'type', 'iat', 'exp', 'iss']},
                'exp': payload.get('exp'),
                'iat': payload.get('iat')
            }
            
        except jwt.ExpiredSignatureError:
            logger.warning("Custom JWT token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid custom JWT token: {str(e)}")
            return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify custom refresh token."""
        cache_key = f"refresh_token:{token}"
        token_data = cache.get(cache_key)
        
        if token_data and token_data.get('type') == 'refresh':
            return {
                'user_id': token_data['user_id'],
                'valid': True
            }
        return None
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token by adding to blacklist."""
        try:
            # For access tokens, add to blacklist until expiry
            payload = jwt.decode(token, self.secret_key, algorithms=['HS256'], 
                               options={'verify_exp': False})
            exp = payload.get('exp')
            if exp:
                ttl = exp - datetime.utcnow().timestamp()
                if ttl > 0:
                    cache.set(f"blacklist:{token}", True, timeout=int(ttl))
            
            # For refresh tokens, delete from cache
            cache.delete(f"refresh_token:{token}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke token: {str(e)}")
            return False
    
    def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Generate new token pair from refresh token."""
        token_data = self.verify_refresh_token(refresh_token)
        if not token_data:
            return None
        
        user_id = token_data['user_id']
        
        # Get user email from database
        from users.models import Profile
        try:
            profile = Profile.objects.get(id=user_id)
            email = profile.email
            
            # Revoke old refresh token
            self.revoke_token(refresh_token)
            
            # Create new tokens
            new_access = self.create_access_token(user_id, email)
            new_refresh = self.create_refresh_token(user_id)
            
            return (new_access, new_refresh)
            
        except Profile.DoesNotExist:
            logger.error(f"Profile not found for user {user_id}")
            return None


class HybridTokenProvider(TokenProvider):
    """
    Hybrid provider that can use both Supabase and Django tokens.
    Useful during migration period.
    """
    
    def __init__(self, supabase_client):
        self.supabase_provider = SupabaseTokenProvider(supabase_client)
        self.django_provider = DjangoTokenProvider()
        self.mode = getattr(settings, 'TOKEN_PROVIDER_MODE', 'supabase')
    
    def create_access_token(self, user_id: str, email: str, metadata: Dict[str, Any] = None) -> str:
        """Create token using configured provider."""
        if self.mode == 'django':
            return self.django_provider.create_access_token(user_id, email, metadata)
        # Supabase doesn't support direct token creation
        raise NotImplementedError("Use Supabase auth methods for token creation")
    
    def create_refresh_token(self, user_id: str) -> str:
        """Create refresh token using configured provider."""
        if self.mode == 'django':
            return self.django_provider.create_refresh_token(user_id)
        raise NotImplementedError("Use Supabase auth methods for token creation")
    
    def verify_access_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Try both providers to verify token."""
        # Try Supabase first
        result = self.supabase_provider.verify_access_token(token)
        if result:
            return result
        
        # Fallback to Django
        if self.mode in ['django', 'hybrid']:
            return self.django_provider.verify_access_token(token)
        
        return None
    
    def verify_refresh_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify refresh token with appropriate provider."""
        if self.mode == 'django':
            return self.django_provider.verify_refresh_token(token)
        return self.supabase_provider.verify_refresh_token(token)
    
    def revoke_token(self, token: str) -> bool:
        """Revoke token with appropriate provider."""
        if self.mode == 'django':
            return self.django_provider.revoke_token(token)
        return self.supabase_provider.revoke_token(token)
    
    def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Refresh tokens with appropriate provider."""
        if self.mode == 'django':
            return self.django_provider.refresh_tokens(refresh_token)
        return self.supabase_provider.refresh_tokens(refresh_token)


class TokenService:
    """
    Main token service facade.
    This is what the application uses.
    """
    
    def __init__(self):
        self.provider = self._get_provider()
    
    def _get_provider(self) -> TokenProvider:
        """Get token provider based on configuration."""
        provider_type = getattr(settings, 'TOKEN_PROVIDER', 'hybrid')
        
        if provider_type == 'supabase':
            from auth_integration.supabase_client import SupabaseClient
            return SupabaseTokenProvider(SupabaseClient())
        
        elif provider_type == 'django':
            return DjangoTokenProvider()
        
        elif provider_type == 'hybrid':
            from auth_integration.supabase_client import SupabaseClient
            return HybridTokenProvider(SupabaseClient())
        
        else:
            raise ValueError(f"Unknown token provider: {provider_type}")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode a token."""
        return self.provider.verify_access_token(token)
    
    def refresh_tokens(self, refresh_token: str) -> Optional[Tuple[str, str]]:
        """Refresh token pair."""
        return self.provider.refresh_tokens(refresh_token)
    
    def revoke_token(self, token: str) -> bool:
        """Revoke a token."""
        return self.provider.revoke_token(token)
    
    def switch_provider(self, provider_type: str):
        """Switch token provider at runtime."""
        settings.TOKEN_PROVIDER = provider_type
        self.provider = self._get_provider()
        logger.info(f"Switched token provider to: {provider_type}")


# Singleton instance
token_service = TokenService()