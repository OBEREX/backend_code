import json
from typing import Dict, Any, Optional
from django.db import transaction
from django.http import JsonResponse
from django.utils import timezone
from pefoma_backend import settings
from users.models import Profile
import logging
from django.views import View

logger = logging.getLogger(__name__)


class ProfileSyncStrategy:
    """
    Handles profile synchronization between Supabase and Django.
    Includes conflict resolution, validation, and data mapping.
    """
    
    # Required fields for profile creation
    REQUIRED_FIELDS = [
        'first_name', 'last_name', 'email', 'phone',
        'company', 'business_type', 'city', 'state'
    ]
    
    # Field mapping from Supabase to Django
    FIELD_MAPPING = {
        'user_metadata': {
            'first_name': 'first_name',
            'last_name': 'last_name',
            'phone': 'phone',
            'company': 'company',
            'business_type': 'business_type',
            'city': 'city',
            'state': 'state',
            'avatar_url': 'avatar_url',
            'theme': 'theme',
            'language': 'language',
            'timezone': 'timezone'
        },
        'root': {
            'email': 'email',
            'email_confirmed_at': 'verified_at',
            'phone': 'phone',
            'phone_confirmed_at': 'phone_verified_at'
        }
    }
    
    @classmethod
    def extract_profile_data(cls, supabase_user: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract profile data from Supabase user object.
        
        Args:
            supabase_user: User data from Supabase
            
        Returns:
            Normalized profile data
        """
        profile_data = {}
        
        # Extract from user_metadata
        user_metadata = supabase_user.get('user_metadata', {}) or supabase_user.get('raw_user_meta_data', {})
        for sup_field, django_field in cls.FIELD_MAPPING['user_metadata'].items():
            if sup_field in user_metadata:
                profile_data[django_field] = user_metadata[sup_field]
        
        # Extract from root level
        for sup_field, django_field in cls.FIELD_MAPPING['root'].items():
            if sup_field in supabase_user:
                value = supabase_user[sup_field]
                if django_field == 'verified_at' and value:
                    profile_data['is_verified'] = True
                    profile_data['verified_at'] = value
                    profile_data['verification_method'] = 'email'
                else:
                    profile_data[django_field] = value
        
        # Set user ID
        profile_data['id'] = supabase_user.get('id')
        
        return profile_data
    
    @classmethod
    def validate_required_fields(cls, profile_data: Dict[str, Any]) -> tuple[bool, list]:
        """
        Validate that all required fields are present.
        
        Returns:
            Tuple of (is_valid, missing_fields)
        """
        missing_fields = []
        for field in cls.REQUIRED_FIELDS:
            if field not in profile_data or not profile_data[field]:
                missing_fields.append(field)
        
        return len(missing_fields) == 0, missing_fields
    
    @classmethod
    def provide_defaults(cls, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Provide sensible defaults for missing fields.
        
        Args:
            profile_data: Partial profile data
            
        Returns:
            Profile data with defaults
        """
        defaults = {
            'first_name': 'User',
            'last_name': 'Pending',
            'phone': 'Not Provided',
            'company': 'Not Specified',
            'business_type': 'Other',
            'city': 'Not Specified',
            'state': 'Not Specified',
            'theme': 'auto',
            'language': 'en',
            'timezone': 'UTC',
            'account_tier': 'free',
            'daily_query_limit': 10,
            'queries_used_today': 0
        }
        
        for field, default_value in defaults.items():
            if field not in profile_data or not profile_data[field]:
                profile_data[field] = default_value
                logger.info(f"Using default value for {field}: {default_value}")
        
        return profile_data
    
    @classmethod
    @transaction.atomic
    def sync_profile(cls, supabase_user: Dict[str, Any], 
                    conflict_strategy: str = 'supabase_wins') -> Optional[Profile]:
        """
        Sync profile from Supabase to Django.
        
        Args:
            supabase_user: User data from Supabase
            conflict_strategy: How to handle conflicts
                - 'supabase_wins': Supabase data overwrites Django
                - 'django_wins': Keep Django data, only fill missing
                - 'merge': Merge with timestamps (newest wins)
                - 'manual': Flag for manual resolution
        
        Returns:
            Profile instance or None if sync failed
        """
        try:
            user_id = supabase_user.get('id')
            if not user_id:
                logger.error("No user ID in Supabase data")
                return None
            
            # Extract and normalize data
            profile_data = cls.extract_profile_data(supabase_user)
            
            # Check if profile exists
            try:
                existing_profile = Profile.objects.select_for_update().get(id=user_id)
                return cls._handle_existing_profile(
                    existing_profile, profile_data, conflict_strategy
                )
            except Profile.DoesNotExist:
                return cls._create_new_profile(profile_data)
                
        except Exception as e:
            logger.error(f"Profile sync failed: {str(e)}")
            return None
    
    @classmethod
    def _handle_existing_profile(cls, profile: Profile, 
                                new_data: Dict[str, Any], 
                                strategy: str) -> Profile:
        """
        Handle updating an existing profile with conflict resolution.
        
        Args:
            profile: Existing profile instance
            new_data: New data from Supabase
            strategy: Conflict resolution strategy
        
        Returns:
            Updated profile instance
        """
        if strategy == 'supabase_wins':
            # Overwrite all fields with Supabase data
            for field, value in new_data.items():
                if hasattr(profile, field) and field != 'id':
                    setattr(profile, field, value)
            profile.save()
            logger.info(f"Profile {profile.id} updated with Supabase data (supabase_wins)")
            
        elif strategy == 'django_wins':
            # Only fill in missing fields
            for field, value in new_data.items():
                if hasattr(profile, field) and field != 'id':
                    current_value = getattr(profile, field)
                    if not current_value or current_value in ['Not Provided', 'Not Specified']:
                        setattr(profile, field, value)
            profile.save()
            logger.info(f"Profile {profile.id} updated with missing fields only (django_wins)")
            
        elif strategy == 'merge':
            # Merge based on timestamps
            cls._merge_by_timestamp(profile, new_data)
            profile.save()
            logger.info(f"Profile {profile.id} merged by timestamp (merge)")
            
        elif strategy == 'manual':
            # Create conflict record for manual resolution
            cls._create_conflict_record(profile, new_data)
            logger.warning(f"Profile {profile.id} has conflicts, flagged for manual resolution")
        
        return profile
    
    @classmethod
    def _create_new_profile(cls, profile_data: Dict[str, Any]) -> Optional[Profile]:
        """
        Create a new profile with validation.
        
        Args:
            profile_data: Profile data dictionary
            
        Returns:
            New profile instance or None if creation failed
        """
        # Validate required fields
        is_valid, missing_fields = cls.validate_required_fields(profile_data)
        
        if not is_valid:
            logger.warning(f"Missing required fields: {missing_fields}")
            # Apply defaults
            profile_data = cls.provide_defaults(profile_data)
        
        try:
            profile = Profile.objects.create(**profile_data)
            logger.info(f"Created new profile for user {profile.id}")
            return profile
        except Exception as e:
            logger.error(f"Failed to create profile: {str(e)}")
            return None
    
    @classmethod
    def _merge_by_timestamp(cls, profile: Profile, new_data: Dict[str, Any]):
        """
        Merge data based on update timestamps.
        
        Args:
            profile: Existing profile
            new_data: New data from Supabase
        """
        # Get Supabase update time
        supabase_updated = new_data.get('updated_at') or new_data.get('created_at')
        if isinstance(supabase_updated, str):
            from dateutil import parser
            supabase_updated = parser.parse(supabase_updated)
        
        # Compare with Django update time
        django_updated = profile.updated_at
        
        if not supabase_updated or not django_updated:
            # Can't compare, use Supabase data
            for field, value in new_data.items():
                if hasattr(profile, field) and field != 'id':
                    setattr(profile, field, value)
        elif supabase_updated > django_updated:
            # Supabase is newer
            for field, value in new_data.items():
                if hasattr(profile, field) and field != 'id':
                    setattr(profile, field, value)
        # else: Django is newer, keep current data
    
    @classmethod
    def _create_conflict_record(cls, profile: Profile, new_data: Dict[str, Any]):
        """
        Create a record of sync conflicts for manual resolution.
        
        Args:
            profile: Existing profile
            new_data: Conflicting data from Supabase
        """
        from django.core.cache import cache
        
        conflicts = {}
        for field, new_value in new_data.items():
            if hasattr(profile, field) and field != 'id':
                current_value = getattr(profile, field)
                if current_value != new_value:
                    conflicts[field] = {
                        'current': current_value,
                        'new': new_value
                    }
        
        if conflicts:
            # Store in cache for admin review
            cache.set(
                f"profile_conflict:{profile.id}",
                {
                    'profile_id': str(profile.id),
                    'conflicts': conflicts,
                    'timestamp': timezone.now().isoformat()
                },
                timeout=86400  # Keep for 24 hours
            )
            
            # You could also create a database model for persistent conflict tracking
            # ProfileSyncConflict.objects.create(profile=profile, conflicts=conflicts)


class ProfileWebhookHandler:
    """
    Handle Supabase webhook events for profile synchronization.
    """
    
    def __init__(self, sync_strategy: ProfileSyncStrategy = None):
        self.sync_strategy = sync_strategy or ProfileSyncStrategy()
    
    def handle_user_created(self, payload: Dict[str, Any]) -> bool:
        """
        Handle user creation webhook from Supabase.
        
        Args:
            payload: Webhook payload
            
        Returns:
            Success status
        """
        try:
            user_data = payload.get('record', {})
            
            # Sync profile with 'supabase_wins' strategy for new users
            profile = ProfileSyncStrategy.sync_profile(
                user_data, 
                conflict_strategy='supabase_wins'
            )
            
            return profile is not None
            
        except Exception as e:
            logger.error(f"Failed to handle user creation webhook: {str(e)}")
            return False
    
    def handle_user_updated(self, payload: Dict[str, Any]) -> bool:
        """
        Handle user update webhook from Supabase.
        
        Args:
            payload: Webhook payload
            
        Returns:
            Success status
        """
        try:
            user_data = payload.get('record', {})
            old_data = payload.get('old_record', {})
            
            # Determine conflict strategy based on what changed
            if self._is_critical_change(old_data, user_data):
                # Critical changes (email, verification) should always sync
                strategy = 'supabase_wins'
            else:
                # Non-critical changes can use merge strategy
                strategy = 'merge'
            
            profile = ProfileSyncStrategy.sync_profile(
                user_data,
                conflict_strategy=strategy
            )
            
            return profile is not None
            
        except Exception as e:
            logger.error(f"Failed to handle user update webhook: {str(e)}")
            return False
    
    def handle_user_deleted(self, payload: Dict[str, Any]) -> bool:
        """
        Handle user deletion webhook from Supabase.
        
        Args:
            payload: Webhook payload
            
        Returns:
            Success status
        """
        try:
            user_data = payload.get('old_record', {})
            user_id = user_data.get('id')
            
            if user_id:
                # Soft delete or hard delete based on your requirements
                Profile.objects.filter(id=user_id).delete()
                logger.info(f"Deleted profile for user {user_id}")
                return True
                
            return False
            
        except Exception as e:
            logger.error(f"Failed to handle user deletion webhook: {str(e)}")
            return False
    
    def _is_critical_change(self, old_data: Dict[str, Any], 
                           new_data: Dict[str, Any]) -> bool:
        """
        Determine if the change is critical and should override local data.
        
        Args:
            old_data: Previous user data
            new_data: New user data
            
        Returns:
            True if critical change
        """
        critical_fields = ['email', 'email_confirmed_at', 'phone', 'banned_until']
        
        for field in critical_fields:
            if old_data.get(field) != new_data.get(field):
                return True
        
        return False


# Usage in webhook view
class SupabaseWebhookView(View):
    """
    Enhanced webhook view with proper sync handling.
    """
    
    def post(self, request):
        try:
            # Verify webhook signature
            if not self._verify_signature(request):
                return JsonResponse({'error': 'Invalid signature'}, status=401)
            
            payload = json.loads(request.body.decode('utf-8'))
            event_type = payload.get('type')
            
            handler = ProfileWebhookHandler()
            
            if event_type == 'INSERT':
                success = handler.handle_user_created(payload)
            elif event_type == 'UPDATE':
                success = handler.handle_user_updated(payload)
            elif event_type == 'DELETE':
                success = handler.handle_user_deleted(payload)
            else:
                logger.warning(f"Unknown webhook event type: {event_type}")
                success = False
            
            return JsonResponse({'success': success})
            
        except Exception as e:
            logger.error(f"Webhook error: {str(e)}")
            return JsonResponse({'error': str(e)}, status=500)
    
    def _verify_signature(self, request) -> bool:
        """
        Verify webhook signature from Supabase.
        
        Args:
            request: HTTP request
            
        Returns:
            True if signature is valid
        """
        webhook_secret = getattr(settings, 'SUPABASE_WEBHOOK_SECRET', '')
        if not webhook_secret:
            # No secret configured, skip verification (not recommended for production)
            return True
        
        signature = request.META.get('HTTP_X_SUPABASE_SIGNATURE', '')
        if not signature:
            return False
        
        # Implement HMAC verification
        import hmac
        import hashlib
        
        expected_signature = hmac.new(
            webhook_secret.encode(),
            request.body,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(signature, expected_signature)