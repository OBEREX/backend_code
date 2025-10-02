import uuid
from django.db import models
from django.utils import timezone as tm


class Profile(models.Model):
    """
    User profile model that mirrors the Supabase profiles table.
    This model is kept in sync with Supabase via webhooks.
    """
    
    BUSINESS_TYPE_CHOICES = [
        ('Retail & E-Commerce', 'Retail & E-Commerce'),
        ('Wholesale & Distribution', 'Wholesale & Distribution'),
        ('Manufacturing', 'Manufacturing'),
        ('Restaurant & Food Service', 'Restaurant & Food Service'),
        ('Healthcare & Pharmacy', 'Healthcare & Pharmacy'),
        ('Automotive', 'Automotive'),
        ('Construction & Hardware', 'Construction & Hardware'),
        ('Technology & Electronics', 'Technology & Electronics'),
        ('Fashion & Apparel', 'Fashion & Apparel'),
        ('Agriculture & Farming', 'Agriculture & Farming'),
        ('Logistics & Warehousing', 'Logistics & Warehousing'),
        ('Education & Training', 'Education & Training'),
        ('Non-Profit Organization', 'Non-Profit Organization'),
        ('Other', 'Other'),
    ]
    
    ACCOUNT_TIER_CHOICES = [
        ('guest', 'Guest'),
        ('free', 'Free'),
        ('premium', 'Premium'),
        ('enterprise', 'Enterprise'),
    ]
    
    THEME_CHOICES = [
        ('light', 'Light'),
        ('dark', 'Dark'),
        ('auto', 'Auto'),
    ]
    
    VERIFICATION_METHOD_CHOICES = [
        ('email', 'Email'),
        ('phone', 'Phone'),
    ]
    
    # Primary key matches Supabase auth.users.id
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Required registration fields
    first_name = models.CharField(max_length=50)
    last_name = models.CharField(max_length=50)
    email = models.EmailField(unique=True)
    phone = models.CharField(max_length=20)
    company = models.CharField(max_length=100)
    business_type = models.CharField(max_length=50, choices=BUSINESS_TYPE_CHOICES)
    city = models.CharField(max_length=50)
    state = models.CharField(max_length=50)
    
    # Account status
    is_verified = models.BooleanField(default=False)
    verification_method = models.CharField(
        max_length=10, 
        choices=VERIFICATION_METHOD_CHOICES, 
        null=True, 
        blank=True
    )
    verified_at = models.DateTimeField(null=True, blank=True)
    
    # Usage tracking
    is_guest = models.BooleanField(default=False)
    guest_converted_at = models.DateTimeField(null=True, blank=True)
    last_login = models.DateTimeField(null=True, blank=True)
    
    # Subscription/limits
    account_tier = models.CharField(
        max_length=20, 
        choices=ACCOUNT_TIER_CHOICES, 
        default='free'
    )
    daily_query_limit = models.IntegerField(default=10)
    queries_used_today = models.IntegerField(default=0)
    
    # Profile settings
    avatar_url = models.URLField(null=True, blank=True)
    theme = models.CharField(max_length=10, choices=THEME_CHOICES, default='auto')
    language = models.CharField(max_length=10, default='en')
    timezone = models.CharField(max_length=50, default='UTC')
    
    # Timestamps
    created_at = models.DateTimeField(default=tm.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'profiles'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone']),
            models.Index(fields=['is_verified']),
            models.Index(fields=['account_tier']),
            models.Index(fields=['created_at']),
        ]
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"
    
    @property
    def full_name(self):
        """Get full name."""
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_premium_user(self):
        """Check if user has premium tier or higher."""
        return self.account_tier in ['premium', 'enterprise']
    
    @property
    def queries_remaining_today(self):
        """Get remaining queries for today."""
        return max(0, self.daily_query_limit - self.queries_used_today)
    
    def can_make_query(self):
        """Check if user can make a query today."""
        return self.queries_remaining_today > 0 or self.is_premium_user
    
    def increment_query_count(self):
        """Increment today's query count."""
        self.queries_used_today = models.F('queries_used_today') + 1
        self.save(update_fields=['queries_used_today'])
    
    def reset_daily_queries(self):
        """Reset daily query count (called by scheduled task)."""
        self.queries_used_today = 0
        self.save(update_fields=['queries_used_today'])











