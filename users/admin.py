from django.contrib import admin
from .models import Profile


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    """
    Admin interface for Profile model.
    """
    list_display = [
        'email', 'full_name', 'company', 'business_type', 
        'account_tier', 'is_verified', 'created_at'
    ]
    list_filter = [
        'account_tier', 'business_type', 'is_verified', 
        'verification_method', 'theme', 'created_at'
    ]
    search_fields = ['email', 'first_name', 'last_name', 'company']
    readonly_fields = ['id', 'created_at', 'updated_at', 'last_login']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('id', 'first_name', 'last_name', 'email', 'phone')
        }),
        ('Business Information', {
            'fields': ('company', 'business_type', 'city', 'state')
        }),
        ('Account Status', {
            'fields': ('is_verified', 'verification_method', 'verified_at', 'account_tier')
        }),
        ('Usage & Limits', {
            'fields': ('daily_query_limit', 'queries_used_today', 'is_guest', 'guest_converted_at')
        }),
        ('Preferences', {
            'fields': ('avatar_url', 'theme', 'language', 'timezone')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_login')
        }),
    )
    
    def full_name(self, obj):
        return obj.full_name
    full_name.short_description = 'Full Name'
    
    def get_queryset(self, request):
        """Optimize queryset for admin list view."""
        return super().get_queryset(request).select_related()