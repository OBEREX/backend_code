# File: dashboard/admin.py

from django.contrib import admin
from .models import Category, InventoryItem, Scan, ScannedItem, BenchmarkSettings


@admin.register(Category)
class CategoryAdmin(admin.ModelAdmin):
    list_display = ['name', 'is_default', 'company', 'color', 'created_at']
    list_filter = ['is_default', 'created_at']
    search_fields = ['name', 'company__email']
    ordering = ['is_default', 'name']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'is_default', 'company', 'color')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(InventoryItem)
class InventoryItemAdmin(admin.ModelAdmin):
    list_display = ['item_name', 'category', 'current_count', 'company', 'last_scanned', 'updated_at']
    list_filter = ['category', 'last_scanned', 'created_at']
    search_fields = ['item_name', 'company__email', 'notes']
    ordering = ['-last_scanned', 'item_name']
    readonly_fields = ['created_at', 'updated_at', 'last_scanned']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('company', 'item_name', 'category')
        }),
        ('Inventory Details', {
            'fields': ('current_count', 'unit_price', 'image_url')
        }),
        ('Additional Information', {
            'fields': ('notes', 'last_scanned')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'company', 'performed_by', 'scan_type', 
        'total_items_count', 'overall_confidence', 
        'time_saved_minutes', 'cost_saved_usd', 'timestamp'
    ]
    list_filter = ['scan_type', 'timestamp', 'company']
    search_fields = ['company__email', 'performed_by__email', 'id']
    ordering = ['-timestamp']
    readonly_fields = ['id', 'timestamp', 'time_saved_minutes', 'cost_saved_usd']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Scan Information', {
            'fields': ('id', 'company', 'performed_by', 'scan_type', 'media_url', 'timestamp')
        }),
        ('Scan Results', {
            'fields': ('total_items_count', 'processing_time_seconds', 'overall_confidence')
        }),
        ('Calculated Metrics', {
            'fields': ('time_saved_minutes', 'cost_saved_usd'),
            'description': 'These fields are automatically calculated based on benchmark settings.'
        }),
    )
    
    def get_queryset(self, request):
        """Optimize query with select_related."""
        qs = super().get_queryset(request)
        return qs.select_related('company', 'performed_by')


@admin.register(ScannedItem)
class ScannedItemAdmin(admin.ModelAdmin):
    list_display = ['item_name', 'scan', 'category', 'count', 'confidence', 'inventory_item']
    list_filter = ['category', 'scan__timestamp']
    search_fields = ['item_name', 'scan__id', 'inventory_item__item_name']
    ordering = ['-confidence', '-scan__timestamp']
    readonly_fields = ['scan']
    
    fieldsets = (
        ('Item Information', {
            'fields': ('scan', 'item_name', 'category', 'inventory_item')
        }),
        ('Detection Details', {
            'fields': ('count', 'confidence')
        }),
    )
    
    def get_queryset(self, request):
        """Optimize query with select_related."""
        qs = super().get_queryset(request)
        return qs.select_related('scan', 'category', 'inventory_item')


@admin.register(BenchmarkSettings)
class BenchmarkSettingsAdmin(admin.ModelAdmin):
    list_display = [
        'company', 'time_per_manual_item_seconds', 
        'labor_cost_per_hour_usd', 'updated_at'
    ]
    search_fields = ['company__email']
    readonly_fields = ['created_at', 'updated_at']
    
    fieldsets = (
        ('Company', {
            'fields': ('company',),
            'description': 'Leave empty for global defaults that apply to all companies.'
        }),
        ('Time Benchmarks', {
            'fields': ('time_per_manual_item_seconds',),
            'description': 'Average time in seconds to manually count one item.'
        }),
        ('Cost Benchmarks', {
            'fields': ('labor_cost_per_hour_usd',),
            'description': 'Average labor cost per hour in USD.'
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of global defaults (where company is None)."""
        if obj and obj.company is None:
            return False
        return super().has_delete_permission(request, obj)