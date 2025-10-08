# File: dashboard/serializers.py

from rest_framework import serializers
from .models import Category, InventoryItem, Scan, ScannedItem, BenchmarkSettings


class CategorySerializer(serializers.ModelSerializer):
    """Serializer for Category model."""
    
    class Meta:
        model = Category
        fields = [
            'id', 'name', 'is_default', 'color',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class ScannedItemSerializer(serializers.ModelSerializer):
    """Serializer for items detected in a scan."""
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = ScannedItem
        fields = [
            'id', 'item_name', 'category', 'category_name',
            'count', 'confidence'
        ]


class ScanCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for creating a new scan from mobile app.
    """
    items_detected = serializers.ListField(
        child=serializers.DictField(),
        write_only=True,
        help_text="List of detected items with structure: {category, item_name, count, confidence}"
    )
    
    class Meta:
        model = Scan
        fields = [
            'scan_type', 'media_url', 'timestamp',
            'total_items_count', 'processing_time_seconds',
            'items_detected'
        ]
    
    def validate_items_detected(self, value):
        """Validate items_detected structure."""
        required_fields = {'category', 'item_name', 'count', 'confidence'}
        
        for item in value:
            if not all(field in item for field in required_fields):
                raise serializers.ValidationError(
                    f"Each item must have: {', '.join(required_fields)}"
                )
            
            if not isinstance(item['count'], int) or item['count'] < 0:
                raise serializers.ValidationError("Count must be a non-negative integer")
            
            if not (0 <= float(item['confidence']) <= 100):
                raise serializers.ValidationError("Confidence must be between 0 and 100")
        
        return value


class ScanListSerializer(serializers.ModelSerializer):
    """Serializer for listing scans."""
    scanned_items = ScannedItemSerializer(many=True, read_only=True)
    performed_by_email = serializers.EmailField(source='performed_by.email', read_only=True)
    
    class Meta:
        model = Scan
        fields = [
            'id', 'scan_type', 'media_url', 'timestamp',
            'total_items_count', 'processing_time_seconds',
            'overall_confidence', 'time_saved_minutes',
            'cost_saved_usd', 'performed_by_email', 'scanned_items'
        ]


class InventoryItemSerializer(serializers.ModelSerializer):
    """Serializer for inventory items."""
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = InventoryItem
        fields = [
            'id', 'item_name', 'category', 'category_name',
            'current_count', 'unit_price', 'last_scanned',
            'image_url', 'notes', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'last_scanned', 'created_at', 'updated_at']


class DashboardOverviewSerializer(serializers.Serializer):
    """Serializer for dashboard overview metrics."""
    total_scans_today = serializers.IntegerField()
    time_saved_today = serializers.CharField()
    cost_savings_today = serializers.CharField()
    accuracy_rate_today = serializers.CharField()
    scans_change = serializers.CharField()
    time_saved_change = serializers.CharField()
    cost_savings_change = serializers.CharField()
    accuracy_change = serializers.CharField()
    comparison_period = serializers.CharField(default='vs_yesterday')


class ScanActivityDataSerializer(serializers.Serializer):
    """Serializer for scan activity chart data."""
    day = serializers.CharField()
    scans = serializers.IntegerField()
    accuracy = serializers.FloatField()


class CategoryDistributionSerializer(serializers.Serializer):
    """Serializer for category distribution pie chart."""
    name = serializers.CharField()
    value = serializers.IntegerField()
    color = serializers.CharField()


class SystemComponentStatusSerializer(serializers.Serializer):
    """Serializer for individual system component status."""
    name = serializers.CharField()
    status = serializers.CharField()
    color = serializers.CharField()
    response_time_ms = serializers.IntegerField(required=False)


class SystemStatusSerializer(serializers.Serializer):
    """Serializer for overall system status."""
    status = serializers.CharField()
    color = serializers.CharField()
    last_sync = serializers.CharField()
    ai_assistant_status = serializers.CharField()
    components = SystemComponentStatusSerializer(many=True)


class BenchmarkSettingsSerializer(serializers.ModelSerializer):
    """Serializer for benchmark settings."""
    
    class Meta:
        model = BenchmarkSettings
        fields = [
            'id', 'time_per_manual_item_seconds',
            'labor_cost_per_hour_usd', 'updated_at'
        ]
        read_only_fields = ['id', 'updated_at']