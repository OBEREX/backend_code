# File: dashboard/models.py

from django.db import models
from django.contrib.postgres.fields import JSONField
from django.core.validators import MinValueValidator, MaxValueValidator
from users.models import Profile
import uuid


class Category(models.Model):
    """
    Product categories for inventory classification.
    Includes both default (system) and custom (user-defined) categories.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100)
    is_default = models.BooleanField(default=False)
    company = models.ForeignKey(
        Profile,
        on_delete=models.CASCADE,
        related_name='categories',
        null=True,
        blank=True,
        help_text="Null for default categories, set for custom categories"
    )
    color = models.CharField(
        max_length=7,
        default='#3b82f6',
        help_text="Hex color code for charts (e.g., #3b82f6)"
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'categories'
        ordering = ['name']
        unique_together = ['name', 'company']
        indexes = [
            models.Index(fields=['company', 'is_default']),
            models.Index(fields=['name']),
        ]

    def __str__(self):
        return f"{self.name} ({'Default' if self.is_default else 'Custom'})"


class InventoryItem(models.Model):
    """
    Inventory items tracked per company.
    Updated by scan results.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        Profile,
        on_delete=models.CASCADE,
        related_name='inventory_items'
    )
    item_name = models.CharField(max_length=255)
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        related_name='inventory_items'
    )
    current_count = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0)]
    )
    unit_price = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Optional: for cost calculations"
    )
    last_scanned = models.DateTimeField(null=True, blank=True)
    image_url = models.URLField(max_length=500, null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'inventory_items'
        ordering = ['-last_scanned', 'item_name']
        indexes = [
            models.Index(fields=['company', 'category']),
            models.Index(fields=['company', 'last_scanned']),
            models.Index(fields=['item_name']),
        ]

    def __str__(self):
        return f"{self.item_name} ({self.current_count})"


class Scan(models.Model):
    """
    Individual scan records from mobile app.
    Each scan represents a video/image processing result.
    """
    SCAN_TYPE_CHOICES = [
        ('video', 'Video'),
        ('image', 'Image'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.ForeignKey(
        Profile,
        on_delete=models.CASCADE,
        related_name='scans'
    )
    performed_by = models.ForeignKey(
        Profile,
        on_delete=models.SET_NULL,
        null=True,
        related_name='performed_scans',
        help_text="Sub-user who performed the scan"
    )
    scan_type = models.CharField(
        max_length=10,
        choices=SCAN_TYPE_CHOICES,
        default='image'
    )
    media_url = models.URLField(
        max_length=500,
        null=True,
        blank=True,
        help_text="Optional: URL to stored video/image"
    )
    total_items_count = models.IntegerField(
        validators=[MinValueValidator(0)]
    )
    processing_time_seconds = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        validators=[MinValueValidator(0)]
    )
    overall_confidence = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)],
        help_text="Average confidence score (0-100)"
    )
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # Calculated fields (filled by backend)
    time_saved_minutes = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Calculated time savings vs manual counting"
    )
    cost_saved_usd = models.DecimalField(
        max_digits=10,
        decimal_places=2,
        null=True,
        blank=True,
        help_text="Calculated cost savings in USD"
    )

    class Meta:
        db_table = 'scans'
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['company', 'timestamp']),
            models.Index(fields=['company', 'performed_by', 'timestamp']),
            models.Index(fields=['timestamp']),
        ]

    def __str__(self):
        return f"Scan {self.id} - {self.total_items_count} items"


class ScannedItem(models.Model):
    """
    Individual items detected within a scan.
    Links scans to inventory items.
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan = models.ForeignKey(
        Scan,
        on_delete=models.CASCADE,
        related_name='scanned_items'
    )
    inventory_item = models.ForeignKey(
        InventoryItem,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='scan_detections',
        help_text="Linked inventory item (if matched)"
    )
    category = models.ForeignKey(
        Category,
        on_delete=models.SET_NULL,
        null=True,
        related_name='scanned_items'
    )
    item_name = models.CharField(max_length=255)
    count = models.IntegerField(validators=[MinValueValidator(0)])
    confidence = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )

    class Meta:
        db_table = 'scanned_items'
        ordering = ['-confidence']
        indexes = [
            models.Index(fields=['scan', 'category']),
            models.Index(fields=['inventory_item']),
        ]

    def __str__(self):
        return f"{self.item_name} x{self.count} ({self.confidence}%)"


class BenchmarkSettings(models.Model):
    """
    Configurable benchmark settings for calculating time/cost savings.
    One record per company (or global defaults if company is null).
    """
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    company = models.OneToOneField(
        Profile,
        on_delete=models.CASCADE,
        related_name='benchmark_settings',
        null=True,
        blank=True,
        help_text="Null for global defaults"
    )
    
    # Time benchmarks (in seconds)
    time_per_manual_item_seconds = models.DecimalField(
        max_digits=6,
        decimal_places=2,
        default=5.0,
        help_text="Average time to manually count one item (seconds)"
    )
    
    # Cost benchmarks
    labor_cost_per_hour_usd = models.DecimalField(
        max_digits=8,
        decimal_places=2,
        default=25.0,
        help_text="Average labor cost per hour (USD)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'benchmark_settings'
        verbose_name = 'Benchmark Settings'
        verbose_name_plural = 'Benchmark Settings'

    def __str__(self):
        if self.company:
            return f"Benchmarks for {self.company.email}"
        return "Global Benchmark Defaults"

    @classmethod
    def get_for_company(cls, company):
        """
        Get benchmark settings for a company, falling back to global defaults.
        """
        try:
            return cls.objects.get(company=company)
        except cls.DoesNotExist:
            # Return global defaults
            defaults, _ = cls.objects.get_or_create(company=None)
            return defaults