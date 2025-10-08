# File: dashboard/tests.py

import pytest
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
from rest_framework.test import APIClient
from users.models import Profile
from dashboard.models import Category, Scan, ScannedItem, BenchmarkSettings
from dashboard.utils import calculate_scan_metrics, format_time_delta


@pytest.fixture
def api_client():
    """Create an API client for testing."""
    return APIClient()


@pytest.fixture
def test_user(db):
    """Create a test user profile."""
    profile = Profile.objects.create(
        id='550e8400-e29b-41d4-a716-446655440000',
        email='test@example.com',
        first_name='Test',
        last_name='User',
        company='Test Company',
        is_verified=True
    )
    return profile


@pytest.fixture
def test_category(db, test_user):
    """Create a test category."""
    return Category.objects.create(
        name='Electronics',
        is_default=True,
        color='#3b82f6'
    )


@pytest.fixture
def test_benchmark(db, test_user):
    """Create test benchmark settings."""
    return BenchmarkSettings.objects.create(
        company=test_user,
        time_per_manual_item_seconds=Decimal('5.0'),
        labor_cost_per_hour_usd=Decimal('25.0')
    )


@pytest.mark.django_db
class TestDashboardModels:
    """Test dashboard models."""
    
    def test_category_creation(self, test_category):
        """Test category model creation."""
        assert test_category.name == 'Electronics'
        assert test_category.is_default is True
        assert test_category.color == '#3b82f6'
    
    def test_scan_creation(self, test_user, test_category):
        """Test scan model creation."""
        scan = Scan.objects.create(
            company=test_user,
            performed_by=test_user,
            scan_type='image',
            total_items_count=10,
            processing_time_seconds=Decimal('3.5'),
            overall_confidence=Decimal('95.5')
        )
        
        assert scan.company == test_user
        assert scan.total_items_count == 10
        assert scan.overall_confidence == Decimal('95.5')
    
    def test_scanned_item_creation(self, test_user, test_category):
        """Test scanned item creation."""
        scan = Scan.objects.create(
            company=test_user,
            total_items_count=5,
            processing_time_seconds=Decimal('2.0'),
            overall_confidence=Decimal('90.0')
        )
        
        scanned_item = ScannedItem.objects.create(
            scan=scan,
            category=test_category,
            item_name='Laptop',
            count=5,
            confidence=Decimal('92.5')
        )
        
        assert scanned_item.item_name == 'Laptop'
        assert scanned_item.count == 5
        assert scanned_item.scan == scan


@pytest.mark.django_db
class TestDashboardUtils:
    """Test utility functions."""
    
    def test_calculate_scan_metrics(self, test_user, test_benchmark):
        """Test scan metrics calculation."""
        scan = Scan.objects.create(
            company=test_user,
            total_items_count=100,
            processing_time_seconds=Decimal('10.0'),
            overall_confidence=Decimal('95.0')
        )
        
        metrics = calculate_scan_metrics(scan, test_benchmark)
        
        # Manual time = 100 items × 5 seconds = 500 seconds
        # Scan time = 10 seconds
        # Time saved = 490 seconds = 8.17 minutes
        assert metrics['time_saved_minutes'] > Decimal('8.0')
        assert metrics['cost_saved_usd'] > Decimal('0')
    
    def test_format_time_delta(self):
        """Test time delta formatting."""
        # Test "Just now"
        delta = timedelta(seconds=30)
        assert format_time_delta(delta) == "Just now"
        
        # Test minutes
        delta = timedelta(minutes=5)
        assert "5 mins ago" in format_time_delta(delta)
        
        # Test hours
        delta = timedelta(hours=2)
        assert "2 hours ago" in format_time_delta(delta)
        
        # Test days
        delta = timedelta(days=3)
        assert "3 days ago" in format_time_delta(delta)


@pytest.mark.django_db
class TestDashboardAPIEndpoints:
    """Test dashboard API endpoints."""
    
    def test_dashboard_overview_unauthorized(self, api_client):
        """Test dashboard overview without authentication."""
        response = api_client.get('/api/v1/dashboard/overview/')
        assert response.status_code == 401
    
    def test_scan_activity_invalid_period(self, api_client, test_user):
        """Test scan activity with invalid period parameter."""
        # Mock authentication (you'll need to implement proper JWT mocking)
        api_client.force_authenticate(user=test_user)
        
        response = api_client.get('/api/v1/dashboard/scan-activity/?period=invalid')
        assert response.status_code == 400
        assert 'Invalid period' in response.data.get('message', '')
    
    def test_category_distribution_empty_data(self, api_client, test_user):
        """Test category distribution with no scan data."""
        api_client.force_authenticate(user=test_user)
        
        response = api_client.get('/api/v1/dashboard/category-distribution/')
        assert response.status_code == 200
        assert 'data' in response.data
        # Should return empty or default categories
    
    def test_system_status(self, api_client, test_user):
        """Test system status endpoint."""
        api_client.force_authenticate(user=test_user)
        
        response = api_client.get('/api/v1/dashboard/system-status/')
        assert response.status_code == 200
        assert 'status' in response.data
        assert 'color' in response.data
        assert 'components' in response.data


# Run tests with: pytest dashboard/tests.py -v