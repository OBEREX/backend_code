# File: dashboard/utils.py

import logging
import time
from django.conf import settings
from auth_integration.supabase_client import SupabaseClient

logger = logging.getLogger(__name__)


def check_supabase_health():
    """
    Check Supabase database connectivity and response time.
    
    Returns:
        dict: Status information with keys: status, color, response_time_ms
    """
    try:
        start_time = time.time()
        
        # Initialize Supabase client
        supabase = SupabaseClient()
        
        # Simple health check query (check if we can connect)
        response = supabase.service_client.table('profiles').select('id').limit(1).execute()
        
        response_time_ms = int((time.time() - start_time) * 1000)
        
        # Determine status based on response time
        if response_time_ms < 200:
            return {
                'status': 'operational',
                'color': 'green',
                'response_time_ms': response_time_ms
            }
        elif response_time_ms < 1000:
            return {
                'status': 'degraded',
                'color': 'yellow',
                'response_time_ms': response_time_ms
            }
        else:
            return {
                'status': 'slow',
                'color': 'yellow',
                'response_time_ms': response_time_ms
            }
            
    except Exception as e:
        logger.error(f"Supabase health check failed: {str(e)}")
        return {
            'status': 'down',
            'color': 'red',
            'response_time_ms': 0
        }


def format_time_delta(delta):
    """
    Format a timedelta into human-readable string.
    
    Args:
        delta: timedelta object
        
    Returns:
        str: Formatted string like "2 mins ago", "3 hours ago", etc.
    """
    total_seconds = int(delta.total_seconds())
    
    if total_seconds < 60:
        return "Just now"
    elif total_seconds < 3600:
        minutes = total_seconds // 60
        return f"{minutes} min{'s' if minutes != 1 else ''} ago"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    else:
        days = total_seconds // 86400
        return f"{days} day{'s' if days != 1 else ''} ago"


def calculate_scan_metrics(scan, benchmark_settings):
    """
    Calculate time saved and cost saved for a scan based on benchmark settings.
    
    Args:
        scan: Scan model instance
        benchmark_settings: BenchmarkSettings model instance
        
    Returns:
        dict: Contains 'time_saved_minutes' and 'cost_saved_usd'
    """
    from decimal import Decimal
    
    # Time calculation
    # Manual time = number of items × time per item (in seconds)
    manual_time_seconds = scan.total_items_count * benchmark_settings.time_per_manual_item_seconds
    
    # AI scan time is already recorded in processing_time_seconds
    scan_time_seconds = float(scan.processing_time_seconds)
    
    # Time saved = manual - scan (convert to minutes)
    time_saved_seconds = max(0, manual_time_seconds - scan_time_seconds)
    time_saved_minutes = Decimal(time_saved_seconds / 60)
    
    # Cost calculation
    # Cost saved = time saved (hours) × hourly labor rate
    time_saved_hours = time_saved_seconds / 3600
    cost_saved_usd = Decimal(time_saved_hours) * benchmark_settings.labor_cost_per_hour_usd
    
    return {
        'time_saved_minutes': round(time_saved_minutes, 2),
        'cost_saved_usd': round(cost_saved_usd, 2)
    }


def get_default_category_colors():
    """
    Return default color mapping for standard categories.
    
    Returns:
        dict: Category name to hex color mapping
    """
    return {
        'Electronics': '#3b82f6',          # Blue
        'Food & Beverage': '#10b981',      # Green
        'Clothing': '#f59e0b',             # Amber
        'Home & Garden': '#8b5cf6',        # Purple
        'Automotive': '#ef4444',           # Red
        'Healthcare & Pharmacy': '#06b6d4', # Cyan
        'Construction & Hardware': '#f97316', # Orange
        'Technology': '#6366f1',           # Indigo
        'Fashion & Apparel': '#ec4899',    # Pink
        'Agriculture': '#84cc16',          # Lime
        'Logistics': '#14b8a6',            # Teal
        'Education': '#a855f7',            # Purple
        'Other': '#6b7280',                # Gray
    }