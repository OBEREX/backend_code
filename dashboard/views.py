# File: dashboard/views.py

import logging
from datetime import datetime, timedelta
from decimal import Decimal
from django.utils import timezone
from django.db.models import Sum, Avg, Count, Q
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from auth_integration.permissions import IsSupabaseAuthenticated, IsEmailVerified
from .models import Scan, Category, ScannedItem, BenchmarkSettings
from .serializers import (
    DashboardOverviewSerializer,
    ScanActivityDataSerializer,
    CategoryDistributionSerializer,
    SystemStatusSerializer
)
from .utils import check_supabase_health, format_time_delta

logger = logging.getLogger(__name__)


class DashboardOverviewView(APIView):
    """
    GET /api/v1/dashboard/overview/
    Returns today's key metrics with comparison to yesterday.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        try:
            company = request.supabase_user.profile
            today = timezone.now().date()
            yesterday = today - timedelta(days=1)
            
            # Get today's scans
            today_scans = Scan.objects.filter(
                company=company,
                timestamp__date=today
            )
            
            # Get yesterday's scans for comparison
            yesterday_scans = Scan.objects.filter(
                company=company,
                timestamp__date=yesterday
            )
            
            # Calculate today's metrics
            total_scans_today = today_scans.count()
            time_saved_today = today_scans.aggregate(
                total=Sum('time_saved_minutes')
            )['total'] or Decimal('0')
            cost_saved_today = today_scans.aggregate(
                total=Sum('cost_saved_usd')
            )['total'] or Decimal('0')
            accuracy_today = today_scans.aggregate(
                avg=Avg('overall_confidence')
            )['avg'] or Decimal('0')
            
            # Calculate yesterday's metrics
            total_scans_yesterday = yesterday_scans.count()
            time_saved_yesterday = yesterday_scans.aggregate(
                total=Sum('time_saved_minutes')
            )['total'] or Decimal('0')
            cost_saved_yesterday = yesterday_scans.aggregate(
                total=Sum('cost_saved_usd')
            )['total'] or Decimal('0')
            accuracy_yesterday = yesterday_scans.aggregate(
                avg=Avg('overall_confidence')
            )['avg'] or Decimal('0')
            
            # Calculate percentage changes
            def calc_change(today_val, yesterday_val):
                if yesterday_val == 0:
                    return "+100%" if today_val > 0 else "0%"
                change = ((today_val - yesterday_val) / yesterday_val) * 100
                sign = "+" if change >= 0 else ""
                return f"{sign}{change:.1f}%"
            
            scans_change = calc_change(total_scans_today, total_scans_yesterday)
            time_saved_change = calc_change(float(time_saved_today), float(time_saved_yesterday))
            cost_savings_change = calc_change(float(cost_saved_today), float(cost_saved_yesterday))
            accuracy_change = calc_change(float(accuracy_today), float(accuracy_yesterday))
            
            # Format values
            time_saved_hours = float(time_saved_today) / 60
            
            data = {
                'total_scans_today': total_scans_today,
                'time_saved_today': f"{time_saved_hours:.1f} hrs",
                'cost_savings_today': f"${float(cost_saved_today):,.0f}",
                'accuracy_rate_today': f"{float(accuracy_today):.1f}%",
                'scans_change': scans_change,
                'time_saved_change': time_saved_change,
                'cost_savings_change': cost_savings_change,
                'accuracy_change': accuracy_change,
                'comparison_period': 'vs_yesterday'
            }
            
            serializer = DashboardOverviewSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'success': True,
                'data': serializer.validated_data
            })
            
        except Exception as e:
            logger.error(f"Error in DashboardOverviewView: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to fetch dashboard overview',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class ScanActivityView(APIView):
    """
    GET /api/v1/dashboard/scan-activity/?period=7d
    Returns scan activity chart data for specified period.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    VALID_PERIODS = {
        '7d': 7,
        '30d': 30,
        '90d': 90
    }
    
    def get(self, request):
        try:
            company = request.supabase_user.profile
            period = request.query_params.get('period', '7d')
            
            if period not in self.VALID_PERIODS:
                return Response({
                    'success': False,
                    'message': f"Invalid period. Must be one of: {', '.join(self.VALID_PERIODS.keys())}"
                }, status=status.HTTP_400_BAD_REQUEST)
            
            days = self.VALID_PERIODS[period]
            start_date = timezone.now().date() - timedelta(days=days-1)
            
            # Get scans for the period
            scans = Scan.objects.filter(
                company=company,
                timestamp__date__gte=start_date
            )
            
            # Group by day
            chart_data = []
            for i in range(days):
                date = start_date + timedelta(days=i)
                day_scans = scans.filter(timestamp__date=date)
                
                scan_count = day_scans.count()
                avg_accuracy = day_scans.aggregate(avg=Avg('overall_confidence'))['avg'] or 0
                
                # Format day label based on period
                if period == '7d':
                    day_label = date.strftime('%a')  # Mon, Tue, etc.
                else:
                    day_label = date.strftime('%m/%d')  # 10/06
                
                chart_data.append({
                    'day': day_label,
                    'scans': scan_count,
                    'accuracy': round(float(avg_accuracy), 1)
                })
            
            serializer = ScanActivityDataSerializer(data=chart_data, many=True)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'success': True,
                'period': period,
                'data': serializer.validated_data
            })
            
        except Exception as e:
            logger.error(f"Error in ScanActivityView: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to fetch scan activity data',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class CategoryDistributionView(APIView):
    """
    GET /api/v1/dashboard/category-distribution/
    Returns category distribution for pie chart.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        try:
            company = request.supabase_user.profile
            
            # Get scanned items grouped by category
            category_data = ScannedItem.objects.filter(
                scan__company=company
            ).values(
                'category__name',
                'category__color'
            ).annotate(
                total_count=Sum('count')
            ).order_by('-total_count')
            
            # Format for chart
            chart_data = []
            for item in category_data:
                if item['category__name']:  # Skip items without category
                    chart_data.append({
                        'name': item['category__name'],
                        'value': item['total_count'] or 0,
                        'color': item['category__color'] or '#3b82f6'
                    })
            
            # If no data, return empty with default categories
            if not chart_data:
                default_categories = Category.objects.filter(is_default=True)
                chart_data = [
                    {
                        'name': cat.name,
                        'value': 0,
                        'color': cat.color
                    }
                    for cat in default_categories[:5]
                ]
            
            serializer = CategoryDistributionSerializer(data=chart_data, many=True)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'success': True,
                'data': serializer.validated_data
            })
            
        except Exception as e:
            logger.error(f"Error in CategoryDistributionView: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to fetch category distribution',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class SystemStatusView(APIView):
    """
    GET /api/v1/dashboard/system-status/
    Returns system health status with component-level checks.
    """
    permission_classes = [IsSupabaseAuthenticated, IsEmailVerified]
    
    def get(self, request):
        try:
            components = []
            overall_status = 'operational'
            overall_color = 'green'
            
            # 1. Check Supabase Database
            db_status = check_supabase_health()
            components.append({
                'name': 'Database',
                'status': db_status['status'],
                'color': db_status['color'],
                'response_time_ms': db_status.get('response_time_ms', 0)
            })
            
            # 2. Check AI Chat Service (placeholder for now)
            # TODO: Implement actual AI service health check when endpoint provided
            ai_status = {
                'name': 'AI Chat',
                'status': 'operational',
                'color': 'green',
                'response_time_ms': 0
            }
            components.append(ai_status)
            
            # 3. Check Scan Processing Service (placeholder)
            # TODO: Implement actual scan service health check when endpoint provided
            scan_status = {
                'name': 'Scan Service',
                'status': 'operational',
                'color': 'green',
                'response_time_ms': 0
            }
            components.append(scan_status)
            
            # Determine overall status based on components
            colors = [c['color'] for c in components]
            if 'red' in colors:
                overall_status = 'degraded'
                overall_color = 'red'
            elif 'yellow' in colors:
                overall_status = 'partial_outage'
                overall_color = 'yellow'
            
            # Get last sync time (most recent scan)
            company = request.supabase_user.profile
            last_scan = Scan.objects.filter(company=company).first()
            
            if last_scan:
                last_sync = format_time_delta(timezone.now() - last_scan.timestamp)
            else:
                last_sync = "Never"
            
            # AI assistant status (same as AI Chat component)
            ai_assistant_status = "Online" if ai_status['status'] == 'operational' else "Offline"
            
            data = {
                'status': overall_status,
                'color': overall_color,
                'last_sync': last_sync,
                'ai_assistant_status': ai_assistant_status,
                'components': components
            }
            
            serializer = SystemStatusSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            
            return Response({
                'success': True,
                **serializer.validated_data
            })
            
        except Exception as e:
            logger.error(f"Error in SystemStatusView: {str(e)}")
            return Response({
                'success': False,
                'message': 'Failed to fetch system status',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)