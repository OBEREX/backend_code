# File: users/management/commands/reset_daily_queries.py

from django.core.management.base import BaseCommand
from users.models import Profile


class Command(BaseCommand):
    """
    Management command to reset daily query counts.
    Should be run daily via cron job.
    """
    help = 'Reset daily query counts for all users'
    
    def handle(self, *args, **options):
        try:
            updated_count = Profile.objects.filter(queries_used_today__gt=0).update(
                queries_used_today=0
            )
            
            self.stdout.write(
                self.style.SUCCESS(f'Successfully reset daily queries for {updated_count} users')
            )
            
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error resetting daily queries: {str(e)}')
            )