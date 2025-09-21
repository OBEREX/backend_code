# File: auth_integration/management/commands/cleanup_tokens.py

from django.core.management.base import BaseCommand
from auth_integration.supabase_client import SupabaseClient


class Command(BaseCommand):
    """
    Management command to cleanup expired tokens.
    Can be run as a scheduled task.
    """
    help = 'Cleanup expired OTP and password reset tokens'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
    
    def handle(self, *args, **options):
        supabase_client = SupabaseClient()
        
        if options['dry_run']:
            self.stdout.write(
                self.style.WARNING('DRY RUN: No tokens will actually be deleted')
            )
        
        try:
            deleted_count = supabase_client.cleanup_expired_tokens()
            
            if options['dry_run']:
                self.stdout.write(
                    self.style.SUCCESS(f'Would delete {deleted_count} expired tokens')
                )
            else:
                self.stdout.write(
                    self.style.SUCCESS(f'Successfully deleted {deleted_count} expired tokens')
                )
                
        except Exception as e:
            self.stdout.write(
                self.style.ERROR(f'Error cleaning up tokens: {str(e)}')
            )