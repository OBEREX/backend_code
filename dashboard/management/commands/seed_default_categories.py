# File: dashboard/management/commands/seed_default_categories.py

from django.core.management.base import BaseCommand
from dashboard.models import Category
from dashboard.utils import get_default_category_colors


class Command(BaseCommand):
    help = 'Seed default product categories'

    def handle(self, *args, **options):
        default_categories = [
            'Electronics',
            'Food & Beverage',
            'Clothing',
            'Home & Garden',
            'Automotive',
            'Healthcare & Pharmacy',
            'Construction & Hardware',
            'Technology & Electronics',
            'Fashion & Apparel',
            'Agriculture & Farming',
            'Logistics & Warehousing',
            'Education & Training',
            'Other',
        ]
        
        color_mapping = get_default_category_colors()
        created_count = 0
        
        for category_name in default_categories:
            category, created = Category.objects.get_or_create(
                name=category_name,
                is_default=True,
                company=None,
                defaults={
                    'color': color_mapping.get(category_name, '#6b7280')
                }
            )
            
            if created:
                created_count += 1
                self.stdout.write(
                    self.style.SUCCESS(f'Created default category: {category_name}')
                )
            else:
                self.stdout.write(f'Category already exists: {category_name}')
        
        self.stdout.write(
            self.style.SUCCESS(f'\nSeeding complete! Created {created_count} new categories.')
        )