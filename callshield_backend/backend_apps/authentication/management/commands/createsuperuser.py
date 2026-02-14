

from django.core.management.base import BaseCommand
from django.core.exceptions import ValidationError
from django.conf import settings
from backend_apps.authentication.models import User
from decouple import config
import phonenumbers


class Command(BaseCommand):
    help = 'Create a superuser with phone number (no password in code!)'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--phone',
            type=str,
            help='Phone number for superuser',
        )
        parser.add_argument(
            '--noinput',
            action='store_true',
            help='Non-interactive mode',
        )
    
    def handle(self, *args, **options):
        phone_number = options.get('phone')
        
        # Interactive mode - ask for phone
        if not phone_number and not options['noinput']:
            phone_number = input('Phone number (e.g., +254712000000): ')
        
        # Validate phone number
        if not phone_number:
            self.stdout.write(self.style.ERROR('Phone number is required'))
            return
        
        try:
            # Validate Kenyan phone number
            parsed = phonenumbers.parse(phone_number, 'KE')
            if not phonenumbers.is_valid_number(parsed):
                raise ValidationError('Invalid phone number')
        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Invalid phone number: {e}'))
            return
        
        # Check if user exists
        if User.objects.filter(phone_number=phone_number).exists():
            self.stdout.write(self.style.WARNING(
                f'User with phone {phone_number} already exists!'
            ))
            
            # Ask if should update
            if not options['noinput']:
                update = input('Update existing user to superuser? (yes/no): ')
                if update.lower() != 'yes':
                    return
                
                user = User.objects.get(phone_number=phone_number)
            else:
                return
        else:
            # Create new user
            user = User.objects.create_user(
                phone_number=phone_number,
                display_name='Admin User'
            )
        
        # Update user to superuser
        user.is_staff = True
        user.is_superuser = True
        user.phone_verified = True
        
        # GET PASSWORD FROM .env OR PROMPT
        # Priority: 1. .env file, 2. User input, 3. Error
        admin_password = config('ADMIN_PASSWORD', default=None)
        
        if not admin_password and not options['noinput']:
            # Interactive: ask for password
            self.stdout.write(self.style.WARNING(
                '\n⚠️  ADMIN_PASSWORD not found file'
            ))
            admin_password = input('Enter admin password (for admin panel): ')
            
            if not admin_password:
                self.stdout.write(self.style.ERROR('Password cannot be empty'))
                return
        
        elif not admin_password and options['noinput']:
            # Non-interactive but no .env password
            self.stdout.write(self.style.ERROR(
                'ADMIN_PASSWORD not set in .env file and --noinput specified'
            ))
            return
        
        # Set password
        user.set_password(admin_password)
        user.save()
        
        # Success message
        self.stdout.write(self.style.SUCCESS(
            f'\n✅ Superuser created/updated successfully!\n'
            f'\nLogin credentials:\n'
            f'  Phone: {phone_number}\n'
            f'  Password: {"(from .env)" if config("ADMIN_PASSWORD", default=None) else "(as entered)"}\n'
            f'\nAdmin panel: http://127.0.0.1:8000/admin/\n'
        ))