from rest_framework import serializers
from django.core.validators import RegexValidator
import re


class SignUpSerializer(serializers.Serializer):
    """
    Serializer for user registration matching SignUp.tsx frontend form.
    """
    first_name = serializers.CharField(
        max_length=50,
        required=True,
        error_messages={'required': 'First name is required'}
    )
    last_name = serializers.CharField(
        max_length=50,
        required=True,
        error_messages={'required': 'Last name is required'}
    )
    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': 'Email is required',
            'invalid': 'Please enter a valid email address'
        }
    )
    phone = serializers.CharField(
        max_length=20,
        required=True,
        error_messages={'required': 'Phone number is required'}
    )
    company = serializers.CharField(
        max_length=100,
        required=True,
        error_messages={'required': 'Company name is required'}
    )
    business_type = serializers.ChoiceField(
        choices=[
            ('Retail & E-Commerce', 'Retail & E-Commerce'),
            ('Wholesale & Distribution', 'Wholesale & Distribution'),
            ('Manufacturing', 'Manufacturing'),
            ('Restaurant & Food Service', 'Restaurant & Food Service'),
            ('Healthcare & Pharmacy', 'Healthcare & Pharmacy'),
            ('Automotive', 'Automotive'),
            ('Construction & Hardware', 'Construction & Hardware'),
            ('Technology & Electronics', 'Technology & Electronics'),
            ('Fashion & Apparel', 'Fashion & Apparel'),
            ('Agriculture & Farming', 'Agriculture & Farming'),
            ('Logistics & Warehousing', 'Logistics & Warehousing'),
            ('Education & Training', 'Education & Training'),
            ('Non-Profit Organization', 'Non-Profit Organization'),
            ('Other', 'Other'),
        ],
        required=True,
        error_messages={'required': 'Business type is required'}
    )
    custom_business_type = serializers.CharField(
        max_length=100,
        required=False,
        allow_blank=True
    )
    state = serializers.CharField(
        max_length=50,
        required=True,
        error_messages={'required': 'State is required'}
    )
    city = serializers.CharField(
        max_length=50,
        required=True,
        error_messages={'required': 'City is required'}
    )
    password = serializers.CharField(
        min_length=8,
        required=True,
        error_messages={
            'required': 'Password is required',
            'min_length': 'Password must be at least 8 characters long'
        }
    )
    confirm_password = serializers.CharField(
        required=True,
        error_messages={'required': 'Please confirm your password'}
    )
    
    def validate_email(self, value):
        """Validate email format."""
        if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', value):
            raise serializers.ValidationError("Please enter a valid email address")
        return value.lower()
    
    def validate_phone(self, value):
        """Validate phone number format."""
        # Remove spaces and common separators
        phone_clean = re.sub(r'[\s\-\(\)]', '', value)
        
        # Basic phone validation (international format support)
        if not re.match(r'^\+?[\d]{7,15}$', phone_clean):
            raise serializers.ValidationError("Please enter a valid phone number")
        
        return value
    
    def validate_password(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        # Check for at least one number
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        return value
    
    def validate(self, data):
        """Cross-field validation."""
        # Check password confirmation
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match'
            })
        
        # Handle custom business type
        if data['business_type'] == 'Other' and not data.get('custom_business_type'):
            raise serializers.ValidationError({
                'custom_business_type': 'Please specify your business type'
            })
        
        # Use custom business type if "Other" is selected
        if data['business_type'] == 'Other' and data.get('custom_business_type'):
            data['business_type'] = data['custom_business_type']
        
        return data


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login matching Login.tsx frontend form.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': 'Email is required',
            'invalid': 'Please enter a valid email address'
        }
    )
    password = serializers.CharField(
        required=True,
        error_messages={'required': 'Password is required'}
    )
    remember_me = serializers.BooleanField(
        required=False,
        default=False
    )
    
    def validate_email(self, value):
        """Normalize email."""
        return value.lower()


class ForgotPasswordSerializer(serializers.Serializer):
    """
    Serializer for forgot password request matching ForgotPassword.tsx.
    """
    email = serializers.EmailField(
        required=True,
        error_messages={
            'required': 'Please enter your email address',
            'invalid': 'Please enter a valid email address'
        }
    )
    
    def validate_email(self, value):
        """Normalize email."""
        return value.lower()


class VerifyOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP verification matching VerifyOTP.tsx.
    """
    token = serializers.CharField(
        min_length=6,
        max_length=6,
        required=True,
        error_messages={
            'required': 'Please enter the verification code',
            'min_length': 'Verification code must be 6 digits',
            'max_length': 'Verification code must be 6 digits'
        }
    )
    email = serializers.EmailField(
        required=False,
        allow_blank=True
    )
    phone = serializers.CharField(
        required=False,
        allow_blank=True
    )
    type = serializers.ChoiceField(
        choices=[
            ('registration', 'Registration'),
            ('login', 'Login'),
            ('password_reset', 'Password Reset'),
            ('email_verification', 'Email Verification'),
        ],
        required=False,
        default='email_verification'
    )
    
    def validate_token(self, value):
        """Validate OTP token format."""
        # Remove any spaces or separators
        token_clean = re.sub(r'\s+', '', value)
        
        # Check if it's exactly 6 digits
        if not re.match(r'^\d{6}$', token_clean):
            raise serializers.ValidationError("Verification code must be exactly 6 digits")
        
        return token_clean
    
    def validate(self, data):
        """Ensure either email or phone is provided."""
        if not data.get('email') and not data.get('phone'):
            raise serializers.ValidationError("Either email or phone must be provided")
        
        return data


class ResetPasswordSerializer(serializers.Serializer):
    """
    Serializer for password reset matching ResetPassword.tsx.
    """
    access_token = serializers.CharField(
        required=True,
        error_messages={'required': 'Reset token is required'}
    )
    password = serializers.CharField(
        min_length=8,
        required=True,
        error_messages={
            'required': 'New password is required',
            'min_length': 'Password must be at least 8 characters long'
        }
    )
    confirm_password = serializers.CharField(
        required=True,
        error_messages={'required': 'Please confirm your new password'}
    )
    
    def validate_password(self, value):
        """Validate password strength."""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        # Check for at least one uppercase letter
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        # Check for at least one lowercase letter
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        # Check for at least one number
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        return value
    
    def validate(self, data):
        """Check password confirmation."""
        if data['password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match'
            })
        
        return data


class RefreshTokenSerializer(serializers.Serializer):
    """
    Serializer for token refresh.
    """
    refresh_token = serializers.CharField(
        required=True,
        error_messages={'required': 'Refresh token is required'}
    )


class UpdateProfileSerializer(serializers.Serializer):
    """
    Serializer for updating user profile matching Settings.tsx.
    """
    first_name = serializers.CharField(max_length=50, required=False)
    last_name = serializers.CharField(max_length=50, required=False)
    phone = serializers.CharField(max_length=20, required=False)
    company = serializers.CharField(max_length=100, required=False)
    business_type = serializers.CharField(max_length=100, required=False)
    city = serializers.CharField(max_length=50, required=False)
    state = serializers.CharField(max_length=50, required=False)
    theme = serializers.ChoiceField(
        choices=[('light', 'Light'), ('dark', 'Dark'), ('auto', 'Auto')],
        required=False
    )
    language = serializers.CharField(max_length=10, required=False)
    timezone = serializers.CharField(max_length=50, required=False)
    
    def validate_phone(self, value):
        """Validate phone number if provided."""
        if value:
            phone_clean = re.sub(r'[\s\-\(\)]', '', value)
            if not re.match(r'^\+?[\d]{7,15}$', phone_clean):
                raise serializers.ValidationError("Please enter a valid phone number")
        return value


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for changing password from settings.
    """
    current_password = serializers.CharField(
        required=True,
        error_messages={'required': 'Current password is required'}
    )
    new_password = serializers.CharField(
        min_length=8,
        required=True,
        error_messages={
            'required': 'New password is required',
            'min_length': 'Password must be at least 8 characters long'
        }
    )
    confirm_password = serializers.CharField(
        required=True,
        error_messages={'required': 'Please confirm your new password'}
    )
    
    def validate_new_password(self, value):
        """Validate new password strength."""
        if len(value) < 8:
            raise serializers.ValidationError("Password must be at least 8 characters long")
        
        if not re.search(r'[A-Z]', value):
            raise serializers.ValidationError("Password must contain at least one uppercase letter")
        
        if not re.search(r'[a-z]', value):
            raise serializers.ValidationError("Password must contain at least one lowercase letter")
        
        if not re.search(r'\d', value):
            raise serializers.ValidationError("Password must contain at least one number")
        
        return value
    
    def validate(self, data):
        """Cross-field validation."""
        if data['new_password'] != data['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': 'Passwords do not match'
            })
        
        if data['current_password'] == data['new_password']:
            raise serializers.ValidationError({
                'new_password': 'New password must be different from current password'
            })
        
        return data
    

class ResendOTPSerializer(serializers.Serializer):
    """
    Serializer for OTP resending supporting multiple verification types.
    """
    email = serializers.EmailField(
        required=False,
        allow_blank=True,
        error_messages={
            'invalid': 'Please enter a valid email address'
        }
    )
    phone = serializers.CharField(
        required=False,
        allow_blank=True,
        error_messages={
            'invalid': 'Please enter a valid phone number'
        }
    )
    type = serializers.ChoiceField(
        choices=[
            ('registration', 'Registration'),
            ('password_reset', 'Password Reset'), 
            ('email_verification', 'Email Verification'),
            ('phone_verification', 'Phone Verification'),
        ],
        required=True,
        error_messages={
            'required': 'Verification type is required',
            'invalid_choice': 'Invalid verification type'
        }
    )
    
    def validate_phone(self, value):
        """Validate phone number format."""
        if value:
            # Basic phone validation - adjust regex based on your requirements
            phone_pattern = r'^\+?[1-9]\d{1,14}$'
            if not re.match(phone_pattern, value.replace(' ', '').replace('-', '')):
                raise serializers.ValidationError("Please enter a valid phone number")
        return value
    
    def validate(self, data):
        """Ensure either email or phone is provided."""
        email = data.get('email')
        phone = data.get('phone')
        
        if not email and not phone:
            raise serializers.ValidationError(
                "Either email or phone number must be provided"
            )
        
        if email and phone:
            raise serializers.ValidationError(
                "Please provide either email or phone number, not both"
            )
        
        # Validate type-specific requirements
        verification_type = data.get('type')
        
        if verification_type == 'phone_verification' and not phone:
            raise serializers.ValidationError(
                "Phone number is required for phone verification"
            )
        
        if verification_type in ['registration', 'password_reset', 'email_verification'] and not email:
            raise serializers.ValidationError(
                f"Email is required for {verification_type.replace('_', ' ')}"
            )
        
        return data