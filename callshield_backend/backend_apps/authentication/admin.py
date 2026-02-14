

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import UserChangeForm, UserCreationForm
from .models import User, AuthAttempt


class CustomUserCreationForm(UserCreationForm):
    class Meta:
        model = User
        fields = ('phone_number',)


class CustomUserChangeForm(UserChangeForm):
    class Meta:
        model = User
        fields = '__all__'


class UserAdmin(BaseUserAdmin):
    form = CustomUserChangeForm
    add_form = CustomUserCreationForm
    
    list_display = ('phone_number', 'display_name', 'user_type', 'is_staff', 'phone_verified', 'created_at')
    list_filter = ('user_type', 'is_staff', 'is_superuser', 'phone_verified', 'is_active')
    
    fieldsets = (
        (None, {'fields': ('phone_number', 'password')}),
        ('Personal Info', {'fields': ('display_name', 'language_preference')}),
        ('Permissions', {'fields': ('user_type', 'is_active', 'is_staff', 'is_superuser')}),
        ('Dates', {'fields': ('created_at', 'last_login_at')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone_number', 'password1', 'password2'),
        }),
    )
    
    readonly_fields = ('created_at', 'last_login_at', 'phone_number_hash')
    search_fields = ('phone_number', 'display_name')
    ordering = ('-created_at',)


class AuthAttemptAdmin(admin.ModelAdmin):
    list_display = ('phone_number', 'otp_code', 'otp_sent_at', 'verified', 'attempts')
    list_filter = ('verified',)
    search_fields = ('phone_number',)
    readonly_fields = ('otp_sent_at', 'otp_expires_at')


admin.site.register(User, UserAdmin)
admin.site.register(AuthAttempt, AuthAttemptAdmin)