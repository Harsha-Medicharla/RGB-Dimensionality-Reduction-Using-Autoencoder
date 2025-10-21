from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser, OTP, ImageUpload

# Custom admin configuration for CustomUser model
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ['username', 'email', 'first_name', 'last_name', 'email_verified', 'is_staff', 'created_at']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'email_verified', 'created_at']
    search_fields = ['username', 'email', 'first_name', 'last_name']
    ordering = ['-created_at']
    
    fieldsets = UserAdmin.fieldsets + (
        ('Additional Info', {
            'fields': ('phone_number', 'bio', 'email_verified')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )
    
    readonly_fields = ['created_at', 'updated_at']
    
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Additional Info', {
            'fields': ('email', 'first_name', 'last_name', 'phone_number', 'email_verified')
        }),
    )

# Register CustomUser with its custom admin configuration
admin.site.register(CustomUser, CustomUserAdmin)

# Admin view for OTP model
@admin.register(OTP)
class OTPAdmin(admin.ModelAdmin):
    list_display = ['email', 'otp_code', 'otp_type', 'is_used', 'created_at', 'expires_at']
    list_filter = ['otp_type', 'is_used', 'created_at']
    search_fields = ['email', 'otp_code']
    readonly_fields = ['created_at']
    ordering = ['-created_at']
    
    def has_add_permission(self, request):
        # Disallow manual OTP creation from admin panel.
        return False

# Admin view for ImageUpload
@admin.register(ImageUpload)
class ImageUploadAdmin(admin.ModelAdmin):
    list_display = ['user', 'uploaded_at', 'processed']
    list_filter = ['processed', 'uploaded_at']
    search_fields = ['user__username', 'user__email']
    readonly_fields = ['uploaded_at']
    ordering = ['-uploaded_at']
    
    def has_add_permission(self, request):
        # Disallow manual image uploads through admin.
        return False