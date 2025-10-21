from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from PIL import Image
from .models import CustomUser, ImageUpload
import re


class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=150, required=True)
    last_name = forms.CharField(max_length=150, required=True)
    phone_number = forms.CharField(max_length=10, required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'phone_number', 'password1', 'password2']
    
    # Validate phone number format
    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number')
        if phone:
            if not re.fullmatch(r'\d{10}', phone):
                raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

    # Validate bio length
    def clean_bio(self):
        bio = self.cleaned_data.get('bio')
        if bio and len(bio) > 400:
            raise ValidationError("Bio cannot exceed 400 characters.")
        return bio


class CustomLoginForm(AuthenticationForm):
    username = forms.CharField()
    password = forms.CharField(widget=forms.PasswordInput)


class UserUpdateForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['email', 'first_name', 'last_name', 'phone_number', 'bio']
        widgets = {
            'bio': forms.Textarea(attrs={'rows': 4}),
        }

    # Validate phone number format
    def clean_phone_number(self):
        phone = self.cleaned_data.get('phone_number')
        if phone:
            import re
            if not re.fullmatch(r'\d{10}', phone):
                raise ValidationError("Phone number must be exactly 10 digits.")
        return phone

    # Validate bio length
    def clean_bio(self):
        bio = self.cleaned_data.get('bio')
        if bio and len(bio) > 400:
            raise ValidationError("Bio cannot exceed 400 characters.")
        return bio


class PasswordResetRequestForm(forms.Form):
    """Form to initiate password reset"""
    pass


class PasswordResetConfirmForm(forms.Form):
    otp_code = forms.CharField(
        max_length=6,
        min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter 6-digit OTP',
            'pattern': '[0-9]{6}',
        }),
        label='OTP Code'
    )
    new_password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'New Password'}),
        label='New Password'
    )
    new_password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Confirm New Password'}),
        label='Confirm New Password'
    )

    # Validate OTP and password match + strength
    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError("Passwords don't match.")
            
            try:
                validate_password(password1)
            except forms.ValidationError as e:
                raise forms.ValidationError(e)

        return cleaned_data


class ImageUploadForm(forms.ModelForm):
    class Meta:
        model = ImageUpload
        fields = ['input_image']
        widgets = {
            'input_image': forms.FileInput(attrs={
                'accept': 'image/png',
                'class': 'image-input'
            })
        }
    
    # Validate uploaded image (format, size, dimensions)
    def clean_input_image(self):
        image = self.cleaned_data.get('input_image')
        
        if not image:
            raise ValidationError("Please upload an image.")
        
        if not image.name.lower().endswith('.png'):
            raise ValidationError("Only PNG images are allowed.")
        
        if image.size > 1 * 1024 * 1024:  # 1MB
            raise ValidationError("Image file size must be less than 1MB.")
        
        try:
            img = Image.open(image)
            
            if img.format != 'PNG':
                raise ValidationError("Only PNG format is allowed.")
            
            if img.size != (96, 96):
                raise ValidationError(f"Image must be exactly 96x96 pixels. Your image is {img.size[0]}x{img.size[1]} pixels.")
            
            if img.mode not in ['RGB', 'RGBA']:
                raise ValidationError("Image must be a color image (RGB or RGBA mode).")
            
            image.seek(0)
            
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Invalid image file: {str(e)}")
        
        return image
