from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.password_validation import validate_password
from .models import CustomUser

class CustomUserCreationForm(UserCreationForm):
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=150, required=True)
    last_name = forms.CharField(max_length=150, required=True)
    phone_number = forms.CharField(max_length=15, required=False)

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'first_name', 'last_name', 'phone_number', 'password1', 'password2']


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


class PasswordResetRequestForm(forms.Form):
    """Form to initiate password reset"""
    pass


class PasswordResetConfirmForm(forms.Form):
    """Form to confirm password reset with OTP"""
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

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError("Passwords don't match.")
            
            # Validate password strength
            try:
                validate_password(password1)
            except forms.ValidationError as e:
                raise forms.ValidationError(e)

        return cleaned_data