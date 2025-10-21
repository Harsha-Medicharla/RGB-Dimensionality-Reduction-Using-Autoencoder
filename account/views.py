import io
import os
import numpy as np
import tensorflow as tf
from PIL import Image
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.files.base import ContentFile
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .forms import (CustomUserCreationForm, CustomLoginForm, UserUpdateForm, 
                    PasswordResetRequestForm, PasswordResetConfirmForm, ImageUploadForm)
from .models import CustomUser, OTP, ImageUpload
from django.conf import settings


# Autoencoder model for image processing
class EnhancedAutoEncoder(tf.keras.Model):
    def __init__(self, **kwargs):
        super(EnhancedAutoEncoder, self).__init__(**kwargs)
        # Encoder architecture
        self.encoder = tf.keras.Sequential([
            tf.keras.layers.Input(shape=(96, 96, 3)),
            tf.keras.layers.Conv2D(64, (3, 3), activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.MaxPooling2D((2, 2), padding='same'),
            tf.keras.layers.Conv2D(32, (3, 3), activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.MaxPooling2D((2, 2), padding='same'),
            tf.keras.layers.Conv2D(16, (3, 3), activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.MaxPooling2D((2, 2), padding='same')
        ], name="encoder")
        # Decoder architecture
        self.decoder = tf.keras.Sequential([
            tf.keras.layers.Conv2DTranspose(16, (3, 3), strides=2, activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Conv2DTranspose(32, (3, 3), strides=2, activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Conv2DTranspose(64, (3, 3), strides=2, activation='relu', padding='same'),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Conv2D(3, (3, 3), activation='sigmoid', padding='same')
        ], name="decoder")

    def call(self, inputs):
        encoded = self.encoder(inputs)
        decoded = self.decoder(encoded)
        return decoded


# Load autoencoder model
MODEL_PATH = os.path.join(settings.BASE_DIR, 'enhanced_autoencoder.keras')
autoencoder_model = None

try:
    if os.path.exists(MODEL_PATH):
        autoencoder_model = tf.keras.models.load_model(
            MODEL_PATH,
            custom_objects={'EnhancedAutoEncoder': EnhancedAutoEncoder}
        )
        print(f"Model loaded successfully from {MODEL_PATH}")
    else:
        print(f"Model file not found at {MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    autoencoder_model = None


def validate_image(image_file):
    """Validate image properties (format, size, dimensions, color)."""
    try:
        if image_file.size > 1 * 1024 * 1024:
            return False, "Image size must be less than 1MB."
        if not image_file.name.lower().endswith('.png'):
            return False, "Only PNG format is supported."
        img = Image.open(image_file)
        if img.size != (96, 96):
            return False, "Image must be exactly 96x96 pixels."
        if img.mode not in ['RGB', 'RGBA']:
            return False, "Image must be in RGB or RGBA color format."
        if img.mode == 'RGBA':
            img = img.convert('RGB')
        return True, None
    except Exception as e:
        return False, f"Error validating image: {str(e)}"


@login_required
def home(request):
    """Handle image upload and trigger processing."""
    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image_file = request.FILES.get('input_image')
            is_valid, error_message = validate_image(image_file)
            if not is_valid:
                messages.error(request, f"Image validation failed: {error_message}")
                return render(request, "account/home.html", {'form': form})
            image_upload = form.save(commit=False)
            image_upload.user = request.user
            image_upload.save()
            try:
                process_image(image_upload)
                messages.success(request, 'Image uploaded and processed successfully!')
                return redirect('account:results', pk=image_upload.pk)
            except Exception as e:
                messages.error(request, f"Error processing image: {str(e)}")
                image_upload.delete()
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = ImageUploadForm()
    recent_uploads = ImageUpload.objects.filter(user=request.user)[:5]
    return render(request, "account/home.html", {'form': form, 'recent_uploads': recent_uploads})


@login_required
def results_view(request, pk):
    """Display processed image results."""
    image_upload = get_object_or_404(ImageUpload, pk=pk, user=request.user)
    return render(request, 'account/results.html', {'image_upload': image_upload})


def process_image(image_upload):
    """Process uploaded image using the trained autoencoder."""
    try:
        if autoencoder_model is None:
            raise Exception("Model not loaded.")
        img = Image.open(image_upload.input_image)
        if img.mode == 'RGBA':
            img = img.convert('RGB')
        if img.size != (96, 96):
            img = img.resize((96, 96), Image.Resampling.LANCZOS)
        img_array = np.expand_dims(np.array(img).astype('float32') / 255.0, axis=0)
        processed_array = autoencoder_model.predict(img_array, verbose=0)[0]
        processed_img = Image.fromarray(np.clip(processed_array * 255, 0, 255).astype('uint8'))
        output_io = io.BytesIO()
        processed_img.save(output_io, format='PNG')
        output_io.seek(0)
        filename = f"processed_{image_upload.id}.png"
        image_upload.output_image.save(filename, ContentFile(output_io.read()), save=False)
        image_upload.processed = True
        image_upload.save()
    except Exception as e:
        print(f"Error processing image: {e}")
        image_upload.processed = False
        image_upload.save()
        raise


@login_required
def profile(request):
    """Display and update user profile."""
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('account:profile')
        messages.error(request, 'Please correct the errors below.')
    else:
        form = UserUpdateForm(instance=request.user)
    return render(request, 'account/profile.html', {'form': form})


def login_view(request):
    """Authenticate and log in user."""
    if request.user.is_authenticated:
        return redirect('account:home')
    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            if user:
                if not user.email_verified:
                    messages.error(request, 'Verify your email before login.')
                    return redirect('account:login')
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect(request.GET.get('next', 'account:home'))
            messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = CustomLoginForm()
    return render(request, 'account/login.html', {'form': form})


def logout_view(request):
    """Log out user."""
    logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('account:login')


def register_view(request):
    """Register a new user and send OTP for verification."""
    if request.user.is_authenticated:
        return redirect('account:home')
    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.email_verified = False
            user.save()
            otp = OTP.create_otp(user.email, 'registration')
            send_otp_email(user.email, otp.otp_code, 'registration')
            request.session['pending_verification_email'] = user.email
            request.session['pending_user_id'] = user.id
            messages.success(request, 'Account created! Check email for OTP.')
            return redirect('account:verify_otp')
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')
    else:
        form = CustomUserCreationForm()
    return render(request, 'account/register.html', {'form': form})


def verify_otp_view(request):
    """Verify OTP for email confirmation."""
    if request.user.is_authenticated:
        return redirect('account:home')
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        try:
            otp = OTP.objects.get(email=email, otp_code=otp_code, otp_type='registration', is_used=False)
            if otp.is_valid():
                otp.is_used = True
                otp.save()
                user = CustomUser.objects.get(id=request.session.get('pending_user_id'))
                user.email_verified = True
                user.save()
                del request.session['pending_verification_email']
                del request.session['pending_user_id']
                login(request, user)
                messages.success(request, 'Email verified successfully!')
                return redirect('account:home')
            else:
                messages.error(request, 'OTP expired.')
        except OTP.DoesNotExist:
            messages.error(request, 'Invalid OTP.')
    return render(request, 'account/verify_otp.html', {'email': email})


def resend_otp_view(request):
    """Resend email verification OTP."""
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    otp = OTP.create_otp(email, 'registration')
    send_otp_email(email, otp.otp_code, 'registration')
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:verify_otp')


@login_required
def password_reset_request_view(request):
    """Request OTP for password reset."""
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = request.user.email
            otp = OTP.create_otp(email, 'password_reset')
            send_otp_email(email, otp.otp_code, 'password_reset')
            request.session['password_reset_email'] = email
            messages.success(request, 'OTP sent to email.')
            return redirect('account:password_reset_confirm')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'account/password_reset_request.html', {'form': form})


@login_required
def password_reset_confirm_view(request):
    """Confirm OTP and reset password."""
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            new_password = form.cleaned_data.get('new_password1')
            try:
                otp = OTP.objects.get(email=email, otp_code=otp_code, otp_type='password_reset', is_used=False)
                if otp.is_valid():
                    otp.is_used = True
                    otp.save()
                    user = request.user
                    user.set_password(new_password)
                    user.save()
                    update_session_auth_hash(request, user)
                    del request.session['password_reset_email']
                    messages.success(request, 'Password changed successfully!')
                    return redirect('account:profile')
                messages.error(request, 'OTP expired.')
            except OTP.DoesNotExist:
                messages.error(request, 'Invalid OTP.')
    else:
        form = PasswordResetConfirmForm()
    return render(request, 'account/password_reset_confirm.html', {'form': form})


@login_required
def resend_password_reset_otp_view(request):
    """Resend password reset OTP."""
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:password_reset_confirm')


def send_otp_email(email, otp_code, otp_type):
    """Send OTP email for verification or password reset."""
    if otp_type == 'registration':
        subject = 'Email Verification OTP'
        message = f'Your OTP for email verification is: {otp_code}\n\nExpires in 10 minutes.'
    else:
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is: {otp_code}\n\nExpires in 10 minutes.'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email], fail_silently=False)
