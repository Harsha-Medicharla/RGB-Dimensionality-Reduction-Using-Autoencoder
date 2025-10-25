import io
import os
import cv2
import numpy as np
import tensorflow as tf
from PIL import Image
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import datetime
from django.core.files.base import ContentFile
from django.shortcuts import render, redirect, get_object_or_404
from tensorflow.keras.models import Sequential
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from .forms import (CustomUserCreationForm, CustomLoginForm, UserUpdateForm, 
                    PasswordResetRequestForm, PasswordResetConfirmForm, ImageUploadForm)
from .models import CustomUser, OTP, ImageUpload
from django.conf import settings


# ---------------------- Autoencoder ----------------------
class EnhancedAutoEncoder(tf.keras.Model):
    """
    Enhanced Autoencoder with Batch Normalization for image reconstruction.
    Input: 96x96x3 RGB images
    Output: 96x96x3 reconstructed RGB images
    """
    def __init__(self, **kwargs):
        super(EnhancedAutoEncoder, self).__init__(**kwargs)
        
        # Encoder: 96x96x3 -> 12x12x16
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
        
        # Decoder: 12x12x16 -> 96x96x3
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




# ---------------------- Load Models ----------------------
MODEL_PATH = os.path.join(settings.BASE_DIR, 'enhanced_autoencoder.keras')
PROJECTOR_PATH = os.path.join(settings.BASE_DIR, 'rgb_projector.keras')

autoencoder_model = None
encoder = None
partial_decoder = None
rgb_projector = None

try:
    if os.path.exists(MODEL_PATH):
        autoencoder_model = tf.keras.models.load_model(
            MODEL_PATH,
            custom_objects={'EnhancedAutoEncoder': EnhancedAutoEncoder}
        )
        print(f"✓ Autoencoder loaded from {MODEL_PATH}")
        
        encoder = autoencoder_model.get_layer("encoder")
        
        # Partial decoder: stops at 48x48 output
        decoder = autoencoder_model.get_layer("decoder")
        partial_decoder = Sequential(decoder.layers[:4], name="partial_decoder")
        partial_decoder.build(input_shape=(None, 12, 12, 16))
        
        if os.path.exists(PROJECTOR_PATH):
            rgb_projector = tf.keras.models.load_model(PROJECTOR_PATH)
            print(f"✓ RGB Projector loaded from {PROJECTOR_PATH}")
        else:
            print(f"✗ RGB Projector not found at {PROJECTOR_PATH}")
    else:
        print(f"✗ Autoencoder model not found at {MODEL_PATH}")
except Exception as e:
    print(f"✗ Error loading models: {e}")



def get_session_info(request):
    """Get session expiry information"""
    try:
        # Get session expiry age in seconds
        expiry_age = request.session.get_expiry_age()
        return max(0, int(expiry_age))
    except:
        # Fallback to session cookie age if expiry not set
        return settings.SESSION_COOKIE_AGE


def validate_image(image_file):
    """Validate uploaded image."""
    try:
        if image_file.size > 1 * 1024 * 1024:
            return False, "Image size must be less than 1MB."
        if not image_file.name.lower().endswith('.png'):
            return False, "Only PNG format is supported."
        img = Image.open(image_file)
        if img.size != (96, 96):
            return False, "Image must be exactly 96x96 pixels."
        if img.mode not in ['RGB', 'RGBA']:
            return False, "Image must be RGB or RGBA."
        return True, None
    except Exception as e:
        return False, f"Error validating image: {str(e)}"



@login_required
def home(request):
    """Handle image upload and trigger processing."""
    # Get session expiry time
    session_time_remaining = get_session_info(request)
    
    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image_file = request.FILES.get('input_image')
            is_valid, error_message = validate_image(image_file)
            if not is_valid:
                messages.error(request, f"Image validation failed: {error_message}")
                return render(request, "account/home.html", {
                    'form': form,
                    'session_time_remaining': session_time_remaining
                })
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
    return render(request, "account/home.html", {
        'form': form,
        'recent_uploads': recent_uploads,
        'session_time_remaining': session_time_remaining
    })


@login_required
def results_view(request, pk):
    """Display processed image results."""
    session_time_remaining = get_session_info(request)
    image_upload = get_object_or_404(ImageUpload, pk=pk, user=request.user)
    return render(request, 'account/results.html', {
        'image_upload': image_upload,
        'session_time_remaining': session_time_remaining
    })


def process_image(image_upload):
    """Process image using autoencoder and projector."""
    if encoder is None or partial_decoder is None or rgb_projector is None:
        raise Exception("Models not loaded properly.")
    
    img = Image.open(image_upload.input_image)
    if img.mode == 'RGBA':
        img = img.convert('RGB')
    if img.size != (96, 96):
        img = img.resize((96, 96), Image.Resampling.LANCZOS)
    
    # CLAHE + Gamma preprocessing
    img_cv = np.array(img)
    lab = cv2.cvtColor(img_cv, cv2.COLOR_RGB2LAB)
    l, a, b = cv2.split(lab)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
    l = clahe.apply(l)
    lab = cv2.merge((l, a, b))
    img_cv = cv2.cvtColor(lab, cv2.COLOR_LAB2RGB)
    gamma = 1.2
    img_cv = np.power(img_cv / 255.0, gamma)
    img_cv = np.clip(img_cv * 255, 0, 255).astype('uint8')
    
    img_array = np.expand_dims(img_cv.astype('float32') / 255.0, axis=0)
    
    encoded = encoder.predict(img_array, verbose=0)
    reduced_features = partial_decoder.predict(encoded, verbose=0)
    reduced_rgb = rgb_projector.predict(reduced_features, verbose=0)[0]
    
    reduced_img = Image.fromarray(np.clip(reduced_rgb * 255, 0, 255).astype('uint8'))
    output_io = io.BytesIO()
    reduced_img.save(output_io, format='PNG')
    output_io.seek(0)
    
    filename = f"reduced_{image_upload.id}.png"
    image_upload.output_image.save(filename, ContentFile(output_io.read()), save=False)
    image_upload.processed = True
    image_upload.save()


@login_required
def profile(request):
    """Display and update user profile."""
    session_time_remaining = get_session_info(request)
    
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Profile updated successfully!')
            return redirect('account:profile')
        messages.error(request, 'Please correct the errors below.')
    else:
        form = UserUpdateForm(instance=request.user)
    return render(request, 'account/profile.html', {
        'form': form,
        'session_time_remaining': session_time_remaining
    })


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
                # Force session to use our configured timeout
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                request.session.modified = True
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
    
    # Get the latest valid OTP for countdown
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='registration', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
    except OTP.DoesNotExist:
        time_remaining = 0
    
    # Check resend cooldown
    resend_cooldown = OTP.get_resend_cooldown(email, 'registration')
    
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
                # Set session expiry explicitly
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                messages.success(request, 'Email verified successfully!')
                return redirect('account:home')
            else:
                messages.error(request, 'OTP expired.')
        except OTP.DoesNotExist:
            messages.error(request, 'Invalid OTP.')
    
    return render(request, 'account/verify_otp.html', {
        'email': email,
        'time_remaining': time_remaining,
        'resend_cooldown': resend_cooldown
    })


def resend_otp_view(request):
    """Resend email verification OTP."""
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    
    # Check if user can resend
    if not OTP.can_resend(email, 'registration'):
        cooldown = OTP.get_resend_cooldown(email, 'registration')
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:verify_otp')
    
    otp = OTP.create_otp(email, 'registration')
    send_otp_email(email, otp.otp_code, 'registration')
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:verify_otp')


def forgot_password_request_view(request):
    """Request OTP for password reset (public - no login required)."""
    if request.user.is_authenticated:
        return redirect('account:home')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        try:
            user = CustomUser.objects.get(email=email)
            if not user.email_verified:
                messages.error(request, 'Email not verified. Please verify your email first.')
                return render(request, 'account/forgot_password_request.html')
            
            otp = OTP.create_otp(email, 'password_reset')
            send_otp_email(email, otp.otp_code, 'password_reset')
            request.session['forgot_password_email'] = email
            messages.success(request, 'OTP sent to your email.')
            return redirect('account:forgot_password_confirm')
        except CustomUser.DoesNotExist:
            messages.error(request, 'No account found with this email.')
    
    return render(request, 'account/forgot_password_request.html')


def forgot_password_confirm_view(request):
    """Confirm OTP and reset password (public - no login required)."""
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('forgot_password_email')
    if not email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:forgot_password_request')
    
    # Get the latest valid OTP for countdown
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='password_reset', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
    except OTP.DoesNotExist:
        time_remaining = 0
    
    # Check resend cooldown
    resend_cooldown = OTP.get_resend_cooldown(email, 'password_reset')
    
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
                    user = CustomUser.objects.get(email=email)
                    user.set_password(new_password)
                    user.save()
                    del request.session['forgot_password_email']
                    messages.success(request, 'Password reset successfully! Please login.')
                    return redirect('account:login')
                messages.error(request, 'OTP expired.')
            except OTP.DoesNotExist:
                messages.error(request, 'Invalid OTP.')
    else:
        form = PasswordResetConfirmForm()
    
    return render(request, 'account/forgot_password_confirm.html', {
        'form': form, 
        'email': email,
        'time_remaining': time_remaining,
        'resend_cooldown': resend_cooldown
    })



def resend_forgot_password_otp_view(request):
    """Resend forgot password OTP (public - no login required)."""
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('forgot_password_email')
    if not email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:forgot_password_request')
    
    # Check if user can resend
    if not OTP.can_resend(email, 'password_reset'):
        cooldown = OTP.get_resend_cooldown(email, 'password_reset')
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:forgot_password_confirm')
    
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:forgot_password_confirm')



@login_required
def password_reset_request_view(request):
    """Request OTP for password reset (logged in users)."""
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
    """Confirm OTP and reset password (logged in users)."""
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    
    # Get the latest valid OTP for countdown
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='password_reset', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
    except OTP.DoesNotExist:
        time_remaining = 0
    
    # Check resend cooldown
    resend_cooldown = OTP.get_resend_cooldown(email, 'password_reset')
    
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
    
    return render(request, 'account/password_reset_confirm.html', {
        'form': form,
        'time_remaining': time_remaining,
        'resend_cooldown': resend_cooldown
    })



@login_required
def resend_password_reset_otp_view(request):
    """Resend password reset OTP (logged in users)."""
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    
    # Check if user can resend
    if not OTP.can_resend(email, 'password_reset'):
        cooldown = OTP.get_resend_cooldown(email, 'password_reset')
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:password_reset_confirm')
    
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:password_reset_confirm')

def send_otp_email(email, otp_code, otp_type):
    """Send OTP email for verification or password reset."""
    if otp_type == 'registration':
        subject = 'Email Verification OTP'
        message = f'Your OTP for email verification is: {otp_code}\n\nExpires in 5 minutes.'
    else:
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is: {otp_code}\n\nExpires in 5 minutes.'
    send_mail(subject, message, settings.EMAIL_HOST_USER, [email], fail_silently=False)