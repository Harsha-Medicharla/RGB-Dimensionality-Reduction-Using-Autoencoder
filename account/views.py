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
import logging
import time
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET

# Configure logging
logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[logging.StreamHandler()]
)

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


# ---------------------- Load Models with Lazy Loading ----------------------
MODEL_PATH = os.path.join(settings.BASE_DIR, 'enhanced_autoencoder.keras')
PROJECTOR_PATH = os.path.join(settings.BASE_DIR, 'rgb_projector.keras')

autoencoder_model = None
encoder = None
partial_decoder = None
rgb_projector = None
models_loaded = False
model_load_error = None


def load_models():
    """Lazy load models on first request"""
    global autoencoder_model, encoder, partial_decoder, rgb_projector, models_loaded, model_load_error
    
    if models_loaded:
        return True
    
    try:
        logger.info("=" * 60)
        logger.info("STARTING MODEL LOADING PROCESS")
        logger.info("=" * 60)
        start_time = time.time()
        
        # Check if model files exist
        logger.info(f"Checking for autoencoder model at: {MODEL_PATH}")
        logger.info(f"Model file exists: {os.path.exists(MODEL_PATH)}")
        
        if not os.path.exists(MODEL_PATH):
            model_load_error = f"Autoencoder model not found at {MODEL_PATH}"
            logger.error(model_load_error)
            return False
        
        logger.info(f"Model file size: {os.path.getsize(MODEL_PATH) / (1024*1024):.2f} MB")
        
        # Load autoencoder
        logger.info("Loading autoencoder model...")
        load_start = time.time()
        autoencoder_model = tf.keras.models.load_model(
            MODEL_PATH,
            custom_objects={'EnhancedAutoEncoder': EnhancedAutoEncoder}
        )
        logger.info(f"✓ Autoencoder loaded in {time.time() - load_start:.2f}s")
        
        # Extract encoder
        logger.info("Extracting encoder...")
        encoder = autoencoder_model.get_layer("encoder")
        logger.info("✓ Encoder extracted")
        
        # Build partial decoder
        logger.info("Building partial decoder...")
        decoder = autoencoder_model.get_layer("decoder")
        partial_decoder = Sequential(decoder.layers[:4], name="partial_decoder")
        partial_decoder.build(input_shape=(None, 12, 12, 16))
        logger.info("✓ Partial decoder built")
        
        # Load RGB projector
        logger.info(f"Checking for RGB projector at: {PROJECTOR_PATH}")
        logger.info(f"Projector file exists: {os.path.exists(PROJECTOR_PATH)}")
        
        if os.path.exists(PROJECTOR_PATH):
            logger.info(f"Projector file size: {os.path.getsize(PROJECTOR_PATH) / (1024*1024):.2f} MB")
            logger.info("Loading RGB projector...")
            load_start = time.time()
            rgb_projector = tf.keras.models.load_model(PROJECTOR_PATH)
            logger.info(f"✓ RGB Projector loaded in {time.time() - load_start:.2f}s")
        else:
            model_load_error = f"RGB Projector not found at {PROJECTOR_PATH}"
            logger.error(model_load_error)
            return False
        
        models_loaded = True
        total_time = time.time() - start_time
        logger.info("=" * 60)
        logger.info(f"ALL MODELS LOADED SUCCESSFULLY in {total_time:.2f}s")
        logger.info("=" * 60)
        return True
        
    except Exception as e:
        model_load_error = f"Error loading models: {str(e)}"
        logger.error("=" * 60)
        logger.error(f"MODEL LOADING FAILED: {model_load_error}")
        logger.error("=" * 60)
        logger.exception("Full traceback:")
        return False


def get_session_info(request):
    """Get session expiry information"""
    try:
        expiry_age = request.session.get_expiry_age()
        return max(0, int(expiry_age))
    except:
        return settings.SESSION_COOKIE_AGE


def validate_image(image_file):
    """Validate uploaded image."""
    logger.info(f"Validating image: {image_file.name}")
    try:
        if image_file.size > 1 * 1024 * 1024:
            logger.warning(f"Image too large: {image_file.size / (1024*1024):.2f} MB")
            return False, "Image size must be less than 1MB."
        
        if not image_file.name.lower().endswith('.png'):
            logger.warning(f"Invalid format: {image_file.name}")
            return False, "Only PNG format is supported."
        
        img = Image.open(image_file)
        logger.info(f"Image opened - Size: {img.size}, Mode: {img.mode}")
        
        if img.size != (96, 96):
            logger.warning(f"Invalid dimensions: {img.size}")
            return False, "Image must be exactly 96x96 pixels."
        
        if img.mode not in ['RGB', 'RGBA']:
            logger.warning(f"Invalid mode: {img.mode}")
            return False, "Image must be RGB or RGBA."
        
        image_file.seek(0)
        
        logger.info("✓ Image validation passed")
        return True, None
    except Exception as e:
        logger.error(f"Image validation error: {str(e)}")
        return False, f"Error validating image: {str(e)}"

@login_required
def home(request):
    """Handle image upload and trigger processing."""
    logger.info(f"HOME view called by user: {request.user.username}")
    session_time_remaining = get_session_info(request)
    
    if request.method == 'POST':
        logger.info("POST request received - Image upload")
        form = ImageUploadForm(request.POST, request.FILES)
        
        if form.is_valid():
            logger.info("Form is valid")
            image_file = request.FILES.get('input_image')
            
            is_valid, error_message = validate_image(image_file)
            if not is_valid:
                logger.error(f"Image validation failed: {error_message}")
                messages.error(request, f"Image validation failed: {error_message}")
                return render(request, "account/home.html", {
                    'form': form,
                    'session_time_remaining': session_time_remaining
                })
            
            # CRITICAL FIX: Reset file pointer after validation
            image_file.seek(0)
            
            # Save image upload
            logger.info("Saving image upload to database...")
            image_upload = form.save(commit=False)
            image_upload.user = request.user
            image_upload.save()
            logger.info(f"✓ Image upload saved with ID: {image_upload.pk}")
            
            # Process image
            try:
                logger.info("Starting image processing...")
                process_start = time.time()
                process_image(image_upload)
                process_time = time.time() - process_start
                logger.info(f"✓ Image processed successfully in {process_time:.2f}s")
                messages.success(request, 'Image uploaded and processed successfully!')
                return redirect('account:results', pk=image_upload.pk)
            except Exception as e:
                logger.error(f"Image processing failed: {str(e)}")
                logger.exception("Full traceback:")
                messages.error(request, f"Error processing image: {str(e)}")
                image_upload.delete()
        else:
            logger.error(f"Form validation errors: {form.errors}")
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        logger.info("GET request - Displaying upload form")
        form = ImageUploadForm()
    
    recent_uploads = ImageUpload.objects.filter(user=request.user)[:5]
    logger.info(f"Rendering home template with {recent_uploads.count()} recent uploads")
    
    return render(request, "account/home.html", {
        'form': form,
        'recent_uploads': recent_uploads,
        'session_time_remaining': session_time_remaining
    })


@login_required
def results_view(request, pk):
    """Display processed image results with metrics and visualization."""
    logger.info(f"RESULTS view called for upload ID: {pk}")
    
    # Get session info and image upload
    session_time_remaining = get_session_info(request)
    image_upload = get_object_or_404(ImageUpload, pk=pk, user=request.user)
    logger.info(f"Image upload found - Processed: {image_upload.processed}")
    
    # Initialize metrics as None
    metrics = None
    
    # Only compute metrics if processing is complete
    if image_upload.processed and image_upload.output_image:
        try:
            # Load input and output images
            input_img = Image.open(image_upload.input_image).convert('RGB')
            output_img = Image.open(image_upload.output_image).convert('RGB')

            # Resize input to match output size for comparison (48x48)
            input_resized = input_img.resize((48, 48), Image.Resampling.LANCZOS)

            # Convert images to numpy arrays
            orig_array = np.array(input_resized).astype('float32')
            final_array = np.array(output_img).astype('float32')

            # Compute metrics
            mse_val = mean_squared_error(orig_array, final_array)
            psnr_val = peak_signal_noise_ratio(orig_array, final_array, data_range=255)
            ssim_val = structural_similarity(orig_array, final_array, channel_axis=2, data_range=255)

            # Compute pixel difference histogram (absolute difference)
            diff_array = np.abs(orig_array - final_array).astype('uint8')
            diff_hist = np.histogram(diff_array.flatten(), bins=256, range=(0, 255))[0].tolist()

            # Compute input and output histograms
            input_hist = np.histogram(orig_array.flatten(), bins=256, range=(0, 255))[0].tolist()
            output_hist = np.histogram(final_array.flatten(), bins=256, range=(0, 255))[0].tolist()

            metrics = {
                'MSE': round(mse_val, 4),
                'PSNR': round(psnr_val, 4),
                'SSIM': round(ssim_val, 4),
                'pixel_diff_histogram': diff_hist,
                'input_hist': input_hist,
                'output_hist': output_hist
            }
            logger.info(f"Metrics computed successfully: MSE={mse_val}, PSNR={psnr_val}, SSIM={ssim_val}")
            
        except Exception as e:
            logger.error(f"Error computing metrics: {str(e)}")
            # metrics remains None, template will handle gracefully

    return render(request, 'account/results.html', {
        'image_upload': image_upload,
        'session_time_remaining': session_time_remaining,
        'metrics': metrics
    })

def process_image(image_upload):
    """Process image using autoencoder and projector."""
    logger.info("=" * 60)
    logger.info(f"PROCESSING IMAGE ID: {image_upload.pk}")
    logger.info("=" * 60)
    
    # Lazy load models
    if not load_models():
        error_msg = model_load_error or "Models failed to load"
        logger.error(f"Cannot process image: {error_msg}")
        raise Exception(error_msg)
    
    try:
        # Load and preprocess image
        logger.info("Loading input image...")
        load_start = time.time()
        img = Image.open(image_upload.input_image)
        logger.info(f"Image loaded in {time.time() - load_start:.3f}s - Size: {img.size}, Mode: {img.mode}")
        
        if img.mode == 'RGBA':
            logger.info("Converting RGBA to RGB...")
            img = img.convert('RGB')
        
        if img.size != (96, 96):
            logger.info(f"Resizing from {img.size} to 96x96...")
            img = img.resize((96, 96), Image.Resampling.LANCZOS)
        
        # CLAHE + Gamma preprocessing
        logger.info("Applying CLAHE preprocessing...")
        preprocess_start = time.time()
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
        logger.info(f"Preprocessing completed in {time.time() - preprocess_start:.3f}s")
        
        img_array = np.expand_dims(img_cv.astype('float32') / 255.0, axis=0)
        logger.info(f"Input array shape: {img_array.shape}")
        
        # Encode
        logger.info("Running encoder...")
        encode_start = time.time()
        encoded = encoder.predict(img_array, verbose=0)
        logger.info(f"Encoding completed in {time.time() - encode_start:.3f}s - Shape: {encoded.shape}")
        
        # Partial decode
        logger.info("Running partial decoder...")
        decode_start = time.time()
        reduced_features = partial_decoder.predict(encoded, verbose=0)
        logger.info(f"Partial decoding completed in {time.time() - decode_start:.3f}s - Shape: {reduced_features.shape}")
        
        # Project to RGB
        logger.info("Running RGB projector...")
        project_start = time.time()
        reduced_rgb = rgb_projector.predict(reduced_features, verbose=0)[0]
        logger.info(f"RGB projection completed in {time.time() - project_start:.3f}s - Shape: {reduced_rgb.shape}")
        
        # Save output
        logger.info("Saving output image...")
        save_start = time.time()
        reduced_img = Image.fromarray(np.clip(reduced_rgb * 255, 0, 255).astype('uint8'))
        output_io = io.BytesIO()
        reduced_img.save(output_io, format='PNG')
        output_io.seek(0)
        
        filename = f"reduced_{image_upload.id}.png"
        image_upload.output_image.save(filename, ContentFile(output_io.read()), save=False)
        image_upload.processed = True
        image_upload.save()
        logger.info(f"Output saved in {time.time() - save_start:.3f}s")
        
        logger.info("=" * 60)
        logger.info(f"IMAGE PROCESSING COMPLETED SUCCESSFULLY")
        logger.info("=" * 60)
        
    except Exception as e:
        logger.error("=" * 60)
        logger.error(f"IMAGE PROCESSING FAILED: {str(e)}")
        logger.error("=" * 60)
        logger.exception("Full traceback:")
        raise


@login_required
def profile(request):
    """Display and update user profile."""
    logger.info(f"PROFILE view called by user: {request.user.username}")
    session_time_remaining = get_session_info(request)
    
    if request.method == 'POST':
        logger.info("POST request - Updating profile")
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            logger.info("✓ Profile updated successfully")
            messages.success(request, 'Profile updated successfully!')
            return redirect('account:profile')
        logger.error(f"Form validation errors: {form.errors}")
        messages.error(request, 'Please correct the errors below.')
    else:
        form = UserUpdateForm(instance=request.user)
    
    return render(request, 'account/profile.html', {
        'form': form,
        'session_time_remaining': session_time_remaining
    })


def login_view(request):
    """Authenticate and log in user."""
    logger.info("LOGIN view called")
    if request.user.is_authenticated:
        logger.info(f"User {request.user.username} already authenticated, redirecting")
        return redirect('account:home')
    
    if request.method == 'POST':
        logger.info("POST request - Login attempt")
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            logger.info(f"Authenticating user: {username}")
            user = authenticate(request, username=username, password=password)
            if user:
                if not user.email_verified:
                    logger.warning(f"User {username} email not verified")
                    messages.error(request, 'Verify your email before login.')
                    return redirect('account:login')
                login(request, user)
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                request.session.modified = True
                logger.info(f"✓ User {username} logged in successfully")
                messages.success(request, f'Welcome back, {username}!')
                return redirect(request.GET.get('next', 'account:home'))
            logger.error(f"Authentication failed for user: {username}")
            messages.error(request, 'Invalid username or password.')
        else:
            logger.error(f"Form validation errors: {form.errors}")
            messages.error(request, 'Invalid username or password.')
    else:
        form = CustomLoginForm()
    
    return render(request, 'account/login.html', {'form': form})


def logout_view(request):
    """Log out user."""
    username = request.user.username if request.user.is_authenticated else "Anonymous"
    logger.info(f"LOGOUT view called by user: {username}")
    logout(request)
    messages.success(request, 'Logged out successfully.')
    return redirect('account:login')


def register_view(request):
    """Register a new user and send OTP for verification."""
    logger.info("REGISTER view called")
    if request.user.is_authenticated:
        logger.info(f"User {request.user.username} already authenticated, redirecting")
        return redirect('account:home')
    
    if request.method == 'POST':
        logger.info("POST request - Registration attempt")
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save(commit=False)
            user.is_active = True
            user.email_verified = False
            user.save()
            logger.info(f"✓ User {user.username} created successfully")
            
            logger.info(f"Creating OTP for {user.email}")
            otp = OTP.create_otp(user.email, 'registration')
            send_otp_email(user.email, otp.otp_code, 'registration')
            logger.info(f"✓ OTP sent to {user.email}")
            
            request.session['pending_verification_email'] = user.email
            request.session['pending_user_id'] = user.id
            messages.success(request, 'Account created! Check email for OTP.')
            return redirect('account:verify_otp')
        
        logger.error(f"Form validation errors: {form.errors}")
        for field, errors in form.errors.items():
            for error in errors:
                messages.error(request, f'{field}: {error}')
    else:
        form = CustomUserCreationForm()
    
    return render(request, 'account/register.html', {'form': form})


def verify_otp_view(request):
    """Verify OTP for email confirmation."""
    logger.info("VERIFY_OTP view called")
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('pending_verification_email')
    if not email:
        logger.warning("No pending verification email in session")
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='registration', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
        logger.info(f"Latest OTP for {email} - Time remaining: {time_remaining}s")
    except OTP.DoesNotExist:
        time_remaining = 0
        logger.warning(f"No valid OTP found for {email}")
    
    resend_cooldown = OTP.get_resend_cooldown(email, 'registration')
    
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        logger.info(f"OTP verification attempt for {email}")
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
                request.session.set_expiry(settings.SESSION_COOKIE_AGE)
                logger.info(f"✓ Email verified successfully for {email}")
                messages.success(request, 'Email verified successfully!')
                return redirect('account:home')
            else:
                logger.warning(f"OTP expired for {email}")
                messages.error(request, 'OTP expired.')
        except OTP.DoesNotExist:
            logger.error(f"Invalid OTP provided for {email}")
            messages.error(request, 'Invalid OTP.')
    
    return render(request, 'account/verify_otp.html', {
        'email': email,
        'time_remaining': time_remaining,
        'resend_cooldown': resend_cooldown
    })


def resend_otp_view(request):
    """Resend email verification OTP."""
    logger.info("RESEND_OTP view called")
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    
    if not OTP.can_resend(email, 'registration'):
        cooldown = OTP.get_resend_cooldown(email, 'registration')
        logger.warning(f"Too many resend attempts for {email} - Cooldown: {cooldown}s")
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:verify_otp')
    
    logger.info(f"Resending OTP to {email}")
    otp = OTP.create_otp(email, 'registration')
    send_otp_email(email, otp.otp_code, 'registration')
    logger.info(f"✓ OTP resent to {email}")
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:verify_otp')


def forgot_password_request_view(request):
    """Request OTP for password reset (public - no login required)."""
    logger.info("FORGOT_PASSWORD_REQUEST view called")
    if request.user.is_authenticated:
        return redirect('account:home')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        logger.info(f"Password reset requested for {email}")
        try:
            user = CustomUser.objects.get(email=email)
            if not user.email_verified:
                logger.warning(f"Email not verified for {email}")
                messages.error(request, 'Email not verified. Please verify your email first.')
                return render(request, 'account/forgot_password_request.html')
            
            otp = OTP.create_otp(email, 'password_reset')
            send_otp_email(email, otp.otp_code, 'password_reset')
            request.session['forgot_password_email'] = email
            logger.info(f"✓ Password reset OTP sent to {email}")
            messages.success(request, 'OTP sent to your email.')
            return redirect('account:forgot_password_confirm')
        except CustomUser.DoesNotExist:
            logger.error(f"No account found with email: {email}")
            messages.error(request, 'No account found with this email.')
    
    return render(request, 'account/forgot_password_request.html')


def forgot_password_confirm_view(request):
    """Confirm OTP and reset password (public - no login required)."""
    logger.info("FORGOT_PASSWORD_CONFIRM view called")
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('forgot_password_email')
    if not email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:forgot_password_request')
    
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='password_reset', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
    except OTP.DoesNotExist:
        time_remaining = 0
    
    resend_cooldown = OTP.get_resend_cooldown(email, 'password_reset')
    
    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            new_password = form.cleaned_data.get('new_password1')
            logger.info(f"Password reset confirmation attempt for {email}")
            try:
                otp = OTP.objects.get(email=email, otp_code=otp_code, otp_type='password_reset', is_used=False)
                if otp.is_valid():
                    otp.is_used = True
                    otp.save()
                    user = CustomUser.objects.get(email=email)
                    user.set_password(new_password)
                    user.save()
                    del request.session['forgot_password_email']
                    logger.info(f"✓ Password reset successfully for {email}")
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
    logger.info("RESEND_FORGOT_PASSWORD_OTP view called")
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('forgot_password_email')
    if not email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:forgot_password_request')
    
    if not OTP.can_resend(email, 'password_reset'):
        cooldown = OTP.get_resend_cooldown(email, 'password_reset')
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:forgot_password_confirm')
    
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    logger.info(f"✓ Password reset OTP resent to {email}")
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:forgot_password_confirm')


@login_required
def password_reset_request_view(request):
    """Request OTP for password reset (logged in users)."""
    logger.info(f"PASSWORD_RESET_REQUEST view called by {request.user.username}")
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = request.user.email
            otp = OTP.create_otp(email, 'password_reset')
            send_otp_email(email, otp.otp_code, 'password_reset')
            request.session['password_reset_email'] = email
            logger.info(f"✓ Password reset OTP sent to {email}")
            messages.success(request, 'OTP sent to email.')
            return redirect('account:password_reset_confirm')
    else:
        form = PasswordResetRequestForm()
    return render(request, 'account/password_reset_request.html', {'form': form})


@login_required
def password_reset_confirm_view(request):
    """Confirm OTP and reset password (logged in users)."""
    logger.info(f"PASSWORD_RESET_CONFIRM view called by {request.user.username}")
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    
    try:
        latest_otp = OTP.objects.filter(
            email=email, 
            otp_type='password_reset', 
            is_used=False
        ).latest('created_at')
        time_remaining = latest_otp.time_remaining()
    except OTP.DoesNotExist:
        time_remaining = 0
    
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
                    logger.info(f"✓ Password changed successfully for {email}")
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
    logger.info(f"RESEND_PASSWORD_RESET_OTP view called by {request.user.username}")
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid reset session.')
        return redirect('account:profile')
    
    if not OTP.can_resend(email, 'password_reset'):
        cooldown = OTP.get_resend_cooldown(email, 'password_reset')
        messages.error(request, f'Too many resend attempts. Please wait {cooldown // 60} minutes and {cooldown % 60} seconds.')
        return redirect('account:password_reset_confirm')
    
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    logger.info(f"✓ Password reset OTP resent to {email}")
    messages.success(request, 'New OTP sent to email.')
    return redirect('account:password_reset_confirm')


def send_otp_email(email, otp_code, otp_type):
    """Send OTP email for verification or password reset."""
    logger.info(f"Sending {otp_type} OTP to {email}")
    try:
        if otp_type == 'registration':
            subject = 'Email Verification OTP'
            message = f'Your OTP for email verification is: {otp_code}\n\nExpires in 5 minutes.'
        else:
            subject = 'Password Reset OTP'
            message = f'Your OTP for password reset is: {otp_code}\n\nExpires in 5 minutes.'
        
        send_mail(subject, message, settings.EMAIL_HOST_USER, [email], fail_silently=False)
        logger.info(f"✓ Email sent successfully to {email}")
    except Exception as e:
        logger.error(f"Failed to send email to {email}: {str(e)}")
        logger.exception("Full traceback:")
        raise
    
@csrf_exempt
@require_GET
def health_check(request):
    """
    Health check endpoint for monitoring
    Returns system status including model loading status
    """
    logger.info("Health check requested")
    
    status = {
        'status': 'healthy',
        'database': 'connected',
        'models_loaded': models_loaded,
        'model_error': model_load_error,
        'timestamp': timezone.now().isoformat()
    }
    
    # Check database connection
    try:
        from django.db import connection
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        status['database'] = 'connected'
    except Exception as e:
        status['database'] = f'error: {str(e)}'
        status['status'] = 'unhealthy'
    
    # Check model files exist
    model_files = {
        'autoencoder': os.path.exists(MODEL_PATH),
        'projector': os.path.exists(PROJECTOR_PATH)
    }
    status['model_files'] = model_files
    
    if not all(model_files.values()):
        status['status'] = 'unhealthy'
        status['error'] = 'Model files missing'
    
    # Check media directories
    media_dirs = {
        'input': os.path.exists(os.path.join(settings.MEDIA_ROOT, 'uploads', 'input')),
        'output': os.path.exists(os.path.join(settings.MEDIA_ROOT, 'uploads', 'output'))
    }
    status['media_dirs'] = media_dirs
    
    http_status = 200 if status['status'] == 'healthy' else 503
    logger.info(f"Health check status: {status['status']}")
    
    return JsonResponse(status, status=http_status)


@csrf_exempt
@require_GET
def readiness_check(request):
    """
    Readiness check - returns 200 only when models are loaded
    This prevents traffic before models are ready
    """
    logger.info("Readiness check requested")
    
    if models_loaded and encoder is not None and rgb_projector is not None:
        logger.info("Readiness check: READY")
        return JsonResponse({'status': 'ready'}, status=200)
    else:
        logger.warning("Readiness check: NOT READY")
        return JsonResponse({
            'status': 'not_ready',
            'models_loaded': models_loaded,
            'error': model_load_error
        }, status=503)
