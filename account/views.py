from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from django.core.files.base import ContentFile
from PIL import Image, ImageFilter
import io
from .forms import (CustomUserCreationForm, CustomLoginForm, UserUpdateForm, 
                    PasswordResetRequestForm, PasswordResetConfirmForm, ImageUploadForm)
from .models import CustomUser, OTP, ImageUpload

@login_required
def home(request):
    if request.method == 'POST':
        form = ImageUploadForm(request.POST, request.FILES)
        if form.is_valid():
            image_upload = form.save(commit=False)
            image_upload.user = request.user
            image_upload.save()
            
            # Process the image (dummy processing for now)
            process_image(image_upload)
            
            messages.success(request, 'Image uploaded and processed successfully!')
            return redirect('account:results', pk=image_upload.pk)
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, error)
    else:
        form = ImageUploadForm()
    
    # Get recent uploads
    recent_uploads = ImageUpload.objects.filter(user=request.user)[:5]
    
    return render(request, "account/home.html", {
        'form': form,
        'recent_uploads': recent_uploads
    })


@login_required
def results_view(request, pk):
    image_upload = get_object_or_404(ImageUpload, pk=pk, user=request.user)
    return render(request, 'account/results.html', {'image_upload': image_upload})


def process_image(image_upload):
    """
    Dummy image processing function.
    In production, this would call your actual ML model.
    For now, it just applies a simple blur filter as a placeholder.
    """
    try:
        # Open the input image
        img = Image.open(image_upload.input_image)
        
        # Dummy processing: Apply a blur filter
        # Replace this with your actual model inference
        processed_img = img.filter(ImageFilter.GaussianBlur(radius=2))
        
        # Save the processed image
        output_io = io.BytesIO()
        processed_img.save(output_io, format='PNG')
        output_io.seek(0)
        
        # Save to the output_image field
        filename = f"processed_{image_upload.id}.png"
        image_upload.output_image.save(filename, ContentFile(output_io.read()), save=False)
        image_upload.processed = True
        image_upload.save()
        
    except Exception as e:
        print(f"Error processing image: {e}")
        # In production, you might want to log this error properly


@login_required
def profile(request):
    if request.method == 'POST':
        form = UserUpdateForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            messages.success(request, 'Your profile has been updated successfully!')
            return redirect('account:profile')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserUpdateForm(instance=request.user)
    
    return render(request, 'account/profile.html', {'form': form})

def login_view(request):
    if request.user.is_authenticated:
        return redirect('account:home')

    if request.method == 'POST':
        form = CustomLoginForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                if not user.email_verified:
                    messages.error(request, 'Please verify your email before logging in.')
                    return redirect('account:login')
                
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                next_url = request.GET.get('next', 'account:home')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid username or password.')
    else:
        form = CustomLoginForm()
    
    return render(request, 'account/login.html', {'form': form})

def logout_view(request):
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('account:login')

def register_view(request):
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
            
            messages.success(request, f'Account created! Please check your email for the OTP.')
            return redirect('account:verify_otp')
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f'{field}: {error}')
    else:
        form = CustomUserCreationForm()

    return render(request, 'account/register.html', {'form': form})

def verify_otp_view(request):
    if request.user.is_authenticated:
        return redirect('account:home')
    
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    
    if request.method == 'POST':
        otp_code = request.POST.get('otp_code')
        
        try:
            otp = OTP.objects.get(
                email=email,
                otp_code=otp_code,
                otp_type='registration',
                is_used=False
            )
            
            if otp.is_valid():
                otp.is_used = True
                otp.save()
                
                user = CustomUser.objects.get(id=request.session.get('pending_user_id'))
                user.email_verified = True
                user.save()
                
                del request.session['pending_verification_email']
                del request.session['pending_user_id']
                
                login(request, user)
                messages.success(request, 'Email verified successfully! Welcome!')
                return redirect('account:home')
            else:
                messages.error(request, 'OTP has expired. Please request a new one.')
        except OTP.DoesNotExist:
            messages.error(request, 'Invalid OTP. Please try again.')
    
    return render(request, 'account/verify_otp.html', {'email': email})

def resend_otp_view(request):
    email = request.session.get('pending_verification_email')
    if not email:
        messages.error(request, 'No pending verification found.')
        return redirect('account:register')
    
    otp = OTP.create_otp(email, 'registration')
    send_otp_email(email, otp.otp_code, 'registration')
    
    messages.success(request, 'A new OTP has been sent to your email.')
    return redirect('account:verify_otp')

@login_required
def password_reset_request_view(request):
    if request.method == 'POST':
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            email = request.user.email
            
            otp = OTP.create_otp(email, 'password_reset')
            send_otp_email(email, otp.otp_code, 'password_reset')
            
            request.session['password_reset_email'] = email
            messages.success(request, 'OTP sent to your email.')
            return redirect('account:password_reset_confirm')
    else:
        form = PasswordResetRequestForm()
    
    return render(request, 'account/password_reset_request.html', {'form': form})

@login_required
def password_reset_confirm_view(request):
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid password reset session.')
        return redirect('account:profile')
    
    if request.method == 'POST':
        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            otp_code = form.cleaned_data.get('otp_code')
            new_password = form.cleaned_data.get('new_password1')
            
            try:
                otp = OTP.objects.get(
                    email=email,
                    otp_code=otp_code,
                    otp_type='password_reset',
                    is_used=False
                )
                
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
                else:
                    messages.error(request, 'OTP has expired. Please request a new one.')
            except OTP.DoesNotExist:
                messages.error(request, 'Invalid OTP. Please try again.')
    else:
        form = PasswordResetConfirmForm()
    
    return render(request, 'account/password_reset_confirm.html', {'form': form})

@login_required
def resend_password_reset_otp_view(request):
    email = request.session.get('password_reset_email')
    if not email or email != request.user.email:
        messages.error(request, 'Invalid password reset session.')
        return redirect('account:profile')
    
    otp = OTP.create_otp(email, 'password_reset')
    send_otp_email(email, otp.otp_code, 'password_reset')
    
    messages.success(request, 'A new OTP has been sent to your email.')
    return redirect('account:password_reset_confirm')

def send_otp_email(email, otp_code, otp_type):
    """Send OTP email to user"""
    if otp_type == 'registration':
        subject = 'Email Verification OTP'
        message = f'Your OTP for email verification is: {otp_code}\n\nThis OTP will expire in 10 minutes.'
    else:
        subject = 'Password Reset OTP'
        message = f'Your OTP for password reset is: {otp_code}\n\nThis OTP will expire in 10 minutes.'
    
    send_mail(
        subject,
        message,
        settings.EMAIL_HOST_USER,
        [email],
        fail_silently=False,
    )