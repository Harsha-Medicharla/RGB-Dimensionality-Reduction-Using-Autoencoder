from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from .forms import CustomUserCreationForm, CustomLoginForm, UserUpdateForm, PasswordResetRequestForm, PasswordResetConfirmForm
from .models import CustomUser, OTP

@login_required
def home(request):
    return render(request, "account/home.html")

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
            # Save user but don't activate yet
            user = form.save(commit=False)
            user.is_active = True  # Keep active but mark email as unverified
            user.email_verified = False
            user.save()
            
            # Generate and send OTP
            otp = OTP.create_otp(user.email, 'registration')
            send_otp_email(user.email, otp.otp_code, 'registration')
            
            # Store email in session for OTP verification
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
                # Mark OTP as used
                otp.is_used = True
                otp.save()
                
                # Verify user email
                user = CustomUser.objects.get(id=request.session.get('pending_user_id'))
                user.email_verified = True
                user.save()
                
                # Clear session
                del request.session['pending_verification_email']
                del request.session['pending_user_id']
                
                # Log user in
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
    
    # Generate new OTP
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
            
            # Generate and send OTP
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
                    # Mark OTP as used
                    otp.is_used = True
                    otp.save()
                    
                    # Update password
                    user = request.user
                    user.set_password(new_password)
                    user.save()
                    
                    # Update session to prevent logout
                    update_session_auth_hash(request, user)
                    
                    # Clear session
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
    
    # Generate new OTP
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