from .views import (
    home, profile, login_view, register_view, 
    verify_otp_view, resend_otp_view,
    password_reset_request_view, password_reset_confirm_view,
    resend_password_reset_otp_view, results_view,
    forgot_password_request_view, forgot_password_confirm_view,
    resend_forgot_password_otp_view
)
from django.urls import path
from django.contrib.auth import views as auth_views

app_name = 'account'

urlpatterns = [
    path('', home, name='home'), 
    path('profile/', profile, name='profile'), 
    path('register/', register_view, name='register'), 
    path('verify-otp/', verify_otp_view, name='verify_otp'),  # Verify registration OTP
    path('resend-otp/', resend_otp_view, name='resend_otp'),  # Resend registration OTP
    path('login/', login_view, name='login'), 
    path('logout/', auth_views.LogoutView.as_view(), name='logout'), 
    
    path('forgot_password/', forgot_password_request_view, name='forgot_password_request'),
    path('forgot-password-confirm/', forgot_password_confirm_view, name='forgot_password_confirm'),
    path('resend-forgot-password-otp/', resend_forgot_password_otp_view, name='resend_forgot_password_otp'),
    path('password-reset/', password_reset_request_view, name='password_reset_request'),
    path('password-reset-confirm/', password_reset_confirm_view, name='password_reset_confirm'),
    path('resend-password-reset-otp/', resend_password_reset_otp_view, name='resend_password_reset_otp'),
    path('results/<int:pk>/', results_view, name='results'),  
]