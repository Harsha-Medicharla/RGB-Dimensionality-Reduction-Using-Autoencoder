from .views import home, login_view , register_view
from django.urls import path, include

from django.contrib.auth import views as auth_views

app_name = 'account'

urlpatterns = [
    path('', home, name='home'),
    path('register/', register_view, name='register'),
    path('login/', login_view, name='login'),
    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
]
