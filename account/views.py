from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from .forms import CustomUserCreationForm

@login_required
def home(request):
    return render(request, "account/home.html")

def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')  # redirect logged-in users

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
        else:
            error = "Invalid username or password"
            return render(request, 'account/login.html', {'error': error})
    return render(request, 'account/login.html')


def logout_view(request):
    logout(request)
    return redirect('login')


def register_view(request):
    if request.user.is_authenticated:
        return redirect('home')  # prevent re-registering if logged in

    if request.method == 'POST':
        form = CustomUserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)  # auto-login after registration
            return redirect('account:home')
    else:
        form = CustomUserCreationForm()

    return render(request, 'account/register.html', {'form': form})
