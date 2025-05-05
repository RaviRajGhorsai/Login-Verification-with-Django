from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model, authenticate, logout, login
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import smtplib, ssl
import requests
# Create your views here.

User = get_user_model()

@csrf_exempt
def signup(request):
    if request.method == 'POST':
        # Handle the signup logic here
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        email = request.POST.get('email')
       
        if password1 != password2:
            print("passwords do not match")
            return render(request, 'signup.html', {'error': 'passwords do not match'})
        
        if not username or not email or not password1:
            print("all fields are required")
            return render(request, 'signup.html', {'error': 'all fields are required'})
        
        try:
            validate_email(email)
        except ValidationError:
            print("Invalid email address")
            return render(request, 'signup.html', {'error': 'Invalid email address'})
        
        if User.objects.filter(username=username).exists():
            return HttpResponse("Username already exists!")
        
        if User.objects.filter(email=email).exists():
            return HttpResponse("Email already exists!")
        
        # Zeruh email verification API
        api_key = "268eb7defd4c6f3ab1383296fffd3122ad31ada8719aa275ab8a2f337e2868d7"
        url = f"https://api.zeruh.com/v1/verify?api_key={api_key}&email_address={email}"
        
        try:
            response = requests.get(url)
            data = response.json()
            
            if response.status_code == 200 and data.get('success') == True:
                verification_result = data.get('result', {})
                if verification_result.get('status') == 'deliverable':
                    print("Email is valid")

                    user = User.objects.create_user(username=username, password=password1, email=email)
                
                    port = 465  # For SSL
                    smtp_server = "smtp.gmail.com"
                    sender_email = "testappdjango37@gmail.com"
                    receiver_email = email
                    password = "thki rglo oqgr koee "
                    message = f"Welcome {username}, you have successfully signed up!"
                    create_context = ssl.create_default_context()
                    
                    with smtplib.SMTP_SSL(smtp_server, port, context=create_context) as server:
                        server.login(sender_email, password)
                        server.sendmail(sender_email, receiver_email, message)
                    return redirect('login')  # Redirect to the login page after signup
                else:
                    print("Email is not deliverable")
                    return render(request, 'signup.html', {'error': 'Email does not exist'})
                    
        except Exception as e:
            print(f"Error verifying email: {e}")
            return render(request, 'signup.html', {'error': e})
                    
    return render(request, 'signup.html')

def login_view(request):
    if request.method == 'POST':
        # Handle the login logic here
        username = request.POST.get('username')
        password = request.POST.get('password')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            # Redirect to the dashboard or any other page after successful login
            print("User is authenticated")
            return redirect('dashboard')
        else:
            print("invalid credentials")
            return render(request, 'login.html', {'error': 'Invalid username or password'})
        
    return render(request, 'login.html')

def dashboard(request):
    if request.user.is_authenticated == True:
       print("hello from dashboard")
    else:
        print("User is not authenticated")

    return render(request, 'dashboard.html')

def logout_view(request):
    if request.user.is_authenticated:
        # Handle the logout logic here
        logout(request)
        return redirect('login')  # Redirect to the login page after logout
    return redirect('login')  # Redirect to the login page if not authenticated