from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib.auth import get_user_model, authenticate, logout, login
from django.views.decorators.csrf import csrf_exempt
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import smtplib, ssl
import requests
import random
import json
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
            
            otp = random.randint(100000, 999999)
            request.session['otp'] = otp
            request.session['user_id'] = user.id
            request.session['username'] = username
            request.session.set_expiry(300)  # Set session expiry to 5 minutes
            
            port = 465
            smtp_server = "smtp.gmail.com"
            sender_email = "testappdjango37@gmail.com"
            receiver_email = user.email
            password_email = "thki rglo oqgr koee"
            message = f"Subject: Login OTP\n\nYour 6-digit OTP is {otp}. Do not share it.\n\nOTP expires in 5 minutes."

            context = ssl.create_default_context()
            try:
                with smtplib.SMTP_SSL(smtp_server, port, context=context) as server:
                    server.login(sender_email, password_email)
                    server.sendmail(sender_email, receiver_email, message)
            except Exception as e:
                print(f"Error sending email: {e}")
                return render(request, 'login.html', {'error': 'Failed to send OTP email'})
            # Redirect to the dashboard or any other page after successful login
            return redirect('otp_verify')  # Redirect to the OTP verification page
        else:
            print("invalid credentials")
            return render(request, 'login.html', {'error': 'Invalid username or password'})
        
    return render(request, 'login.html')

def otp_verify(request):
    if request.method == 'POST':
        # Handle the OTP verification logic here
        entered_otp = ''.join([request.POST.get(str(i), '') for i in range(6)])
        print(entered_otp)
        actual_otp = request.session.get('otp')
        user_id = request.session.get('user_id')
        print(actual_otp)
        if not actual_otp or not user_id:
            return render(request, 'otp.html', {'error': 'Session expired. Please login again.'})
        
        # data = json.loads(request.body)
        # entered_otp = data.get('otp')
        # print(entered_otp)
        
        if entered_otp == str(actual_otp):
            print("verified")
            user = User.objects.get(id=user_id)
            login(request, user)
            # Clear the OTP from the session after successful verification
            request.session.pop('otp', None)
            request.session.pop('user_id', None)
            return redirect('dashboard')
        else:
            print("invalid OTP")
            return render(request, 'otp.html', {'error': 'Invalid OTP. Please try again.'})
    return render(request, 'otp.html')

def dashboard(request):
    if request.user.is_authenticated == True:
       print("hello from dashboard")
       request.session.pop('username', None)
       
    else:
        print("User is not authenticated")

    return render(request, 'dashboard.html')

def logout_view(request):
    if request.user.is_authenticated:
        # Handle the logout logic here
        logout(request)
        return redirect('login')  # Redirect to the login page after logout
    return redirect('login')  # Redirect to the login page if not authenticated