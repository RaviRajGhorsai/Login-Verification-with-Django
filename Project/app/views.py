from django.shortcuts import render, redirect
from django.http import HttpResponse
from django.contrib.auth import get_user_model

import smtplib, ssl
# Create your views here.

User = get_user_model()

def signup(request):
    if request.method == 'POST':
        # Handle the signup logic here
        username = request.POST.get('username')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        email = request.POST.get('email')
       
        if password1 != password2:
            return HttpResponse("Passwords do not match!")
        
        if User.objects.filter(username=username).exists():
            return HttpResponse("Username already exists!")
        
        if User.objects.filter(email=email).exists():
            return HttpResponse("Email already exists!")
        
        user = User.objects.create_user(username=username, password=password1, email=email)
        
        # Send a confirmation email
        
        port = 465  # For SSL
        smtp_server = "smtp.gmail.com"
        sender_email = "testappdjango37@gmail.com"
        receiver_email = email
        password = "djangotest"
        message = f"Wlecome {username}, you have successfully signed up!"
        create_context = ssl.create_default_context()
        
        with smtplib.SMTP_SSL(smtp_server, port, context=create_context) as server:
            server.login(sender_email, password)
            server.sendmail(sender_email, receiver_email, message)
        
        return redirect('login')  # Redirect to the login page after signup
    return render(request, 'signup.html')

def login_view(request):
    return render(request, 'login.html')