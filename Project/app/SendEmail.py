import smtplib, ssl


def email_send(email, username, message):
    
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