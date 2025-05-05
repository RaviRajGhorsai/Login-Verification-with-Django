# Email OTP Authentication System

This project is a user authentication system that includes signup, email verification, login with OTP (One-Time Password), and dashboard access. The flow ensures that only valid and verified users can log in securely.

## Features

- **User Signup**
  - Collects user information (e.g., name, email, password).
  - Verifies the provided email address using an external API.
  - If the email is valid, the user is saved to the database.
  - Sends a **registration success** email to the user.

- **User Login**
  - Authenticates the user using username and password.
  - If credentials are valid, sends a one-time password (OTP) to the user's registered email.
  - Redirects the user to the `verify_otp` page.

- **OTP Verification**
  - The user enters the OTP received via email.
  - If the OTP is valid, the user is redirected to the **dashboard**.

## Pages / Routes

- `/signup` - User registration form
- `/login` - Username and password authentication
- `/verify_otp` - OTP input form for final login step
- `/dashboard` - Protected page accessible after successful OTP verification

## Technologies Used

- Backend:  Django
- Database: SQL Server
- Email Services: SMTP
- OTP Generation: Randomized numeric code (6 digits)

## How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/RaviRajGhorsai/Login-Verification-with-Django.git
   cd Login-Verification-with-Django
