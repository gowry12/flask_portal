# login-registration-portal
https://flask-portal.onrender.com
This project is a secure and user-friendly login and registration portal built using Flask. It allows users to register with their email and password, verify their email using a code sent to their inbox, and securely log in to access the portal. The portal ensures email verification before granting access to user-specific content.

##Technologies Used
Backend: Flask (Python), Flask-Login, Flask-Mail, SQLAlchemy
Database: SQLite
Frontend: HTML, CSS
Security: Password hashing with Werkzeug

##Features
User registration with email and password
Email verification with a 6-digit code
Secure login and logout functionality
User session management

##Installation and Usage Instructions
Prerequisites
Python installed on your system (version 3.7 or higher).
A Gmail account to configure email sending.

##installation
Configure email settings in app.py:
Replace your_secret_key with a secure secret key.
Replace MAIL_USERNAME and MAIL_PASSWORD with your email and app password.

##Initialize the database:
python app.py
The database users.db will be created automatically.

##Running the Application
Start the Flask development server:
python app.py
Open your web browser and navigate to:
http://127.0.0.1:5000

##Usage
Register: Provide your email and password to create an account. You will receive an email with a verification code.
Verify Email: Enter the code to verify your email address.
Login: Use your verified email and password to log in.
Logout: Click the "Logout" button to end your session.

##Screenshots
Welcome Page
<img width="960" alt="Screenshot 2024-12-20 142940" src="https://github.com/user-attachments/assets/d2853120-a3a5-4417-a82d-fb53c7f2f8dc" />
Registration Page
<img width="959" alt="Screenshot 2024-12-20 142949" src="https://github.com/user-attachments/assets/4df70bf1-8b1a-4b2f-a47b-c85ca0c23024" />
Login Page
<img width="960" alt="Screenshot 2024-12-20 143003" src="https://github.com/user-attachments/assets/f9e13e70-a1d8-451a-8488-2480b8d20b5b" />
Email Verification
<img width="960" alt="Screenshot 2024-12-20 143114" src="https://github.com/user-attachments/assets/fe747aa9-a561-46a2-b405-a4d2b0defb63" />
Home Page
<img width="960" alt="Screenshot 2024-12-20 143050" src="https://github.com/user-attachments/assets/06b06f5a-15dc-44ab-b3fa-b3fe740d5eea" />
