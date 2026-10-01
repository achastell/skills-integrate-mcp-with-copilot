# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Browse participant rosters
- Teacher-only sign-up and unregister controls
- Teacher sign-in with hashed credentials and expiring sessions

## Configure Teacher Access

Copy `teachers.example.json` to `teachers.json`. The local credentials file is ignored by Git. Create a password hash from the `src` directory with:

```sh
python -c 'import getpass; from app import hash_teacher_password; print(hash_teacher_password(getpass.getpass("Teacher password: ")))'
```

Add a record using the generated hash:

```json
{
   "teachers": [
      {"username": "teacher1", "password_hash": "pbkdf2_sha256$..."}
   ]
}
```

Set a persistent random `SESSION_SECRET` before deployment. For HTTPS deployments, also set `SESSION_COOKIE_SECURE=true`. Without `SESSION_SECRET`, the app generates an ephemeral key at startup, so teachers must sign in again after a restart.

## Getting Started

1. Install the dependencies:

   ```
   pip install fastapi uvicorn
   ```

2. Run the application:

   ```
   python app.py
   ```

3. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| POST   | `/auth/login`                                                      | Sign in as a teacher                                               |
| GET    | `/auth/status`                                                     | Check the current teacher session                                  |
| POST   | `/auth/logout`                                                     | Sign out the current teacher                                       |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student; teacher login required                       |

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
