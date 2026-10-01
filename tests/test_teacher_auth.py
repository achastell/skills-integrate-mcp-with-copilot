import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from fastapi import HTTPException, Response

from src import app as app_module


class TeacherAuthTests(unittest.TestCase):
    def setUp(self):
        self.original_teachers_file = app_module.TEACHERS_FILE
        self.original_session_secret = app_module.SESSION_SECRET
        self.original_activities = {
            name: {**activity, "participants": list(activity["participants"])}
            for name, activity in app_module.activities.items()
        }
        self.temp_dir = tempfile.TemporaryDirectory()
        app_module.TEACHERS_FILE = Path(self.temp_dir.name) / "teachers.json"
        app_module.SESSION_SECRET = "test-session-secret"

    def tearDown(self):
        app_module.TEACHERS_FILE = self.original_teachers_file
        app_module.SESSION_SECRET = self.original_session_secret
        app_module.activities.clear()
        app_module.activities.update(self.original_activities)
        self.temp_dir.cleanup()

    def request_with_cookies(self, cookies=None):
        return SimpleNamespace(cookies=cookies or {})

    def test_password_hash_verifies_without_storing_plaintext(self):
        password_hash = app_module.hash_teacher_password("correct horse battery staple")

        self.assertNotIn("correct horse battery staple", password_hash)
        self.assertTrue(app_module.verify_teacher_password("correct horse battery staple", password_hash))
        self.assertFalse(app_module.verify_teacher_password("wrong password", password_hash))

    def test_login_sets_httponly_signed_cookie(self):
        password_hash = app_module.hash_teacher_password("teacher-password")
        app_module.TEACHERS_FILE.write_text(
            json.dumps({"teachers": [{"username": "teacher", "password_hash": password_hash}]}),
            encoding="utf-8",
        )
        response = Response()

        result = app_module.login_teacher(
            app_module.LoginRequest(username="teacher", password="teacher-password"),
            response,
        )

        self.assertEqual(result["username"], "teacher")
        self.assertIn("httponly", response.headers["set-cookie"].lower())
        self.assertIn("samesite=strict", response.headers["set-cookie"].lower())

    def test_invalid_login_is_rejected(self):
        app_module.TEACHERS_FILE.write_text('{"teachers": []}', encoding="utf-8")

        with self.assertRaises(HTTPException) as error:
            app_module.login_teacher(
                app_module.LoginRequest(username="teacher", password="wrong"),
                Response(),
            )

        self.assertEqual(error.exception.status_code, 401)

    def test_session_rejects_tampering_and_expired_tokens(self):
        valid_token = app_module.create_teacher_session("teacher")
        tampered_token = valid_token[:-1] + ("A" if valid_token[-1] != "A" else "B")
        expired_token = app_module.create_teacher_session("teacher", expires_at=1)

        self.assertEqual(
            app_module.get_authenticated_teacher(
                self.request_with_cookies({app_module.SESSION_COOKIE_NAME: valid_token})
            ),
            "teacher",
        )
        self.assertIsNone(
            app_module.get_authenticated_teacher(
                self.request_with_cookies({app_module.SESSION_COOKIE_NAME: tampered_token})
            )
        )
        self.assertIsNone(
            app_module.get_authenticated_teacher(
                self.request_with_cookies({app_module.SESSION_COOKIE_NAME: expired_token})
            )
        )

    def test_unauthenticated_signup_and_unregister_are_rejected(self):
        activity = "Chess Club"
        email = "student@example.edu"
        request = self.request_with_cookies()

        with self.assertRaises(HTTPException) as signup_error:
            app_module.signup_for_activity(activity, email, request)
        with self.assertRaises(HTTPException) as unregister_error:
            app_module.unregister_from_activity(activity, email, request)

        self.assertEqual(signup_error.exception.status_code, 401)
        self.assertEqual(unregister_error.exception.status_code, 401)
        self.assertNotIn(email, app_module.activities[activity]["participants"])

    def test_authenticated_teacher_can_sign_up_and_unregister(self):
        activity = "Chess Club"
        email = "student@example.edu"
        token = app_module.create_teacher_session("teacher")
        request = self.request_with_cookies({app_module.SESSION_COOKIE_NAME: token})

        app_module.signup_for_activity(activity, email, request)
        self.assertIn(email, app_module.activities[activity]["participants"])

        app_module.unregister_from_activity(activity, email, request)
        self.assertNotIn(email, app_module.activities[activity]["participants"])


if __name__ == "__main__":
    unittest.main()