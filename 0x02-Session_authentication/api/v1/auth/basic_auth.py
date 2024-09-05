#!/usr/bin/env python3
"""
Task 6. Basic auth

The BasicAuth class
"""

from api.v1.auth.auth import Auth
from models.user import User
from base64 import b64decode
from typing import Tuple, TypeVar


class BasicAuth(Auth):
    """BasicAuth

    An imporved API authentication using the Auth class.
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """extract_base64_authorization_header

        Returns the Base64 part of the authorization header.
        """
        if authorization_header is None:
            return None
        if not isinstance(authorization_header, str):
            return None
        if "Basic " not in authorization_header:
            return None
        return authorization_header.split('Basic ', 1)[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """decode_base64_authorization_header

        Returns the decoded value as UTF8 string.
        """
        if base64_authorization_header is None:
            return None
        if not isinstance(base64_authorization_header, str):
            return None
        try:
            return b64decode(base64_authorization_header).decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """extract_user_credentials

        Returns the user email & password from base64 decoded value
        """
        if decoded_base64_authorization_header is None:
            return (None, None)
        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)
        return decoded_base64_authorization_header.split(":", 1)[0], \
            decoded_base64_authorization_header.split(":", 1)[1]

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """user_object_from_credentials

        Returns the user instance based on the email & password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            else:
                return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user

        Return the user instance from request.(overrides current_user in AUTH)
        """
        auth_header = self.authorization_header(request)
        base_extract = self.extract_base64_authorization_header(auth_header)
        base_decode = self.decode_base64_authorization_header(base_extract)
        user = self.extract_user_credentials(base_decode)
        return self.user_object_from_credentials(user[0], user[1])
