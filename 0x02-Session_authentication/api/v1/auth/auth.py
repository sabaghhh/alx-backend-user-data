#!/usr/bin/env python3
"""
Task 3. Auth class

The API authentication class.
"""

from os import getenv
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth

    The API authentication class manager.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require_auth
        """
        if path is None:
            return True
        if excluded_paths is None or excluded_paths is []:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """authorization_header
        """
        if request is None or "Authorization" not in request.headers:
            return None
        return request.headers.get('Authorization')

    def current_user(self, request=None) -> TypeVar('User'):
        """current_user
        """
        return None

    def session_cookie(self, request=None):
        """session_cookie

        Returns a cookie value from a request.
        """
        if request is None:
            return None
        return request.cookies.get(getenv('SESSION_NAME'))
