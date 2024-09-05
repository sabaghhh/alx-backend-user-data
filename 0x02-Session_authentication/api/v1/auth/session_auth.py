#!/usr/bin/env python3
"""
The session authentication class
"""

from uuid import uuid4
from api.v1.auth.auth import Auth
from models.user import User


class SessionAuth(Auth):
    """SessionAuth
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """create_session

        Creates a session id for a user id.
        """
        if user_id is None or not isinstance(user_id, str):
            return None
        session_id = str(uuid4())
        self.user_id_by_session_id[session_id] = user_id
        return session_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """user_id_for_session_id

        Returns the user id based on the session id
        """
        if session_id is None or not isinstance(session_id, str):
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None):
        """current_user

        Returns a user instance based on a cookie value.
        """
        user_id = self.user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)

    def destroy_session(self, request=None):
        """destroy_session

        Detects the user session/logout.
        """
        if request is None:
            return False
        session_id = self.session_cookie(request)
        if session_id not in request or session_id is None:
            return False
        users = self.user_id_for_session_id(session_id)
        if session_id not in users or users is None:
            return False
        del self.user_id_by_session_id[session_id]
        return True
