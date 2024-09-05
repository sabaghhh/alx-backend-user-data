#!/usr/bin/env python3
"""
The expiration session authentication class
"""

from datetime import datetime, timedelta
from os import getenv
from api.v1.auth.session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """SessionExpAuth
    """
    def __init__(self):
        """__init__

        Overload the constructor
        """
        if int(getenv('SESSION_DURATION')):
            self.session_duration = int(getenv('SESSION_DURATION'))
        else:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """create_session
        """
        try:
            session_id = super().create_session(user_id)
        except Exception:
            return None
        session_dict = {
            'user_id': user_id,
            'created_at': datetime.now()
        }

        self.user_id_by_session_id[session_id] = session_dict
        return session_id

    def user_id_for_session_id(self, session_id=None):
        """user_id_for_session_id
        """
        if session_id is None:
            return None

        session_dict = self.user_id_by_session_id.get(session_id)
        if session_dict is None or 'created_at' not in session_dict:
            return None

        if self.session_duration <= 0:
            return session_dict.get('user_id')

        created_at = session_dict.get('created_at')
        session_elapsed = timedelta(seconds=self.session_duration)

        if created_at + session_elapsed < datetime.now():
            return None
        else:
            return session_dict.get('user_id')
