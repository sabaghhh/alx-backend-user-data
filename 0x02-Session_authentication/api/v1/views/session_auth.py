#!/usr/bin/env python3
"""
The session authentication class
"""

from typing import Tuple
from api.v1.views import app_views
from flask import abort, jsonify, request
from models.user import User
from os import getenv


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """login

    POST /api/v1/auth_session/login
    Return:
      - JSON representation of a User object.
    """
    email = request.form.get('email')
    if email is None or len(email.strip()) == 0:
        return jsonify({'error': 'email missing'}), 400

    password = request.form.get('password')
    if password is None or len(password.strip()) == 0:
        return jsonify({'error': 'password missing'}), 400

    not_found = {'error': 'no user found for this email'}
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify(not_found), 404
    if len(users) <= 0:
        return jsonify(not_found), 404
    if users[0].is_valid_password(password):
        from api.v1.app import auth
        sessiond_id = auth.create_session(getattr(users[0], 'id'))
        res = jsonify(users[0].to_json())
        res.set_cookie(getenv("SESSION_NAME"), sessiond_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
        '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout():
    """logout
    """
    from api.v1.app import auth
    if not auth.destroy_session(request):
        abort(404)
    return jsonify({}), 200
