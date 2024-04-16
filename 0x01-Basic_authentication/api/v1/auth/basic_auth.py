#!/usr/bin/env python3
"""
Definition of class BasicAuth
"""
import base64
from .auth import Auth
from typing import TypeVar

from models.user import User


class BasicAuth(Auth):
    """Implements Basic Authorization protocol methods."""
    def extract_base64_authorization_header(self,
                                            auth_header_str: str) -> str:
        """
        Extracts the Base64 part of the Authorization header for Basic
        Authorization.
        """
        if auth_header_str is None or not isinstance(auth_header_str, str):
            return None
        if not auth_header_str.startswith("Basic "):
            return None
        token = auth_header_str.split(" ")[-1]
        return token

    def decode_base64_authorization_header(self,
                                           base64_auth_header: str) -> str:
        """
        Decode a Base64-encoded string.
        """
        if base64_auth_header is None or not isinstance(base64_auth_header, str):
            return None
        try:
            decoded = base64.b64decode(base64_auth_header.encode('utf-8'))
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_auth_header: str) -> (str, str):
        """
        Returns user email and password from Base64 decoded value.
        """
        if decoded_base64_auth_header is None or not isinstance(decoded_base64_auth_header, str):
            return (None, None)
        if ':' not in decoded_base64_auth_header:
            return (None, None)
        email, password = decoded_base64_auth_header.split(":", 1)
        return (email, password)

    def user_object_from_credentials(self, user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """
        Return a User instance based on email and password.
        """
        if user_email is None or not isinstance(user_email, str):
            return None
        if user_pwd is None or not isinstance(user_pwd, str):
            return None
        try:
            users = User.search({"email": user_email})
            if not users or users == []:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Returns a User instance based on a received request.
        """
        auth_header = self.authorization_header(request)
        if auth_header is not None:
            token = self.extract_base64_authorization_header(auth_header)
            if token is not None:
                decoded = self.decode_base64_authorization_header(token)
                if decoded is not None:
                    email, password = self.extract_user_credentials(decoded)
                    if email is not None:
                        return self.user_object_from_credentials(email, password)
        return None
