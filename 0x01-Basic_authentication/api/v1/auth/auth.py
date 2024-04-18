#!/usr/bin/env python3
""""
A Module for the API authentication
"""

from flask import request
from typing import List, TypeVar


class Auth:
    """
    An Authentication class
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Checks if a path requires authentication
        """
        if path is None or not excluded_paths:
            return True
        for i in excluded_paths:
            if i.endswith('*') and path.startswith(i[:-1]):
                return False
            elif i in {path, path + '/'}:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        It Returns the value of the Authorization header
        """
        if request is None or 'Authorization' not in request.headers:
            return None
        else:
            return request.headers['Authorization']
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        It Returns the current user
        """
        return None
