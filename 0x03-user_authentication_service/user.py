#!/usr/bin/env python3
"""
a User Module
"""

from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String

Base = declarative_base()


class User(Base):
    """
    a User class
    """

    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)

    def __repr__(self):
        """
        String Rep
        """
        return f"User: id={self.id}"
