"""
    Custom exceptions for the instant messaging system.
"""

__all__ = [
    'NonceVerificationError',
    'PasswordVerificationError',
    'ResourceNotFoundError',
    'UserNotFoundError', 'MultipleUsersFoundError', 'UsernameVerificationError',
    'CertificateExpirationError',
    'InvalidSignatureError',
    'AlreadyLoggedInError',
    'MethodNotFoundError',
    'DatabaseError'
]

class NonceVerificationError(Exception):
    pass


class PasswordVerificationError(Exception):
    pass


class ResourceNotFoundError(Exception):
    pass


class UserNotFoundError(Exception):
    pass


class MultipleUsersFoundError(Exception):
    pass


class UsernameVerificationError(Exception):
    pass


class CertificateExpirationError(Exception):
    pass


class InvalidSignatureError(Exception):
    pass


class AlreadyLoggedInError(Exception):
    pass


class MethodNotFoundError(Exception):
    pass


class DatabaseError(Exception):
    pass
