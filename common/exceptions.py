"""
    Custom exceptions for the instant messaging system.
"""

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


class AlreadyLoggedInError(Exception):
    pass


class MethodNotFoundError(Exception):
    pass
