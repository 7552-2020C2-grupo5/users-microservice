"""Exceptions for the project."""


class UserDoesNotExist(Exception):
    pass


class PasswordDoesNotMatch(Exception):
    pass


class EmailAlreadyRegistered(Exception):
    pass


class BlockedUser(Exception):
    pass


class ServerTokenError(Exception):
    pass


class UnsetServerToken(Exception):
    pass


class InvalidEnvironment(Exception):
    pass
