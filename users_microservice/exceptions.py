"""Exceptions for the project."""


class UserDoesNotExist(Exception):
    pass


class PasswordDoesNotMatch(Exception):
    pass


class EmailAlreadyRegistered(Exception):
    pass
