"""Helper methods for tests."""


def listdiff(a: list, b: list):
    """Return the differences between two lists."""
    return [i for i in a if i not in b]
