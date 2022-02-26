"""Helper methods for tests."""


def listdiff(a, b):
    """Return the differences between two lists."""
    return [i for i in a if i not in b]
