"""Additional hamcrest matchers for use in tests."""

from hamcrest.core.base_matcher import BaseMatcher


class Exits(BaseMatcher):
    """Internal class, see `exits` method."""

    def __init__(self, expected_code):
        self.expected_code = expected_code

    def _matches(self, function, description=None):
        if not callable(function):
            if description:
                description.append_text('%s is not callable' % function)
            return False

        try:
            function()
        except SystemExit as e:
            if e.code == self.expected_code:
                return True
            if description:
                description.append_text('exited with code %s' % e.code)
            return False
        except Exception as e:
            if description:
                description.append_text('raised %s: %s' % (type(e), e))
            return False

        if self.expected_code == 0:
            # Did not raise, and was expected to exit successfully.
            # This is OK, top-level function returning normally also exits with 0 exit code
            return True

        # Did not raise, and was expected to exit unsuccessfully => fail
        if description:
            description.append_text('returned normally')
        return False

    def describe_to(self, description):
        description.append_text('a callable exiting with code %s' % self.expected_code)

    def describe_mismatch(self, item, description):
        self._matches(item, description)


def exits(code):
    """Matches if called function results in an exit with given exit code.

    Also matches if the exit code is 0 and the function returns normally.

    Similar to hamcrest "raises", but that doesn't work on exiting exceptions."""
    return Exits(code)

