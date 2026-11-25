"""Swapping a module attribute for a test and putting it back after it.

A test that sets `module.SessionLocal = ...` (or a path, a constant, a function) and never restores it leaves the swap to every test that runs
later in the same process - so a later test that forgot to swap a module silently works on an earlier test's database instead of failing, and the
leak only shows in a full run (seen: test_central_feeds let router_logs write logons to the real data/mikrotik.db).
"""


def swap(case, obj, attr: str, value) -> None:
    """Sets obj.attr = value for one test; the old value comes back when the test ends (pass the test case)."""
    old = getattr(obj, attr)
    case.addCleanup(setattr, obj, attr, old)
    setattr(obj, attr, value)


def swap_class(cls, obj, attr: str, value) -> None:
    """The same for setUpClass: the old value comes back after the last test of the class."""
    old = getattr(obj, attr)
    cls.addClassCleanup(setattr, obj, attr, old)
    setattr(obj, attr, value)
