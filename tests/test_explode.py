import os

import rpm
import koji
import mock

from alt_src.alt_src import (
    explode_srpm,
    explode_srpm_cpio,
    explode_srpm_install,
    spec_from_headers,
    CommandError,
)


TESTS_PATH = os.path.dirname(__file__)
RPMS_PATH = os.path.join(TESTS_PATH, "data", "rpms")


def test_explode_install(tmpdir):
    """explode_srpm_install correctly unpacks files in the typical case."""

    srpm = os.path.join(RPMS_PATH, "fake-1.1-22.src.rpm")

    # Simulate that we're exploding into an existing git checkout.
    tmpdir.mkdir(".git")
    tmpdir.join(".git").join("config").write("foobar")

    # SRPM can be exploded without raising
    explode_srpm_install(srpm, str(tmpdir))

    # Destination directory contains expected files
    output_files = []
    for (dirpath, dirnames, filenames) in os.walk(str(tmpdir)):
        dirpath = os.path.relpath(dirpath, str(tmpdir))
        for filename in filenames:
            output_files.append(os.path.join(dirpath, filename))

    # It should extract exactly the expected files and should not touch unrelated files
    assert sorted(output_files) == [
        ".git/config",
        "SOURCES/foo.txt",
        "SPECS/fake.spec",
    ]


def test_explode_cpio(tmpdir):
    """explode_srpm_cpio correctly unpacks files in the typical case."""

    srpm = os.path.join(RPMS_PATH, "fake-1.1-22.src.rpm")

    # Simulate that we're exploding into an existing git checkout.
    tmpdir.mkdir(".git")
    tmpdir.join(".git").join("config").write("foobar")

    # SRPM can be exploded without raising
    header = koji.get_rpm_header(srpm)
    explode_srpm_cpio(srpm, header, str(tmpdir))

    # Destination directory contains expected files
    output_files = []
    for (dirpath, dirnames, filenames) in os.walk(str(tmpdir)):
        dirpath = os.path.relpath(dirpath, str(tmpdir))
        for filename in filenames:
            output_files.append(os.path.join(dirpath, filename))

    # It should extract exactly the expected files and should not touch unrelated files
    assert sorted(output_files) == [
        ".git/config",
        "SOURCES/foo.txt",
        "SPECS/fake.spec",
    ]


def test_explode_fallback():
    """explode_srpm tries "rpm -i" and falls back to rpm2cpio"""

    srpm = os.path.join(RPMS_PATH, "fake-1.1-22.src.rpm")

    with mock.patch('alt_src.alt_src.explode_srpm_install') as mock_install:
        mock_install.side_effect = CommandError('oops, did not work')
        with mock.patch('alt_src.alt_src.explode_srpm_cpio') as mock_cpio:
            # It should run without raising
            explode_srpm(srpm)

    # It should have tried both methods
    mock_install.assert_called_once()
    mock_cpio.assert_called_once()


def test_unflagged_spec():
    """spec_from_headers falls back to filename heuristic in case of missing flags."""

    headers = {
        # mix of strs and bytes intentionally used here since rpm can produce both
        rpm.RPMTAG_BASENAMES: ["somefile.patch", b"otherfile.spec", b"otherfile2.spec"],
        rpm.RPMTAG_FILEFLAGS: [0, 0, 0],
    }

    found = spec_from_headers(headers)

    # When no file was explicitly flagged as a spec file, it should use the first
    # file whose name ended in .spec - exactly compatible with logic built in to rpm.
    assert found == "otherfile.spec"
