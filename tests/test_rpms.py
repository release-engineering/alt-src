import shutil
import tempfile
import os
from subprocess import Popen, PIPE, STDOUT

from ConfigParser import RawConfigParser

import pytest
from hamcrest import assert_that, empty, equal_to, not_


TESTS_PATH = os.path.dirname(__file__)
RPMS_PATH = os.path.join(TESTS_PATH, 'data', 'rpms')
RULES_PATH = os.path.join(TESTS_PATH, 'data', 'rules')
SRC_PATH = os.path.dirname(TESTS_PATH)
ALT_SRC = os.path.join(SRC_PATH, 'alt-src')

DEBRAND_XFAIL = [
    # list any RPMs where debrand is expected to fail here
]


@pytest.fixture
def tempdir():
    """Yields path to temporary directory removed after tests"""
    path = tempfile.mkdtemp('alt-src-test')
    yield path
    shutil.rmtree(path)


@pytest.fixture
def rulesdir():
    """Yields path to rules directory used within tests.

    Uses tests/data/rules by default, but ALTSRC_TEST_RULESDIR can be
    set to test against a different path."""
    from_env = os.environ.get('ALTSRC_TEST_RULESDIR')
    if from_env:
        return from_env
    return RULES_PATH


@pytest.fixture
def pushdir(tempdir):
    """Yields (existing) directory under which the pushed repos will be located"""
    out = os.path.join(tempdir, 'pushtest')
    os.makedirs(out)
    return out


@pytest.fixture
def lookasidedir(tempdir):
    return os.path.join(tempdir, 'lookaside')


@pytest.fixture
def default_config(pushdir, lookasidedir, tempdir):
    stagedir = os.path.join(tempdir, 'stage')
    os.makedirs(stagedir)

    return {
        'stagedir': stagedir,
        'lookaside': '%s/lookaside' % tempdir,
        'gitdir': '%s/git' % tempdir,
        'log_level': 'DEBUG',
        'rulesdir': rulesdir(),
        'git_push_url': os.path.join(pushdir, '%(package)s.git'),
        'init_rsync_dest': os.path.join(pushdir, '%(package)s.git'),
        'lookaside_rsync_dest': lookasidedir,
        # no blacklist
        'smtp_enabled': 'no',
        'smtp_host': 'smtp.example.redhat.com',
        'smtp_to': 'no_such_person@redhat.com',
        'smtp_log_to': 'no_such_person@redhat.com',
    }


@pytest.fixture
def config_file(tempdir, default_config):
    """Yields path to a configuration file suitable for testing."""
    cfg = RawConfigParser()
    cfg.add_section('altsrc')
    for key, value in default_config.iteritems():
        cfg.set('altsrc', key, value)

    filename = '%s/altsrc-test.cfg' % tempdir
    with open(filename, 'w') as fh:
        cfg.write(fh)

    yield filename

    os.unlink(filename)


def git_subject(git_dir, ref):
    """Return subject of a git ref within the given path."""
    cmd = ['git', 'show', '-s', '--format=%s', ref]
    proc = Popen(cmd, cwd=git_dir, stdout=PIPE)
    out, _ = proc.communicate()

    assert_that(proc.returncode, equal_to(0), "`git show' failed")

    return out.strip()


@pytest.mark.parametrize('branch,name,version,release', [
    ('c7', 'grub2', '2.02', '0.64.el7'),
    ('c7', 'ntp', '4.2.6p5', '25.el7_3.2'),
])
def test_push_with_debrand(config_file, pushdir, lookasidedir,
                           branch, name, version, release):
    """Verify that alt-src command completes without any errors and generates
    a debranding commit for the given RPM."""

    rpm = '-'.join([name, version, release]) +  '.src.rpm'

    command = [
        ALT_SRC,
        '-v',
        '-c', config_file,
        '--push',
        branch,
        os.path.join(RPMS_PATH, rpm)
    ]

    proc = Popen(command, stdout=PIPE, stderr=STDOUT)
    out, _ = proc.communicate()

    # It should complete with 0 exit code
    assert_that(proc.returncode, equal_to(0), 'failed with output:\n%s' % out)

    out_lines = out.splitlines()

    try:
        # It should not have logged any ERROR
        errors = [line for line in out_lines if '[ERROR]' in line]
        assert_that(errors, empty(), 'failed with output:\n%s' % out)

        # There should be a debrand commit
        subject = git_subject('%s/%s.git' % (pushdir, name), branch)
        expected_subject = 'debrand %s-%s-%s' % (name, version, release)
        assert_that(subject, equal_to(expected_subject))
    except AssertionError:
        if rpm not in DEBRAND_XFAIL:
            raise
    else:
        assert_that(rpm not in DEBRAND_XFAIL,
                    'RPM was expected to fail debranding, but passed')

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, name, branch)
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))
