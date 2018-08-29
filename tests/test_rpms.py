import re
import shutil
import tempfile
import os
import logging
from subprocess import Popen, PIPE, STDOUT

from ConfigParser import RawConfigParser

import pytest
from hamcrest import assert_that, empty, equal_to, not_, calling

from test_import.alt_src import main
from .matchers import exits

TESTS_PATH = os.path.dirname(__file__)
RPMS_PATH = os.path.join(TESTS_PATH, 'data', 'rpms')
RULES_PATH = os.path.join(TESTS_PATH, 'data', 'rules')

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

def remove_handlers():
    logger = logging.getLogger('altsrc')
    logger.handlers = []

@pytest.mark.parametrize('branch,name,version,release', [
    ('c7', 'grub2', '2.02', '0.64.el7'),
    ('c7', 'ntp', '4.2.6p5', '25.el7_3.2'),
])
def test_push_with_debrand(config_file, pushdir, lookasidedir,
                           branch, name, version, release, capsys):
    """Verify that alt-src command completes without any errors and generates
    a debranding commit for the given RPM."""

    rpm = '-'.join([name, version, release]) +  '.src.rpm'

    options = ['-v',
               '-c', config_file,
               '--push',
               branch,
               os.path.join(RPMS_PATH, rpm)
    ]

    assert_that(calling(main).with_args(options), exits(0))
    out, err = capsys.readouterr()

    try:
        assert_that(len(err), equal_to(0))
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
    remove_handlers()

@pytest.mark.parametrize('branch,name,version,release', [
    ('c7', 'grub2', '2.02', '0.64.el7'),
    ('c7', 'ntp', '4.2.6p5', '25.el7_3.2'),
])
def test_repush_with_staged_data(config_file, pushdir, lookasidedir,
                           branch, name, version, release, capsys):
    """Push once, the push again. The script should warn, but not error"""

    rpm = '-'.join([name, version, release]) +  '.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        branch,
        os.path.join(RPMS_PATH, rpm)
    ]

    # push once
    assert_that(calling(main).with_args(options), exits(0))
    # clear the output/err
    out, err = capsys.readouterr()
    # remove the handlers from global logger alt-src
    remove_handlers()
    # push again with same options
    assert_that(calling(main).with_args(options), exits(0))
    out, err = capsys.readouterr()
    out_lines = out.splitlines()

    try:
        assert_that(len(err), equal_to(0))
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

    # It should have logged a WARNING about duplicate content
    w_expect = '[WARNING] Skipping push for duplicate content'
    assert [l for l in out_lines if w_expect in l]


    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, name, branch)
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@pytest.mark.parametrize('branch,name,version,release', [
    ('c7', 'grub2', '2.02', '0.64.el7'),
    ('c7', 'ntp', '4.2.6p5', '25.el7_3.2'),
])
def test_repush_without_staged_data(config_file, pushdir, lookasidedir,
                           branch, name, version, release, default_config, capsys):
    """Push, clear stage, push again. The script should warn, but not error"""

    rpm = '-'.join([name, version, release]) +  '.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        branch,
        os.path.join(RPMS_PATH, rpm)
    ]

    # push once
    assert_that(calling(main).with_args(options), exits(0))
    # clear the output/err
    capsys.readouterr()
    # remove the handlers from global logger alt-src
    remove_handlers()
    # clear stage
    stagedir = default_config['stagedir']
    for fn in os.listdir(stagedir):
        shutil.rmtree("%s/%s" % (stagedir, fn))

    # run same push again
    assert_that(calling(main).with_args(options), exits(0))
    out, err = capsys.readouterr()
    out_lines = out.splitlines()

    try:
        # It should not have logged any ERROR
        assert_that(len(err), equal_to(0))
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

    # It should have logged a WARNING about duplicate content
    w_expect = '[WARNING] Skipping push for duplicate content'
    assert [l for l in out_lines if w_expect in l]

    # It should also warn about the existing tag
    w_expect = re.compile('\[WARNING\] Tag imports/.* already present on remote')
    assert [l for l in out_lines if w_expect.search(l)]

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, name, branch)
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@pytest.mark.parametrize('branch,name,version,release', [
    ('c7', 'fake', '1.1', '22'),
    # need no-debrand packages for this test
])
def test_repush_without_tag(config_file, pushdir, lookasidedir, branch,
                            name, version, release, default_config, capsys):
    """Push (no tag), clear stage, push again. Should warn, but not error"""

    rpm = '-'.join([name, version, release]) +  '.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '-o', 'push_tags=no',
        '--push',
        branch,
        os.path.join(RPMS_PATH, rpm)
    ]

    # push once
    assert_that(calling(main).with_args(options), exits(0))
    # clear the output/err
    capsys.readouterr()
    # remove the handlers from global logger alt-src
    remove_handlers()
    # clear stage
    stagedir = default_config['stagedir']
    for fn in os.listdir(stagedir):
        shutil.rmtree("%s/%s" % (stagedir, fn))

    # we need gitdir to exist
    os.makedirs(default_config['gitdir'])

    # run same push again
    assert_that(calling(main).with_args(options), exits(0))
    out, err = capsys.readouterr()
    out_lines = out.splitlines()

    # It should not have logged any ERROR
    assert_that(len(err), equal_to(0))
    # It should have logged a WARNING that rpm was already pushed
    w_expect = '[WARNING] Already pushed'
    dupwarn = [l for l in out_lines if w_expect in l]
