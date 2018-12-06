import re
import sys
import shutil
import tempfile
import os
import logging
import fcntl
import pytest
from subprocess import Popen, PIPE, check_call, check_output
from multiprocessing import Process
from mock import patch, MagicMock, call
from configparser import RawConfigParser
from hamcrest import assert_that, empty, equal_to, not_, calling, raises

from .matchers import exits

# ensure python2 before attempting to import sources
if sys.version_info < (3, 0):
    from .test_import.alt_src import main, BaseProcessor, acquire_lock

xfail = pytest.mark.xfail(sys.version_info >= (3, 0), reason="Incompatible with python3")

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
        'wait_time': 5,
        'sleep_interval': 1,
    }


@pytest.fixture
def config_file(tempdir, default_config):
    """Yields path to a configuration file suitable for testing."""
    cfg = RawConfigParser()
    cfg.add_section('altsrc')
    for key, value in default_config.items():
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


@xfail(strict=True)
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


@xfail(strict=True)
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


@xfail(strict=True)
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


@xfail(strict=True)
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
    assert dupwarn


@xfail(strict=True)
def test_repush_with_state_init(config_file, pushdir, lookasidedir, default_config, capsys):

    rpm = 'grub2-2.02-0.64.el7.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm)
    ]

    # call once, fail the task in staging process, the state ends with INIT
    with patch("tests.test_import.alt_src.Stager.setup_checkout", autospec=True, side_effect=RuntimeError):
        assert_that(calling(main).with_args(options), exits(2))
    # remove handlers
    remove_handlers()

    # clear out/err
    capsys.readouterr()
    # call main again to push
    assert_that(calling(main).with_args(options), exits(0))

    out, err = capsys.readouterr()
    out_lines = out.splitlines()

    assert_that(len(err), equal_to(0))
    expected = "[WARNING] Incomplete staging dir %s/c7/g/grub2/grub2-2.02-0.64.el7 (state=INIT), \
will overwrite." % default_config['stagedir']
    assert [l for l in out_lines if expected in l]

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'grub2', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@xfail(strict=True)
def test_repush_with_state_none(config_file, lookasidedir, capsys):
    """
    set_state fails, state file is not created, so get_state fails to open
    it and state ends with None.
    Repush succeeds.
    """

    rpm = 'grub2-2.02-0.64.el7.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm)
    ]

    # call once, fail the task at state file creation, the state ends with None
    with patch("tests.test_import.alt_src.BaseProcessor.set_state",
               autospec=True, side_effect=RuntimeError):
        assert_that(calling(main).with_args(options), exits(2))
    # remove handlers
    remove_handlers()

    # clear out/err
    capsys.readouterr()

    # call main again to push
    assert_that(calling(main).with_args(options), exits(0))

    out, err = capsys.readouterr()
    out_lines = out.splitlines()

    assert_that(len(err), equal_to(0))
    expected = '(state=None), will overwrite.'
    assert [l for l in out_lines if expected in l]

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'grub2', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@xfail(strict=True)
def test_get_state_with_error_other_than_enoent(tempdir):
    options = MagicMock(brew=None, source=tempfile.mkstemp(dir=tempdir)[1])
    processor = BaseProcessor(options)
    processor.workdir = tempfile.mkstemp(dir=tempdir)[1]

    # attempting to open state file raises generic IOError
    with patch('__builtin__.open', autospec=True, side_effect=IOError):
        # error is raised by method because only ENOENT is handled
        assert_that(calling(processor.get_state), raises(IOError))


@xfail(strict=True)
def test_repush_with_state_staged(config_file, pushdir, lookasidedir, default_config, capsys):

    rpm = 'grub2-2.02-0.64.el7.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm)
    ]

    with patch("tests.test_import.alt_src.Pusher.push_git", autospec=True, side_effect=RuntimeError):
        assert_that(calling(main).with_args(options), exits(2))

    # before push again, we need to change the branch to some unkown branch
    # to simulate what would happen in push_git
    cmd = 'git checkout -b arandombranch'
    checkout = default_config['stagedir']+'/c7/g/grub2/grub2-2.02-0.64.el7/checkout'
    check_call(cmd.split(), cwd=checkout)

    # remove handlers to avoid duplicate logs/errors
    remove_handlers()
    # clear the out/err from last main call
    capsys.readouterr()

    assert_that(calling(main).with_args(options), exits(0))

    out, err = capsys.readouterr()
    out_lines = out.splitlines()
    assert_that(len(err), equal_to(0))

    expected = '[WARNING] Already successfully staged: %s/c7/g/grub2/grub2-2.02-0.64.el7' % default_config['stagedir']
    assert [l for l in out_lines if expected in l]

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'grub2', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@xfail(strict=True)
def test_log_cmd_with_retries(capsys):

    mock_options = MagicMock(brew=False)
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
    logger = logging.getLogger('altsrc')
    handler = logging.StreamHandler()
    handler.setLevel('DEBUG')
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(handler)

    with patch('time.sleep') as mocked_sleep:
        with patch('subprocess.Popen.wait', side_effect=[1,1,1,0]) as mocked_wait:
            assert_that(calling(processor.log_cmd).with_args(['echo', 'hello'], tries=4), exits(0))
            assert len(mocked_wait.mock_calls) == 4
            assert mocked_sleep.call_args_list == [call(30), call(60), call(90)]

    out, err = capsys.readouterr()

    # should fail three times and succeed in the forth time
    expected = '[WARNING]  Command echo hello failed, will retry in 90s [tried: 3/4]'
    assert expected in err


@xfail(strict=True)
@pytest.mark.parametrize('cmd, expected', [(['git', 'clone', 'some_git_url'], 4),
                                           (['rsync', 'src', 'dst'], 4),
                                           (['echo', 'foo'], 1)
                                           ])
def test_default_tries(cmd, expected):
    """
    test different number of tries for different commands.
    If the command trys to communicate with remote server e.g. git clone,
    then the retries is set to 4, else it's defaulted to 1
    """
    mock_options = MagicMock(brew=False)
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
    assert processor.default_tries(cmd) == expected


@xfail(strict=True)
def test_push_when_already_pushed(config_file, lookasidedir, default_config, capsys):
    """
    test if the same content has already pushed to remote,
    then the task should continue to push tags
    """
    rpm_1 = 'rcm-repoquery-1.4-1.foo.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm_1)
    ]

    # push content to remote
    assert_that(calling(main).with_args(options), exits(0))
    capsys.readouterr()
    remove_handlers()

    # push an rpm with same content but different tag
    rpm_2 = 'rcm-repoquery-1.4-1.bar.src.rpm'
    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm_2)
    ]
    assert_that(calling(main).with_args(options), exits(0))
    out, err = capsys.readouterr()
    out_lines = out.splitlines()
    expected = '[INFO] Same content already on remote, will push tag only'
    assert [l for l in out_lines if expected in l]
    # check if both tags are in the remote repo
    git_url = default_config['git_push_url'] % {'package':'rcm-repoquery'}
    cmd = ['git', 'tag']
    out = check_output(cmd, cwd=git_url)
    assert sorted(out.splitlines()) == ['imports/c7/rcm-repoquery-1.4-1.bar',
                            'imports/c7/rcm-repoquery-1.4-1.foo']

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'rcm-repoquery', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@xfail(strict=True)
def test_acquire_release_lock(tempdir):
    # test lock and relase file lock function works as expected
    logger = logging.getLogger('altsrc')
    logger.setLevel('DEBUG')
    log_file = os.path.join(tempdir, 'altsrc-log')
    handler = logging.FileHandler(log_file)
    handler.setLevel('DEBUG')
    handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
    logger.addHandler(handler)

    lock_file_path = os.path.join(tempdir, 'lock')
    # acquire the lock first
    locker = acquire_lock(lock_file_path, 1, 0.2, logger)
    # invoke another process to acquire the lock again
    proc = Process(target=acquire_lock, args=(lock_file_path, 1, 0.2, logger))
    proc.start()
    proc.join()

    # should raise error.
    expected_1 = '[INFO] Another task is processing the current directory, waiting..'
    expected_2 = '[ERROR] Failed to acquire lock within 1s'
    with open(log_file, 'r') as f:
        logs = f.readlines()
        assert [l for l in logs if expected_1 in l]
        assert [l for l in logs if expected_2 in l]

    # release the lock and invoke another process to acquire lock again
    fcntl.lockf(locker, fcntl.LOCK_UN)
    locker.close()
    proc = Process(target=acquire_lock, args=(lock_file_path, 1, 0.2, logger))
    proc.start()
    proc.join()

    # lock should be acquired successfully.
    expected = '[INFO] Lock acquired'
    with open(log_file, 'r') as f:
        assert expected in f.readlines()[-1]
    remove_handlers()


@xfail(strict=True)
def test_stage_only(config_file, pushdir, capsys):
    """
    test a task without push option
    """
    rpm = 'grub2-2.02-0.64.el7.src.rpm'

    options = ['-v',
               '-c', config_file,
               'c7',
               os.path.join(RPMS_PATH, rpm)
            ]

    assert_that(calling(main).with_args(options), exits(0))
    _, err = capsys.readouterr()

    assert_that(len(err), equal_to(0))
    files = os.listdir(pushdir)
    assert_that(files, empty())
