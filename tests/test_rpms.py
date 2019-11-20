import fcntl
import logging
import os
import re
import shutil
import sys
import tempfile
from multiprocessing import Process
from subprocess import PIPE, Popen, check_call, check_output
import pytest
import yaml
from configparser import RawConfigParser
from hamcrest import assert_that, calling, empty, equal_to, not_, raises
from mock import MagicMock, call, patch

from .matchers import exits

# ensure python2 before attempting to import sources
if sys.version_info < (3, 0):
    from alt_src.alt_src import (main, BaseProcessor, acquire_lock, StartupError,
                         SanityError, InputError, CONFIG_DEFAULTS, Stager,
                         CommandError)

xfail = pytest.mark.xfail(sys.version_info >= (3, 0), reason="Incompatible with python3")

TESTS_PATH = os.path.dirname(__file__)
RPMS_PATH = os.path.join(TESTS_PATH, 'data', 'rpms')
RULES_PATH = os.path.join(TESTS_PATH, 'data', 'rules')
MODULES_PATH = os.path.join(TESTS_PATH, 'data', 'module_source')

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
        'git_push_url_module': os.path.join(pushdir, '%(package)s.git'),
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


@pytest.fixture
def key_file(tempdir):
    "yields path to pagure api key file"
    filename = '%s/pagure.key' % tempdir
    with open(filename, 'w') as f:
        f.write("token xxxxxx")

    yield filename

    os.unlink(filename)


@pytest.fixture
def mock_koji_session():
    with patch('koji.ClientSession') as mock_koji_session:
        yield mock_koji_session


@pytest.fixture
def mock_koji_pathinfo():
    with patch('koji.PathInfo') as mock_koji_pathinfo:
        yield mock_koji_pathinfo


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


def get_test_mmd_str_and_dict():
    name = "my_package"
    stream = "42.2"
    version = "1.10"
    context = "c_1"
    summary = "foo_summary"
    mmd_dict = {'data':
                    {'name': name,
                     'stream': stream,
                     'version': version,
                     'context': context,
                     'summary': summary
                    }
               }
    mmd_str = """
---
document: modulemd
version: 2
data:
  name: my_package
  stream: 42.2
  summary: foo_summary
  context: c_1
  version: 1.10
"""

    return mmd_str, mmd_dict['data']


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
    _, err = capsys.readouterr()
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
    with patch("alt_src.alt_src.Stager.setup_checkout", autospec=True, side_effect=RuntimeError):
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
    expected = "[WARNING] Incomplete staging dir %s/c7/rpms/g/grub2/grub2-2.02-0.64.el7 \
(state=INIT), will overwrite." % default_config['stagedir']
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
    with patch("alt_src.alt_src.BaseProcessor.set_state",
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
    options = MagicMock(koji=None, source=tempfile.mkstemp(dir=tempdir)[1])
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

    with patch("alt_src.alt_src.Pusher.push_git", autospec=True, side_effect=RuntimeError):
        assert_that(calling(main).with_args(options), exits(2))

    # before push again, we need to change the branch to some unkown branch
    # to simulate what would happen in push_git
    cmd = 'git checkout -b arandombranch'
    checkout = default_config['stagedir']+'/c7/rpms/g/grub2/grub2-2.02-0.64.el7/checkout'
    check_call(cmd.split(), cwd=checkout)

    # remove handlers to avoid duplicate logs/errors
    remove_handlers()
    # clear the out/err from last main call
    capsys.readouterr()

    assert_that(calling(main).with_args(options), exits(0))

    out, err = capsys.readouterr()
    out_lines = out.splitlines()
    assert_that(len(err), equal_to(0))

    expected = '[WARNING] Already successfully staged: \
%s/c7/rpms/g/grub2/grub2-2.02-0.64.el7' % default_config['stagedir']
    assert [l for l in out_lines if expected in l]

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'grub2', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))


@xfail(strict=True)
def test_log_cmd_with_retries(capsys):

    mock_options = MagicMock(koji=False)
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
    mock_options = MagicMock(koji=False)
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
    remove_handlers()


@xfail(strict=True)
def test_stage_repo_no_master(config_file, pushdir, capsys, default_config):
    """
    check staging on new branch in repo having no master branch
    """
    rpm = 'grub2-2.02-0.64.el7.src.rpm'
    err_cmd_call_cnt = [1]

    workdir = default_config['stagedir']+'/c7/rpms/g/grub2/grub2-2.02-0.64.el7'
    os.makedirs(workdir)

    def init_repo():
        # init repo without master
        cmd = ['git', 'init', '--bare', 'repo_init.git']
        check_call(cmd, cwd=workdir)

    def log_cmd(cmd, fatal=True, **kwargs):
        # fail creating orphan branch first time
        # other calls respond as executed
        err_cmd = ['git', 'checkout', '--orphan', 'altsrc-stage-c7']

        if err_cmd == cmd and err_cmd_call_cnt[0] == 1:
            err_cmd_call_cnt[0] += 1
            if fatal:
                raise CommandError("command failed: %r" % err_cmd)
            return 1
        else:
            kwargs['stdout'] = PIPE
            kwargs['stderr'] = PIPE
            kwargs['close_fds'] = True
            proc = Popen(cmd, **kwargs)
            ret = proc.wait()
            if ret and fatal:
                raise CommandError("command failed: %r" % cmd)
            return ret

    options = ['-v',
               '-c', config_file,
               'c7',
               os.path.join(RPMS_PATH, rpm)
              ]

    with patch("alt_src.alt_src.Stager.init_new_repo") as mock_repo:
        with patch("alt_src.alt_src.BaseProcessor.log_cmd") as mock_cmd:
            mock_cmd.side_effect = log_cmd
            mock_repo.side_effect = init_repo
            assert_that(calling(main).with_args(options), exits(0))

    _, err = capsys.readouterr()

    assert_that(len(err), equal_to(0))
    files = os.listdir(pushdir)
    assert_that(files, empty())
    remove_handlers()


@xfail(strict=True)
def test_not_existing_source_file(config_file):
    rpm = 'foo.src.rpm'

    options = ['-v',
               '-c', config_file,
               'c7',
               os.path.join(RPMS_PATH, rpm)
              ]

    assert_that(calling(main).with_args(options), raises(StartupError))
    remove_handlers()


@xfail(strict=True)
def test_srpm_koji(mock_koji_session, mock_koji_pathinfo):
    mock_koji_session.return_value.getRPM.return_value = {'arch': 'src', 'build_id': 42}
    mock_koji_pathinfo.return_value.build.return_value = "test_build"
    mock_koji_pathinfo.return_value.rpm.return_value = "test_relpath"

    mock_options = MagicMock(koji=True, source="build_nvr.src.rpm")
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
        assert_that(processor.source_file, equal_to("test_build/test_relpath"))


@xfail(strict=True)
@pytest.mark.parametrize('getRPM_return_value',
                         [{'arch': 'foo'}, None],
                         ids=("wrong_arch", "source_not_found"))
def test_srpm_koji_sanity_error(getRPM_return_value, mock_koji_session, mock_koji_pathinfo):
    mock_koji_session.return_value.getRPM.return_value = getRPM_return_value
    mock_koji_pathinfo.return_value.build.return_value = "test_build"
    mock_koji_pathinfo.return_value.rpm.return_value = "test_relpath"

    mock_options = MagicMock(koji=True, source="build_nvr.src.rpm")
    assert_that(calling(BaseProcessor).with_args(mock_options), raises(SanityError))


@xfail(strict=True)
def test_module_src_koji(mock_koji_session, mock_koji_pathinfo):
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': "foo_module_str"}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_koji_pathinfo.return_value.typedir.return_value = "test_build/files/module/"

    mock_options = MagicMock(koji=True, source="build_nvr:modulemd.src.txt")
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
        assert_that(processor.source_file, equal_to("test_build/files/module/modulemd.src.txt"))
        assert_that(processor.mmd, equal_to("foo_module_str"))


@xfail(strict=True)
def test_module_src_koji_build_not_found(mock_koji_session, mock_koji_pathinfo):
    mock_koji_session.return_value.getBuild.return_value = None
    mock_koji_pathinfo.return_value.build.return_value = "test_build"

    mock_options = MagicMock(koji=True, source="build_nvr:modulemd.src.txt")
    assert_that(calling(BaseProcessor).with_args(mock_options), raises(SanityError))


@xfail(strict=True)
def test_read_srpm_input_error(mock_koji_session, mock_koji_pathinfo):
    mock_koji_session.return_value.getRPM.return_value = {'arch': 'src', 'build_id': 42}
    mock_koji_pathinfo.return_value.build.return_value = "test_build"
    mock_koji_pathinfo.return_value.rpm.return_value = "test_relpath"

    with patch('koji.get_rpm_header'):
        mock_options = MagicMock(koji=True, source="build_nvr.src.rpm")
        with patch('os.path.isfile', return_value=True):
            processor = BaseProcessor(mock_options)
            assert_that(calling(processor.read_srpm), raises(InputError))


@xfail(strict=True)
def test_read_mmd_str(mock_koji_session, mock_koji_pathinfo):
    mmd_str, mmd_dict = get_test_mmd_str_and_dict()

    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_options = MagicMock(koji=True, source="build_nvr:modulemd.src.txt")
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
        processor.source_file = os.path.join(MODULES_PATH, "modulemd.src.txt")
        processor.read_source_file()

    assert_that(processor.package, equal_to(mmd_dict['name']))
    assert_that(processor.version, equal_to(mmd_dict['stream']))
    assert_that(processor.release, equal_to(str(mmd_dict['version']) + '.' + mmd_dict['context']))
    assert_that(processor.summary, equal_to(mmd_dict['summary']))


@xfail(strict=True)
def test_mmd_no_changelog(mock_koji_session, mock_koji_pathinfo):
    mmd_str, mmd_dict = get_test_mmd_str_and_dict()
    mock_koji_pathinfo.return_value.rpm.return_value = "test_relpath"

    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_options = MagicMock(koji=True, source="build_nvr:modulemd.src.txt")
    with patch('os.path.isfile', return_value=True):
        processor = Stager(mock_options)
        processor.source_file = os.path.join(MODULES_PATH, "modulemd.src.txt")
        processor.read_source_file()
        processor.prep_changelog([])

    fn = '%s/changelog.txt' % processor.workdir
    assert_that(os.path.exists(fn), equal_to(False))
    assert_that(processor.package, equal_to(mmd_dict['name']))


@xfail(strict=True)
def test_git_url_module(mock_koji_session, mock_koji_pathinfo):
    mmd_str, mmd_dict = get_test_mmd_str_and_dict()
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo

    mock_options = MagicMock(koji=True, source="build_nvr:modulemd.src.txt", config=CONFIG_DEFAULTS)
    with patch('os.path.isfile', return_value=True):
        processor = BaseProcessor(mock_options)
        processor.source_file = os.path.join(MODULES_PATH, "modulemd.src.txt")
        processor.read_source_file()

        git_push_url = processor.git_push_url()
        git_fetch_url = processor.git_fetch_url()
        assert_that(git_push_url,
                    equal_to(processor.options.config['git_push_url_module']
                             % {'package': mmd_dict['name']}))

        assert_that(git_fetch_url,
                    equal_to(processor.options.config['git_push_url_module']
                             % {'package': mmd_dict['name']}))


@xfail(strict=True)
def test_unsupported_source_startup_error():
    mock_options = MagicMock(koji=True, source="build_nvr.src.foo")
    assert_that(calling(BaseProcessor).with_args(mock_options), raises(StartupError))


@xfail(strict=True)
def test_stage_module_src(config_file, pushdir, lookasidedir, capsys, default_config,
                          mock_koji_session, mock_koji_pathinfo):
    """Verify that alt-src command completes without any errors and generates
    a commit for the given module source."""
    branch = 'c7'
    modulemd = 'fake-nvr:modulemd.src.txt'

    options = ['-v',
               '-c', config_file,
               '--brew',
               branch,
               modulemd
              ]

    mmd_str, mmd_dict = get_test_mmd_str_and_dict()
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_koji_pathinfo.return_value.typedir.return_value = MODULES_PATH

    staged_module_source_path = os.path.join(default_config['stagedir'],
                                             branch,
                                             "modules",
                                             mmd_dict['name'][0],
                                             mmd_dict['name'],
                                             'fake-nvr',
                                             'checkout',
                                             'SOURCES',
                                             'modulemd.src.txt')

    assert_that(calling(main).with_args(options), exits(0))
    _, err = capsys.readouterr()

    assert_that(len(err), equal_to(0))
    assert_that(os.path.isfile(staged_module_source_path))
    remove_handlers()


@xfail(strict=True)
def test_push_to_pagure(config_file, key_file, pushdir, lookasidedir, capsys):

    rpm = 'grub2-2.02-0.64.el7.src.rpm'

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
        os.path.join(RPMS_PATH, rpm)
    ]

    CONFIG_DEFAULTS['pagure_repo_init_api'] = 'https://pagure_git_url/api/0/new'
    CONFIG_DEFAULTS['pagure_api_key_file'] = key_file

    def side_eff():
        # create dummy remote repo to succeed git calls
        cmd = ['git', 'init', '--bare', 'grub2.git']
        check_call(cmd, cwd=pushdir)
        return '{"message": "Project \\"rpms/grub2\\" created"}'

    with patch.dict("alt_src.alt_src.CONFIG_DEFAULTS", CONFIG_DEFAULTS):
        with patch("alt_src.alt_src.urlopen") as mock_resp:
            mock_resp.return_value.read.side_effect = side_eff
            # call main to push
            assert_that(calling(main).with_args(options), exits(0))
            mock_resp.assert_called_once()

    _, err = capsys.readouterr()
    assert_that(len(err), equal_to(0))

    # lookaside dir should have content
    lookaside = '%s/%s/%s' % (lookasidedir, 'grub2', 'c7')
    files = os.listdir(lookaside)
    assert_that(files, not_(empty()))
    remove_handlers()


@xfail(strict=True)
def test_push_module_to_pagure(config_file, key_file, pushdir, capsys,
                               mock_koji_session, mock_koji_pathinfo):
    """ verifies modules are pushed to pagure repo without any error """

    branch = 'c7'
    modulemd = 'fake-nvr:modulemd.src.txt'

    options = ['-v',
               '-c', config_file,
               '--koji',
               '--push',
               branch,
               modulemd
              ]

    mmd_str, mmd_dict = get_test_mmd_str_and_dict()
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_koji_pathinfo.return_value.typedir.return_value = MODULES_PATH

    CONFIG_DEFAULTS['pagure_repo_init_api'] = 'https://pagure_git_url/api/0/new'
    CONFIG_DEFAULTS['pagure_api_key_file'] = key_file

    def side_eff():
        # create dummy remote repo to succeed git calls
        cmd = ['git', 'init', '--bare', '%s.git' % mmd_dict['name']]
        check_call(cmd, cwd=pushdir)
        return '{"message": "Project \\"modules/%s\\" created"}' % mmd_dict['name']

    with patch.dict("alt_src.alt_src.CONFIG_DEFAULTS", CONFIG_DEFAULTS):
        with patch("alt_src.alt_src.urlopen") as mock_resp:
            mock_resp.return_value.read.side_effect = side_eff
            # call main to push
            assert_that(calling(main).with_args(options), exits(0))
            mock_resp.assert_called_once()

    _, err = capsys.readouterr()
    assert_that(len(err), equal_to(0))


@xfail(strict=True)
@pytest.mark.parametrize('cmd_args,package,expected_extra_dir', [
    ([os.path.join(RPMS_PATH, 'grub2-2.02-0.64.el7.src.rpm')], 'grub2', 'rpms'),
    (['--koji', 'fake-nvr:modulemd.src.txt'], 'my_package', 'modules'),
])
@patch("alt_src.alt_src.Stager.default_tries")
@patch("alt_src.alt_src.Stager.debrand")
@patch("alt_src.alt_src.Pusher.push_git")
@patch('os.path.isfile', side_effect=[True, True,] + 100*[False,])
def test_push_remote_not_exist(patched_isfile, patched_push_git, patched_debrand,
                               patched_default_tries, config_file, key_file,
                               pushdir, capsys, mock_koji_session,
                               mock_koji_pathinfo, default_config,
                               cmd_args, package, expected_extra_dir):

    patched_default_tries.return_value = 1

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
    ] + cmd_args

    mmd_str, _ = get_test_mmd_str_and_dict()
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_koji_pathinfo.return_value.typedir.return_value = MODULES_PATH

    CONFIG_DEFAULTS['pagure_repo_init_api'] = 'https://pagure_git_url/api/0/new'
    CONFIG_DEFAULTS['pagure_api_key_file'] = key_file

    def side_eff():
        # create dummy remote repo to succeed git calls
        cmd = ['git', 'init', '--bare', 'grub2.git']
        check_call(cmd, cwd=pushdir)
        return '{"message": "Project \\"rpms/grub2\\" created"}'

    exists_original = os.path.exists
    repo_dir = os.path.join(
        default_config['gitdir'],
        expected_extra_dir,
        "%s.git" % package
    )
    with patch("os.path.exists") as mocked_exists:
        mocked_exists.side_effect = exists_original
        with patch.dict("alt_src.alt_src.CONFIG_DEFAULTS", CONFIG_DEFAULTS):
            with patch("alt_src.alt_src.urlopen") as mock_resp:
                mock_resp.return_value.read.side_effect = side_eff
                main(options)
                repo_dir = os.path.join(
                    default_config['gitdir'],
                    expected_extra_dir,
                    "%s.git" % package
                )
                mocked_exists.assert_any_call(repo_dir)

    std, _ = capsys.readouterr()
    missing_repo_str="Remote repo is missing: %s" % (
        default_config['git_push_url'] % {"package": package},
    )
    assert missing_repo_str in std
    assert "Initializing new repo:" in std

@xfail(strict=True)
@pytest.mark.parametrize('cmd_args,package,expected_extra_dir', [
    ([os.path.join(RPMS_PATH, 'grub2-2.02-0.64.el7.src.rpm')], 'grub2', 'rpms'),
    (['--koji', 'fake-nvr:modulemd.src.txt'], 'my_package', 'modules'),
])
@patch("alt_src.alt_src.Pusher.push_lookaside")
@patch("alt_src.alt_src.Stager.import_sources")
@patch("alt_src.alt_src.BaseProcessor.log_cmd", return_value=0)
@patch("alt_src.alt_src.BaseProcessor.get_output")
@patch("alt_src.alt_src.BaseProcessor.default_tries")
@patch("alt_src.alt_src.Stager.debrand")
@patch("alt_src.alt_src.Pusher.push_git")
@patch('os.path.isfile', side_effect=[True, True,] + 100*[False, ])
def test_push_remote_exists(patched_isfile, patched_push_git, patched_debrand,
                            patched_default_tries, patched_get_output,
                            patched_log_cmd, patched_wipe_git_dir,
                            patched_push_lookaside,
                            config_file, key_file,
                            pushdir, capsys, mock_koji_session,
                            mock_koji_pathinfo, default_config,
                            cmd_args, package, expected_extra_dir):

    patched_default_tries.return_value = 1

    options = [
        '-v',
        '-c', config_file,
        '--push',
        'c7',
    ] + cmd_args

    def patched_get_output_sf(cmd, *args, **kwargs):
        if cmd[:2] == ["git", "ls-remote"]:
            ret = ("", 0)
        else:
            ret = patched_get_output.get_original()(cmd, *args, **kwargs)

        return ret

    patched_get_output.side_effect = patched_get_output_sf

    mmd_str, _ = get_test_mmd_str_and_dict()
    binfo = {'extra': {'typeinfo': {'module': {'modulemd_str': mmd_str}}}}
    mock_koji_session.return_value.getBuild.return_value = binfo
    mock_koji_pathinfo.return_value.typedir.return_value = MODULES_PATH

    CONFIG_DEFAULTS['pagure_repo_init_api'] = 'https://pagure_git_url/api/0/new'
    CONFIG_DEFAULTS['pagure_api_key_file'] = key_file

    exists_original = os.path.exists
    repo_dir = os.path.join(
        default_config['gitdir'],
        expected_extra_dir,
        "%s.git" % package
    )
    with patch("os.path.exists") as mocked_exists:
        mocked_exists.side_effect = exists_original
        with patch.dict("alt_src.alt_src.CONFIG_DEFAULTS", CONFIG_DEFAULTS):
            main(options)
            mocked_exists.assert_any_call(repo_dir)

    std, _ = capsys.readouterr()
    assert "Initializing new repo:" not in std


@xfail(strict=True)
def test_option_alias(config_file, pushdir, lookasidedir, default_config, capsys):

    rpm = 'grub2-2.02-0.64.el7'

    options = [
        '-c', config_file,
        '--brew',
        rpm,
        os.path.join(RPMS_PATH, rpm)
    ]

    with patch("alt_src.alt_src.setup_logging",
               side_effect=RuntimeError) as mocked_logging:
        try:
            main(options)
        except RuntimeError:
            pass
        assert hasattr(mocked_logging.mock_calls[0], 'koji')
