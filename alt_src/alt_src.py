#!/usr/bin/env python
'''
Given an srpm and product, stage for alt-src release
'''

import copy
import datetime
import errno
import fcntl
import fnmatch
import hashlib
import logging
from optparse import OptionParser
import os
import os.path
import re
import shutil
import simplejson as json
import six
from six.moves import configparser
from six.moves import cStringIO as StringIO
from six.moves.urllib.parse import urlencode
from six.moves.urllib.request import Request, urlopen
import smtplib
import subprocess
import sys
import time
import traceback
import yaml

import koji
import rpm

__all__ = ["main", "entry_point"]

CONFIG_DEFAULTS = {
    'stagedir': '/srv/cache/stage',
    'gitdir': '/srv/git',
    'rulesdir': '/var/lib/altsrc/rules',
    'debrand': True,
    'lookaside': '/srv/cache/lookaside',
    'git_push_url': '/srv/git/pushtest/%(package)s.git',
    'git_push_url_module': '/srv/git/pushtest-modules/%(package)s.git',
    'git_fetch_url': None,  # None means same as push
    'git_fetch_url_module': None,  # None means same as push
    'push_tags': True,
    'lookaside_rsync_dest': '/srv/cache/lookaside2',
    'log_level': 'INFO',
    'log_file': None,
    'log_format': '%(asctime)s [%(levelname)s] %(message)s',
    'whitelist': '',
    'blacklist': '',
    'commit_format': 'import %(nvr)s',
    'changelog_user': 'CentOS Sources <bugs@centos.org>',
    'git_name': 'CentOS Sources',
    'git_email': 'bugs@centos.org',
    'koji_hub': 'https://koji.fedoraproject.org/kojihub/',
    'koji_topdir': '/mnt/kojiroot/',
    'smtp_enabled': True,
    'smtp_host': 'localhost',
    'smtp_from': 'Alt Source Stager <altsrc@example.com>',
    'smtp_to': 'username',
    'smtp_log_to': '',
    'wait_time': 3600,
    'sleep_interval': 60,
    'pagure_api_key_file': None,
    'pagure_repo_init_api': None,
}

CONFIG_INT_OPTS = set([])
CONFIG_BOOL_OPTS = set(['smtp_enabled', 'push_tags', 'debrand'])


def get_config(cfile, overrides):
    if not os.access(cfile, os.F_OK):
        die("Missing config file: %s" % cfile)
    confp = configparser.RawConfigParser()
    confp.read(cfile)
    if not confp.has_section('altsrc'):
        die("Configuration file missing [altsrc] section: %s" % cfile)

    #apply overrides from command line
    overrides = overrides or []
    for opt in overrides:
        parts = opt.split("=", 1)
        if len(parts) != 2:
            die('Invalid option specification: %s\nUse OPT=VALUE' % opt)
        key, value = parts
        confp.set('altsrc', key, value)

    #generate config dictionary
    config = dict(CONFIG_DEFAULTS)  #copy
    for key in confp.options('altsrc'):
        if key in CONFIG_INT_OPTS:
            config[key] = confp.getint('altsrc', key)
        elif key in CONFIG_BOOL_OPTS:
            config[key] = confp.getboolean('altsrc', key)
        else:
            config[key] = confp.get('altsrc', key)

    #sanity checks
    if not os.path.isdir(config['stagedir']):
        die("No such directory: %s" % config['stagedir'])

    return config


class StageError(Exception):
    """Our base error class"""
    pass


class InputError(StageError):
    pass


class StartupError(StageError):
    """Raised when an error happens very early"""
    pass


class CommandError(StageError):
    """Raised when a command we run fails"""


class FilterError(StageError):
    pass


class SanityError(StageError):
    pass


class ConfigError(StageError):
    pass


class UntaggedDuplicate(Exception):
    """We use this to signal late duplicate detection"""


class BaseProcessor(object):

    def __init__(self, options):
        self.options = options
        self.logger = logging.getLogger("altsrc")
        self.error_log = None
        self.checkout = None
        self.git_auth_set = False

        self.mmd = None
        self.mmd_parsed = None
        self.src_mmd_parsed = None

        self.logfile = None
        self.workdir = None
        self.lock = None
        self.nvr = "UNKNOWN"
        self.package = "UNKNOWN"

        self.headers = None
        self.release = None
        self.version = None
        self.summary = None

        if self.options.koji:
            if self.options.source.endswith('modulemd.src.txt'):
                # expected source arg: <nvr>:module.src.txt
                self.nvr = self.options.source.rsplit(':', 1)[0]
                self.source_file, self.mmd = self.get_koji_module_src()
                self.rpms_or_module_dir = 'modules'

            elif self.options.source.endswith('src.rpm'):
                self.source_file = self.get_koji_srpm()
                self.rpms_or_module_dir = 'rpms'
            else:
                raise StartupError("Unsupported source: %s" % self.options.source)

        else:
            self.source_file = self.options.source
            self.rpms_or_module_dir = 'rpms'

        if not os.path.isfile(self.source_file):
            raise StartupError("No such file: %s" % self.source_file)

    def run(self):
        raise NotImplementedError

    def add_error_logger(self):
        """Capture all error messages for use in later notifications"""
        self.error_log = StringIO()
        handler = logging.StreamHandler(self.error_log)
        handler.setFormatter(logging.Formatter(self.options.config['log_format']))
        handler.setLevel(logging.ERROR)
        self.logger.addHandler(handler)

    def setup_logfile(self, logname):
        if not os.path.isdir(self.workdir):
            raise SanityError("Work dir does not exist: %s" % self.workdir)
        fname = fname_ = os.path.join(self.workdir, logname)
        ntimes = 0
        while os.path.exists(fname):
            # don't overwrite an old logfile
            ntimes += 1
            if ntimes > 1024:
                raise SanityError("Too many log backups")
            fname = "%s.%d" % (fname_, ntimes)
        self.logfile = open(fname, 'w')
        handler = logging.StreamHandler(self.logfile)
        handler.setFormatter(logging.Formatter(self.options.config['log_format']))
        handler.setLevel(self.options.file_log_level)
        self.logger.addHandler(handler)

    def default_tries(self, cmd):
        """Returns the default number of attempts for the given command"""
        if cmd[0] == 'rsync' or \
            (cmd[0] == 'git' and cmd[1] in ('fetch', 'push',
                                            'clone', 'ls-remote')):
            tries = 4
            self.logger.debug('Setting number of attempts to 4')
        else:
            tries = 1
        return tries

    def log_cmd(self, cmd, logfile=None, fatal=True, tries=None, **kwargs):
        """Run command and log output if able"""
        # check if the command is used to communicating with remote
        if not tries:
            tries = self.default_tries(cmd)

        self.logger.info('Running command: %s', ' '.join(cmd))
        if logfile:
            kwargs.setdefault('stdout', self.logfile)
            kwargs.setdefault('stderr', subprocess.STDOUT)
            kwargs.setdefault('close_fds', True)
        elif self.logfile:
            self.logfile.flush()
            kwargs.setdefault('stdout', self.logfile)
            kwargs.setdefault('stderr', subprocess.STDOUT)
            kwargs.setdefault('close_fds', True)

        fmt_command = 'Command %s failed, exit code: %s.'
        fmt_retries = 'Will retry in %ss [tried: %s/%s]'
        for i in range(1, tries+1):
            proc = subprocess.Popen(cmd, **kwargs)
            ret = proc.wait()
            if not ret:
                return ret
            elif ret and i < tries+1:
                sleep_time = i * 30
                self.logger.warn(' '.join([fmt_command, fmt_retries]),
                                 ' '.join(cmd), ret, sleep_time, i, tries)
                time.sleep(sleep_time)
        if ret:
            if fatal:
                raise CommandError(fmt_command % (' '.join(cmd), ret))
            #otherwise
            self.logger.warn(fmt_command, ' '.join(cmd), ret)
        return ret

    def get_output(self, cmd, fatal=True, **kwargs):
        """Run command and log output if able"""
        self.logger.info('Getting output from command: %s', ' '.join(cmd))
        kwargs['stdout'] = subprocess.PIPE
        kwargs.setdefault('close_fds', True)
        if 'stderr' in kwargs:
            # convenience values
            if kwargs['stderr'] == 'null':
                kwargs['stderr'] = open('/dev/null', 'w')
            elif kwargs['stderr'] == 'keep':
                kwargs['stderr'] = subprocess.STDOUT
        elif self.logfile:
            self.logfile.flush()
            kwargs['stderr'] = self.logfile
        proc = subprocess.Popen(cmd, universal_newlines=True, **kwargs)
        output = proc.communicate()[0]
        self.logger.debug("Command output was:\n%s", output)
        retval = proc.wait()
        if retval:
            self.logger.warn("Command failed: %r", cmd)
            if fatal:
                raise CommandError("command failed: %r" % cmd)
        return output, retval

    def _get_koji_session_and_pathinfo(self):
        session = koji.ClientSession(self.options.config['koji_hub'], {'anon_retry': True})
        pathinfo = koji.PathInfo(self.options.config['koji_topdir'])
        return session, pathinfo

    def get_koji_srpm(self):
        """Assume source is an n-v-r.a from koji and get the file from there"""
        session, pathinfo = self._get_koji_session_and_pathinfo()
        rpminfo = session.getRPM(self.options.source)
        if not rpminfo:
            raise SanityError("No such rpm: %s" % self.options.source)
        if rpminfo['arch'] != 'src':
            raise SanityError("Not a source rpm: %s" % self.options.source)
        binfo = session.getBuild(rpminfo['build_id'])
        bdir = pathinfo.build(binfo)
        relpath = pathinfo.rpm(rpminfo)
        return os.path.join(bdir, relpath)

    def get_koji_module_src(self):
        session, pathinfo = self._get_koji_session_and_pathinfo()
        binfo = session.getBuild(self.nvr)

        if binfo is None:
            raise SanityError("No such build %s:" % self.nvr)

        mmd = binfo['extra']['typeinfo']['module']['modulemd_str']
        return os.path.join(pathinfo.typedir(binfo, 'module'), 'modulemd.src.txt'), mmd

    def read_source_file(self):
        if self.mmd:
            self.read_mmd()
        else:
            self.read_srpm()

    def read_mmd(self):
        self.mmd_parsed = yaml.load(self.mmd, Loader=yaml.BaseLoader)
        module_data = self.mmd_parsed['data']
        fobj = open(self.source_file)
        try:
            self.src_mmd_parsed = yaml.load(fobj)
        finally:
            fobj.close()

        name = module_data['name']
        version = module_data['stream']
        release = '.'.join((str(module_data['version']), module_data['context']))

        self.package = name
        self.version = version
        self.release = release
        self.summary = module_data['summary']

    def read_srpm(self):
        self.logger.info('Reading source rpm: %s', self.source_file)
        headers = koji.get_rpm_header(self.source_file)
        self.headers = headers
        if headers[rpm.RPMTAG_SOURCEPACKAGE] != 1:
            raise InputError("%s is not a source package" % self.source_file)
        data = koji.get_header_fields(headers, ['name', 'version', 'release', 'summary'])
        self.nvr = "%(name)s-%(version)s-%(release)s" % data
        self.package = data['name']
        self.version = data['version']
        self.release = data['release']
        self.summary = data['summary']
        return self.headers

    def get_package_filter(self, pfilter):
        """Parse a black or white list filter and apply branch checks

        Return the part of the filter applicable to current branch
        """

        ret = []
        for rule in pfilter.split():
            parts = rule.split('::', 1)
            if len(parts) == 1:
                # no branch pattern
                ret.append(rule)
            elif fnmatch.fnmatch(self.options.branch, parts[0]):
                ret.append(parts[1])
        return ret

    def check_package(self):
        """Check whitelist/blacklist and load any package rules"""

        whitelist = self.get_package_filter(self.options.config['whitelist'])
        self.logger.debug("Got whitelist: %r", whitelist)
        if whitelist:
            whitelisted = koji.util.multi_fnmatch(self.package, whitelist)
        else:
            whitelisted = False
        if not whitelisted:
            blacklist = self.get_package_filter(self.options.config['blacklist'])
            self.logger.debug("Got blacklist: %r", blacklist)
            if blacklist and koji.util.multi_fnmatch(self.package, blacklist):
                # raise FilterError, 'Blacklisted package: %s' % self.package
                self.logger.info('Blacklisted package: %s, quitting' % self.package)
                sys.exit(0)

    def git_push_url(self):
        params = {'package': self.package}
        if self.mmd:
            git_url = self.options.config['git_push_url_module'] % params
        else:
            git_url = self.options.config['git_push_url'] % params
        return git_url

    def git_fetch_url(self):
        if self.mmd:
            url_form = (self.options.config['git_fetch_url_module']
                        or self.options.config['git_push_url_module'])
        else:
            url_form = (self.options.config['git_fetch_url']
                        or self.options.config['git_push_url'])

        params = {'package': self.package}
        git_url = url_form % params
        return git_url

    def git_base_cmd(self):
        if not self.git_auth_set:
            name, email = self.options.config['git_name'], self.options.config['git_email']
            os.environ['GIT_AUTHOR_NAME'] = name
            os.environ['GIT_COMMITTER_NAME'] = name
            os.environ['GIT_AUTHOR_EMAIL'] = email
            os.environ['GIT_COMMITTER_EMAIL'] = email
            self.git_auth_set = True
        return ['git', ]

    def get_workdir(self):
        if not os.path.isdir(self.options.config['stagedir']):
            raise SanityError("stagedir is missing: %s" % self.options.config['stagedir'])
        letter = self.package[0]
        if not letter.isalpha():
            letter = "_"
        parts = [
            os.path.join(self.options.config['stagedir']),
            self.options.branch,
            self.rpms_or_module_dir,
            letter,
            self.package,
            self.nvr,
        ]
        # branch included in the path because debranding rules can depend on it
        return os.path.join(*parts)

    # pylint: disable=unused-argument
    def find_spec(self, relative=False):
        """Locate specfile in checkout"""
        specdir = os.path.join(self.checkout, 'SPECS')

        #first look for $package.spec
        path = os.path.join(specdir, self.package + '.spec')
        if os.path.isfile(path):
            return path

        #otherwise
        for fname in os.listdir(specdir):
            if fname.endswith('.spec'):
                return os.path.join(specdir, fname)

        raise SanityError('No spec file in checkout: %s' % self.checkout)

    def duplicate_check(self):
        """Check to see if we're already on remote"""
        # XXX Currently mostly useless if push_tags is disabled
        # TODO rework this for a non-tagging workflow
        tagname = self.get_import_tagname()
        git_url = self.git_fetch_url()
        self.logger.debug("Checking remote %s for tag %s", git_url, tagname)
        self.logger.debug("Logfile is %r", self.logfile)
        cmd = ['git', 'ls-remote', git_url, "refs/tags/%s" % tagname]
        output, retval = self.get_output(cmd, stderr='null', fatal=False)
        if retval:
            # ignore for now. either repo is missing (ok) or network/server broken (we'll die later)
            self.logger.warning("Unable to check remote repo: %s", git_url)
            return False
        if output:
            self.logger.warning("Tag %s already present on remote", tagname)
            return True
            #TODO further verification
        return False

    def get_state(self):
        if not self.workdir:
            return None
        statefile = os.path.join(self.workdir, 'state')
        try:
            fobj = open(statefile, 'r')
        except IOError:
            _, err = sys.exc_info()[:2]
            if err.errno == errno.ENOENT:
                self.logger.debug('No state file at %s', statefile)
                return None
            raise
        self.logger.debug('Reading state file: %s', statefile)
        try:
            fcntl.lockf(fobj.fileno(), fcntl.LOCK_SH)
            state = fobj.read()
            self.logger.debug('Read state: %s', state)
        finally:
            fobj.close()
        return state.strip()

    def set_state(self, state):
        if not self.workdir:
            raise SanityError("No workdir to set state for")
        statefile = os.path.join(self.workdir, 'state')
        self.logger.debug('Writing state %s to file %s', state, statefile)
        fobj = open(statefile, 'w')
        try:
            fcntl.lockf(fobj.fileno(), fcntl.LOCK_EX)
            fobj.write(state)
        finally:
            fobj.close()
        return state

    def set_in_progress(self):
        """
        see if there's another task processing the current working directory by
        attempting to acquire the lock of 'lock' file, if failed, then wait for
        sleep_interval and re-try, the default longest waiting time is 60 mins.
        """
        lock_file_path = self.workdir + '.lock'
        wait_time = int(self.options.config['wait_time'])
        sleep_interval = int(self.options.config['sleep_interval'])
        self.logger.info('Setting current workdir to in progress')
        self.lock = acquire_lock(lock_file_path, wait_time, sleep_interval, self.logger)

    def sanitize_ref(self, ref):
        return '/'.join([self.sanitize_ref_segment(seg) for seg in ref.split('/')])

    # % is ok in refs, but we use it to escape the rest
    git_sanitize_re = (r'((?:^[.]'
                       r'|[.]$'
                       r'|[[:cntrl:]]'
                       r'|[ %~^:?*/\\[])+)')

    def sanitize_ref_segment(self, ref):
        """Sanitize a segment of a git reference

        Hex encodes any problematic character sequences
        See the git-check-ref-format man page for reference naming rules
        """
        prog = re.compile(self.git_sanitize_re)
        parts = []
        ofs = 0
        for match in prog.finditer(ref):
            index_a, index_b = match.span()
            parts.append(ref[ofs:index_a])
            part2 = ref[index_a:index_b]
            part2 = ''.join(['%%%2x' % ord(c) for c in part2])
            parts.append(part2)
            ofs = index_b
        parts.append(ref[ofs:]) #tail
        ref = ''.join(parts)
        # deal with multichar patterns
        ref = re.sub(r'[.][.]', '.%2e', ref)
        ref = re.sub(r'[.]lock$', '%2elock', ref)
        ref = re.sub(r'@{', '%40{', ref)
        return ref

    def get_import_tagname(self):
        safe_nvr = self.sanitize_ref_segment(self.nvr)
        tagname = "imports/%s/%s" % (self.options.branch, safe_nvr)
        return tagname

    def send_email_notice(self, level, subject, body, extra_headers=None):
        do_send = True
        if not self.options.config['smtp_enabled']:
            self.logger.warning("SMTP disabled. Skipping email notification.")
            do_send = False
            #return
        if level == 'info':
            recipients = self.options.config['smtp_log_to']
        else:
            recipients = self.options.config['smtp_to']
        if not recipients:
            self.logger.warning("No recipients configured. Skipping email notification.")
            do_send = False
            #return
        package = self.package or "UNKNOWN"
        headers = [
            ('From', self.options.config['smtp_from']),
            ('Subject', subject),
            ('To', recipients),
            ('X-altsrc-package', package),
        ]
        if extra_headers:
            headers.extend(extra_headers)

        head = "\n".join(["%s: %s" % (k, v) for k, v in headers])
        message = "%s\n\n%s" % (head, body)
        message.replace('\n', '\r\n')
        message = koji.fixEncoding(message)
        self.logger.debug("Email notice contents:\n%s\n", message)
        if not do_send:
            self.logger.debug("Email not sent")
            return
        server = smtplib.SMTP(self.options.config['smtp_host'])
        server.sendmail(self.options.config['smtp_from'], self.options.config['smtp_to'], message)
        server.quit()

    def notify_errors(self):
        """Send notification about non-fatal errors"""

        if not self.error_log:
            return
        error_messages = self.error_log.getvalue()
        if not error_messages:
            return
        self.logger.warning("Sending notification of non-fatal errors")
        nvr = self.nvr or "UNKNOWN"
        subject = 'Non-fatal errors for %s' % nvr
        body = "Errors:\n%s" % error_messages
        self.error_log.seek(0)
        self.error_log.truncate()
        #TODO : be more informative
        self.send_email_notice('error', subject, body)

    def handle_error(self):
        """Handle an exception. Called from top level."""
        tback = ''.join(traceback.format_exception(*sys.exc_info()))
        self.logger.exception('Staging failed')
        self.logger.warning("Sending error email")
        nvr = self.nvr or "UNKNOWN"
        subject = 'Error staging %s' % nvr
        body = """\
Staging failed for %(nvr)s.

%(tback)s
"""
        body = body % {"tback":tback, "nvr":nvr}
        #TODO : be more informative
        if self.error_log:
            error_messages = self.error_log.getvalue()
            if error_messages:
                body = "%s\nErrors:\n%s\n" % (body, error_messages)
                self.error_log.seek(0)
                self.error_log.truncate()

        self.send_email_notice('error', subject, body)
        if self.logfile:
            logfilename = getattr(self.logfile, 'name')
            if logfilename:
                self.logger.info("Logfile: %s", logfilename)

    def check_push_to_pagure(self):
        if self.options.config['pagure_repo_init_api']:
            return True
        return False

    def list_local_tags(self):
        cmd = self.git_base_cmd()
        cmd.extend(['tag', '-l'])
        out, _ = self.get_output(cmd, cwd=self.checkout)
        return out.split()

    def delete_local_tag(self, tag):
        cmd = self.git_base_cmd()
        cmd.extend(['tag', '-d', tag])
        self.log_cmd(cmd, cwd=self.checkout)


class Stager(BaseProcessor):
    MMD_DEBRAND_RTYPES = [
        "mmd"
    ]

    def __init__(self, options):
        self.branchname = None
        super(Stager, self).__init__(options)

    def run(self):
        self.add_error_logger()
        self.read_source_file()
        self.check_package()
        if self.duplicate_check() and not self.options.repush:
            self.logger.warning('Skipping staging for duplicate content')
            return
        if self.make_workdir() in ['STAGED', 'PUSHED']:
            return
        self.setup_logfile('stage.log')
        self.sync_repo()
        self.setup_checkout()
        #pylint: disable=broad-except
        try:
            self.import_sources()
        except UntaggedDuplicate:
            self.set_state('UNTAGGED')
            return
        try:
            self.debrand()
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception:
            self.logger.exception('Debranding failed')
            self.handle_debrand_fail()
        self.set_state("STAGED")
        self.notify()

    def make_workdir(self):
        self.workdir = dirname = self.get_workdir()
        koji.ensuredir(os.path.dirname(self.workdir))
        if os.path.islink(dirname):
            raise SanityError("%s is a symlink" % dirname)
        elif os.path.isdir(dirname):
            # TODO - more sanity checks
            self.set_in_progress()
            if self.options.restage:
                self.logger.warn("Overwriting existing workdir: %s", dirname)
                # TODO - back up first
                shutil.rmtree(dirname)
            else:
                state = self.get_state()
                if state == 'STAGED':
                    self.logger.warn("Already successfully staged: %s", dirname)
                    self.logger.info("Checkout to desired branch: %s", self.options.branch)
                    self.do_checkout()
                    return state
                elif state == 'PUSHED':
                    self.logger.warn("Already successfully pushed: %s", dirname)
                    return state
                else:
                    self.logger.warn("Incomplete staging dir %s (state=%s), \
will overwrite.", dirname, state)
                    shutil.rmtree(dirname)
        elif os.path.exists(dirname):
            raise SanityError("%s exists and is not a directory" % dirname)
        self.logger.info('Creating working directory: %s', dirname)
        koji.ensuredir(dirname)
        self.set_in_progress()
        return self.set_state("INIT")

    def sync_repo(self):
        """Sync the primary (bare) git repo from the (local) master"""

        repo = os.path.join(self.options.config['gitdir'], self.rpms_or_module_dir,
                            "%s.git" % self.package)

        if not os.path.exists(repo):
            self.init_repo()
            return

        # if our local copy exists, we assume that remote does as well

        git_url = self.git_fetch_url()
        self.logger.info('Syncing primary repo: %s', repo)
        cmd = ['git', 'fetch', '-v', git_url, '+refs/*:refs/*']
        try:
            self.log_cmd(cmd, cwd=repo)
        except Exception:
            self.logger.error('Unable to fetch remote repo')
            self.logger.error('Local cache exists: %s', repo)
            raise

        # TODO - add sanity checks

    def init_repo(self):
        """Initialize a new repo"""
        # check if repo exists on remote
        git_url = self.git_fetch_url()
        self.logger.info("Checking if remote repo exists: %s", git_url)
        cmd = ['git', 'ls-remote', git_url, "refs/heads/master"]
        _, retval = self.get_output(cmd, fatal=False)
        if retval:
            # error talking to remote
            # for now, we assume this means the remote does not exist
            #TODO distinguish this from other errors (e.g. network)
            self.logger.warning("Remote repo is missing: %s", git_url)
            self.init_new_repo()
            return
        # otherwise we just need to clone it
        git_dir = os.path.join(self.options.config['gitdir'], self.rpms_or_module_dir)
        koji.ensuredir(git_dir)
        cmd = ['git', 'clone', '--bare', git_url, "%s.git" % self.package]
        self.log_cmd(cmd, cwd=git_dir)

    gitblit_config_format = r'''
[gitblit]
        description = %(summary)s
        owner = kbsingh
        useTickets = false
        useDocs = false
        accessRestriction = PUSH
        showRemoteBranches = false
        isFrozen = false
        showReadme = true
        skipSizeCalculation = false
        skipSummaryMetrics = false
        federationStrategy = FEDERATE_THIS
        isFederated = false
'''

    def init_new_repo(self):
        initdir = os.path.join(self.workdir, "repo_init")
        self.logger.info('Initializing new repo: %s', initdir)
        koji.ensuredir(initdir)
        cmd = ['git', 'init']
        self.log_cmd(cmd, cwd=initdir)
        readme = os.path.join(initdir, 'README.md')
        fobj = open(readme, 'w')
        # XXX this text need to live elsewhere
        fobj.write('''\
The master branch has no content

Look at the c7 branch if you are working with CentOS-7, or the c4/c5/c6 branch for CentOS-4, 5 or 6
If you find this file in a distro specific branch, it means that no content has been checked in yet
''')
        fobj.close()
        cmd = ['git', 'add', 'README.md']
        self.log_cmd(cmd, cwd=initdir)
        cmd = self.git_base_cmd()
        cmd.extend(['commit', '-m', 'init git for %s' % self.package])
        self.log_cmd(cmd, cwd=initdir)
        branches = self.options.config.get('init_branches')
        if branches:
            for distbranch in branches:
                cmd = ['git', 'branch', distbranch]
                self.log_cmd(cmd, cwd=initdir)
        #finally create a bare repo from our working copy
        cmd = ['git', 'clone', '--bare', initdir, "repo_init.git"]
        self.log_cmd(cmd, cwd=self.workdir)
        descfile = os.path.join(self.workdir, "repo_init.git", "description")
        fobj = open(descfile, 'w')
        fobj.write(self.summary)
        fobj.write('\n')
        fobj.close()
        if not self.check_push_to_pagure():
            # add gitblit options to git config
            # XXX this content should not be hard coded
            git_config = os.path.join(self.workdir, "repo_init.git", "config")
            fobj = open(git_config, 'a')
            params = {
                'summary' : self.summary,
                'package' : self.package,
                # anything else?
            }
            fobj.write(self.gitblit_config_format % params)

    def setup_checkout(self):
        """Setup our working checkout"""

        src = os.path.join(self.options.config['gitdir'],
                           self.rpms_or_module_dir, "%s.git" % self.package)
        if not os.path.exists(src):
            # should be new repo case
            src = os.path.join(self.workdir, "repo_init.git")
        dst = os.path.join(self.workdir, "checkout")
        cmd = ['git', 'clone', '--local', '-v', src, dst]
        self.log_cmd(cmd, cwd=self.workdir)
        self.do_checkout(new_branch=True)

        self.set_state("CHECKOUT")

    def do_checkout(self, new_branch=False):
        #create and checkout our staging branch
        dst = os.path.join(self.workdir, "checkout")
        self.checkout = dst
        self.logger.info('Setting up working checkout: %s', dst)
        branchname = "altsrc-stage-%s" % self.options.branch
        branchname = self.sanitize_ref_segment(branchname)
        self.branchname = branchname
        if new_branch:
            base = 'refs/remotes/origin/%s' % self.options.branch
            self.logger.info('Setting up staging branch: %s', branchname)
            cmd = ['git', 'show-ref', '--verify', base]
            retval = self.log_cmd(cmd, cwd=dst, fatal=False)
            if retval:
                self.logger.warn('Base branch %s missing, staging on an orphan branch', self.options.branch)
                # create new branch
                cmd = ['git', 'checkout', '-b', branchname]
                retval = self.log_cmd(cmd, cwd=dst, fatal=False)
                if retval:
                    # commit for branch initialization
                    # on error when switching with empty HEAD/unborn branch
                    cmd = ['git', 'commit', '--allow-empty', '-m', 'init_branch']
                    self.log_cmd(cmd, cwd=dst)
                    # switch to new branch
                    cmd = ['git', 'checkout', '-b', branchname]
                    self.log_cmd(cmd, cwd=dst)
                # orphan the branch (remove parent)
                cmd = ['git', 'update-ref', '-d', 'refs/heads/%s' % branchname]
                self.log_cmd(cmd, cwd=dst)
                # remove staged files
                cmd = ['git', 'rm', '-rf', '--ignore-unmatch', '.']
                self.log_cmd(cmd, cwd=dst)

            else:
                cmd = ['git', 'checkout', '-b', branchname, base]
                self.log_cmd(cmd, cwd=dst)
        # the branch could be existed, if the task failed at push_git in Pusher class
        else:
            cmd = ['git', 'checkout', branchname]
            self.log_cmd(cmd, cwd=dst)

    # file extensions that are automatically placed in lookaside
    # (should all be lower case)
    UPLOAD_EXTS = [
        'tar', 'gz', 'bz2', 'lzma', 'xz', 'z', 'zip', 'tff',
        'bin', 'tbz', 'tbz2', 'tgz', 'tlz', 'txz', 'pdf', 'rpm',
        'jar', 'war', 'db', 'cpio', 'jisp', 'egg', 'gem', 'iso',
        ]

    # file extensions that are automatically included in repo
    # (should all be lower case)
    INCLUDE_EXTS = [
        'spec', 'patch', 'diff',
        'html', 'txt', 'init', 'conf', 'sh',
        ]

    def for_lookaside(self, path):
        """Determine if a file should go to the lookaside cache

        Return True if file should go to the lookaside
        """
        # there are varying heuristics for what to place in the lookaside
        # Fedora/pyrpkg decides based on extension
        # Centos/nazar decides based on output of the file utility
        # We're using a hybrid approach
        ext = path.rsplit('.')[-1].lower()
        if ext in self.INCLUDE_EXTS:
            return False
        if ext in self.UPLOAD_EXTS:
            return True
        fstat = os.stat(path)
        if fstat.st_size < 1024:
            # the UPLOAD_EXTS check should catch most of what we want in
            # the lookaside, so we'll just include anything small
            return False
        #lastly, see what the file utility says
        cmd = ['file', '--brief', path]
        output, retval = self.get_output(cmd, stderr='keep', fatal=False)
        if retval:
            #nonfatal
            return False
        self.logger.debug("Source file %s: %s", path, output)
        return output.find('text') == -1

    def import_sources(self):
        """Import our source srpm/modulemd on the specified branch"""
        # clear our checkout dir
        dst = self.checkout
        wipe_git_dir(dst)
        # confirm that the directory is wiped, because in the duplicate check
        # below, we want to be sure that the duplicate content really came
        # from our exploded srpm
        for fname in os.listdir(dst):
            if fname != '.git':
                raise SanityError('Failed to clear checkout')
        sourcedir = os.path.join(dst, 'SOURCES/')
        if self.mmd:
            # move module src to stage dir
            os.makedirs(sourcedir)
            shutil.copy(self.source_file, os.path.join(sourcedir))
        else:
            # explode our srpm
            self.logfile.flush()
            explode_srpm(self.source_file, dst, logfile=self.logfile)

        #figure out which sources go to the lookaside
        to_move = []
        for fname in os.listdir(sourcedir):
            path = os.path.join(sourcedir, fname)
            if self.for_lookaside(path):
                to_move.append(fname)
        to_move.sort()

        # move files to lookaside
        meta = open(os.path.join(dst, ".%s.metadata" % self.package), 'w')
        gitignore = open(os.path.join(dst, ".gitignore"), 'w')
        for fname in to_move:
            path = os.path.join(sourcedir, fname)
            digest = self.get_digest(path)
            self.copy_to_lookaside(path, digest)
            if not self.options.keep_sources:
                os.unlink(path)
            # write metadata file
            meta.write("%s SOURCES/%s\n" % (digest, fname))
            # write .gitignore
            gitignore.write('SOURCES/%s\n' % fname)
        meta.close()
        gitignore.close()

        cmd = ['git', 'add', '-A', '.']
        self.log_cmd(cmd, cwd=dst)

        # see if we have anything to commit
        cmd = ['git', 'diff', '--cached', '--name-only']
        output, _ = self.get_output(cmd, cwd=dst, stderr='keep', fatal=False)
        if not output:
            # This means our exploded srpm matched the last commit exactly
            cmd = self.git_base_cmd() + ['show', '-s', '--format=%h %s']
            output, _ = self.get_output(cmd, cwd=dst, stderr='keep', fatal=False)
            self.logger.warning('Source matches last commit: %s', output)
            raise UntaggedDuplicate

        cmd = self.git_base_cmd()
        msg_data = koji.util.dslice(vars(self), ['nvr', 'package', 'version', 'release', 'summary'])
        msg_data['branch'] = self.options.branch
        commit_msg = self.options.config['commit_format'] % msg_data
        cmd.extend(['commit', '-m', commit_msg])
        self.log_cmd(cmd, cwd=dst)
        self.set_state("IMPORT")

        #tag this import for reference
        #this is not the tag we will actually push because of the rebase
        tagname = "altsrc-stage-import-%s" % self.options.branch
        tagname = self.sanitize_ref_segment(tagname)
        cmd = ['git', 'tag', tagname]
        self.log_cmd(cmd, cwd=self.checkout)

    def get_digest(self, path):
        """Calculate hex digest for file"""

        csum = hashlib.sha1()
        fobj = open(path, 'rb')
        chunk = 'IGNORE ME!'
        while chunk:
            chunk = fobj.read(8192)
            csum.update(chunk)
        fobj.close()
        return csum.hexdigest()

    def copy_to_lookaside(self, path, digest):
        """Copy file to lookaside"""

        dirname = os.path.join(self.options.config['lookaside'], self.package, self.options.branch)
        lpath = os.path.join(dirname, digest)
        if not os.path.isfile(lpath):
            koji.ensuredir(dirname)
            self.logger.info('Copying source file to lookaside: %s -> %s', path, lpath)
            shutil.copy2(path, lpath)
        else:
            # we appear to already have it
            st1 = os.stat(path)
            st2 = os.stat(lpath)
            if st1.st_size != st2.st_size:
                self.logger.error("Possibly corrupt lookaside entry: %s", lpath)
                self.logger.error("Size: %s, but current matching source is %s", st1.st_size, st2.st_size)
                raise SanityError("Lookaside size mismatch")
            # TODO - more sanity checks
            self.logger.info('Skipping source, already in digest: %s', path)

    def debrand(self):
        """Apply debranding rules"""
        #search for applicable rules

        if not self.options.config['debrand']:
            self.logger.warning("Debranding is disabled")
            return
        confp = configparser.RawConfigParser()
        for name in 'altsrc-global', self.package:
            cfile = os.path.join(self.options.config['rulesdir'], name + '.cfg')
            self.logger.debug('Looking for rules in %s', cfile)
            if not os.access(cfile, os.F_OK):
                continue
            self.logger.info('Loading rules from %s', cfile)
            confp.read(cfile)

        # order rules
        rules = []
        for section in confp.sections():
            parts = section.split(None, 1)
            if len(parts) < 2:
                continue
            rtype, key = parts
            if self.mmd:
                if rtype in self.MMD_DEBRAND_RTYPES:
                    rules.append((key, rtype, section))
            else:
                if rtype not in self.MMD_DEBRAND_RTYPES:
                    rules.append((key, rtype, section))
        rules.sort()

        if not rules:
            self.logger.info('No debranding rules found')
            return

        # apply rules
        changelog_notes = []
        for key, rtype, section in rules:
            handler = 'rule_handler_%s' % rtype
            if not hasattr(self, handler):
                raise ConfigError("No handler for rule type %s" % rtype)
            data = dict(confp.items(section))
            if 'enabled' in data:
                enabled = data['enabled'].lower().strip()
                if enabled in ('no', 'false', '0'):
                    self.logger.info('Skipping disabled rule: %s', section)
                    continue
            if 'on_package' in data:
                patterns = data['on_package'].split()
                if not koji.util.multi_fnmatch(self.package, patterns):
                    self.logger.debug('Skipping rule due to package filter: %s', section)
                    continue
            if 'on_version' in data:
                patterns = data['on_version'].split()
                if not koji.util.multi_fnmatch(self.version, patterns):
                    self.logger.debug('Skipping rule due to version filter: %s', section)
                    continue
            if 'on_branch' in data:
                patterns = data['on_branch'].split()
                if not koji.util.multi_fnmatch(self.options.branch, patterns):
                    self.logger.debug('Skipping rule due to branch filter: %s', section)
                    continue
            self.logger.info("Applying rule: %s", section)
            clog_note = data.get('changelog')
            if clog_note:
                changelog_notes.append(clog_note)
            can_fail = False
            if data.get('can_fail', '').lower() in ('yes', 'y', '1', 'true'):
                can_fail = True
            #pylint: disable=broad-except
            try:
                getattr(self, handler)(data)
                # TODO - check result
            except (SystemExit, KeyboardInterrupt):
                raise
            except Exception:
                self.logger.exception('Failed to apply debranding rule (%s: %s) to %s',
                        rtype, key, self.nvr)
                if not can_fail:
                    # caller will handle
                    raise

        #see if any new sources need to go to the lookaside
        cmd = ['git', 'ls-files', '--exclude-standard', '--others']
        output, _ = self.get_output(cmd, cwd=self.checkout)
        for_lookaside = []
        if output:
            self.logger.info('New files added:\n%s', output)
            for fname in output.splitlines():
                path = os.path.join(self.checkout, fname)
                if self.for_lookaside(path):
                    for_lookaside.append(fname)
        if for_lookaside:
            meta = open(os.path.join(self.checkout, ".%s.metadata" % self.package), 'a')
            gitignore = open(os.path.join(self.checkout, ".gitignore"), 'a')
            for fname in for_lookaside:
                path = os.path.join(self.checkout, fname)
                digest = self.get_digest(path)
                self.copy_to_lookaside(path, digest)
                if not self.options.keep_sources:
                    os.unlink(path)
                meta.write("%s %s\n" % (digest, fname))
                gitignore.write('%s\n' % fname)
            meta.close()
            gitignore.close()


        # and commit changes
        cmd = ['git', 'add', '-A', '.']
        self.log_cmd(cmd, cwd=self.checkout)

        # write out changelog for later
        # we'll update the date and add to spec at push time
        self.prep_changelog(changelog_notes)

        # check that we actually have something to commit
        cmd = ['git', 'diff', '--cached', '--name-only']
        output, _ = self.get_output(cmd, cwd=self.checkout, stderr='keep', fatal=False)
        if not output:
            raise SanityError("Debranding rules made no changes")
            # caller will clean up

        cmd = self.git_base_cmd()
        cmd.extend(['commit', '-m', 'debranding changes'])
        self.log_cmd(cmd, cwd=self.checkout)
        self.set_state("DEBRAND")

    def handle_debrand_fail(self):
        """If debranding fails, clean up and note failure"""

        self.logger.warning("Resetting checkout to import")
        tagname = "altsrc-stage-import-%s" % self.options.branch
        tagname = self.sanitize_ref_segment(tagname)
        self.logger.info("Logging changes to be reverted")
        self.log_cmd(['git', 'diff', '-a', tagname], cwd=self.checkout)
        cmd = ['git', 'reset', '--hard', "refs/tags/%s" % tagname]
        self.log_cmd(cmd, cwd=self.checkout)
        cmd = ['git', 'clean', '-f']
        self.log_cmd(cmd, cwd=self.checkout)

        self.logger.warning("Adding debranding failure notice")
        fname = os.path.join(self.checkout, "README.debrand")
        fobj = open(fname, 'w')
        fobj.write('''\
Warning: This package was configured for automatic debranding, but the changes
failed to apply.
''')
        fobj.close()
        cmd = ['git', 'add', 'README.debrand']
        self.log_cmd(cmd, cwd=self.checkout)
        #and commit
        cmd = self.git_base_cmd()
        cmd.extend(['commit', '-m', 'Debranding failure notice'])
        self.log_cmd(cmd, cwd=self.checkout)

    def prep_changelog(self, notes):
        """Generate changelog info"""
        if self.mmd:
            # for modules, nothing to do
            return
        self.logger.info('Preparing changelog entry')
        user = self.options.config['changelog_user']
        verrel = self.get_modded_verrel()
        #now = datetime.datetime.now().strftime('%a %b %d %Y')
        parts = ['* INSERT_DATE_HERE %s - %s\n' % (user, verrel)]
        if not notes:
            parts.append('- Apply debranding changes\n')
        for note in notes:
            lineno = 0
            for line in note.splitlines():
                line = line.strip()
                if line:
                    lineno += 1
                    if lineno == 1:
                        parts.append('- %s\n' % line)
                    else:
                        parts.append('-  %s\n' % line)
        fobj = open(os.path.join(self.workdir, 'changelog.txt'), 'w')
        for part in parts:
            fobj.write(part)
            self.logger.debug("%s", part)
        fobj.close()

    def get_modded_verrel(self):
        spec = self.find_spec()
        macros = self.get_mod_macros()
        cmd = ['rpm', '-q', '--specfile', spec,
                '--define', '_topdir %s' % self.checkout]
        for macro in macros:
            cmd.extend(['--define', '%s %s' % (macro, macros[macro])])
        cmd.extend([
               '--qf', '%{v}-%{r}\\n'])
        output, _ = self.get_output(cmd, cwd=self.checkout)
        verrel = output.splitlines()[0]
        return verrel

    branch_re = r'^c([3456789])(?:-.*)?$'
    dist_re = r'[.]el([3456789])(?:_[0-9]+)?'

    def get_mod_macros(self):
        # try to determine from branch name
        prog = re.compile(self.branch_re)
        macro = prog.match(self.options.branch)
        if macro:
            rhel = macro.group(1)
            return {
                'dist' : ".el%s.centos" % rhel,
                'rhel' : rhel,
            }
        # try to determine from dist tag
        prog = re.compile(self.dist_re)
        macro = prog.search(self.release)
        if macro:
            rhel = macro.group(1)
            return {
                'dist' : ".el%s.centos" % rhel,
                'rhel' : rhel,
            }
        #otherwise...
        return {
            "dist" : ".centos",
            "rhel" : "7",
            # some specs will fail without a rhel macro
            }

    def rule_handler_spec(self, data):
        """Patch the spec file"""

        spec_patch = os.path.join(self.options.config['rulesdir'], data['patch'])
        specfile = self.find_spec()
        cmd = ['patch', '-r', '-', '--no-backup-if-mismatch', specfile, spec_patch]
        # TODO more options
        self.log_cmd(cmd, cwd=self.checkout)

    def rule_handler_simplepatch(self, data):
        """Just apply a patch to the checkout"""

        patchfile = os.path.join(self.options.config['rulesdir'], data['patch'])
        strip = int(data.get('strip', '1'))
        cmd = ['patch', '-r', '-', '--no-backup-if-mismatch', '-p%i' % strip, '-i', patchfile]
        if 'fuzz' in data:
            fuzz = int(data['fuzz'])
            cmd.extend(['-F', fuzz])
        self.log_cmd(cmd, cwd=self.checkout)

    def rule_handler_re(self, data):
        """Apply a regex substitution to the spec file"""

        if data.get('mode') == 'line':
            self.handle_re_line(data)
        if 'file' in data:
            fname = os.path.join(self.checkout, data['file'])
        else:
            fname = self.find_spec()
        fobj = open(fname, 'r')
        text = fobj.read()
        fobj.close()
        count = int(data.get('count', '0'))
        if count:
            text = re.sub(data['match'], data['replace'], text, count)
        else:
            text = re.sub(data['match'], data['replace'], text)
        fobj = open(fname, 'w')
        fobj.write(text)
        fobj.close()

    def rule_handler_mmd(self, data):
        src_mmd_parsed_copy = copy.deepcopy(self.src_mmd_parsed)
        stack = [(src_mmd_parsed_copy, [src_mmd_parsed_copy],
                  0, data["yaml_path"].split("\n"))]
        while stack:
            current_data, parent, parent_key, matching_path = stack.pop(0)
            if not matching_path:
                continue

            gen = None
            if isinstance(current_data, list):
                gen = enumerate(current_data)
            elif isinstance(current_data, dict):
                gen = list(current_data.items())
            if gen:
                for key, val in gen:
                    if re.match(matching_path[0], str(key)):
                        stack.append((val, current_data, key, matching_path[1:]))

            if isinstance(current_data, six.string_types):
                replaced = re.sub(matching_path[0],
                                  data['replace'],
                                  current_data)
                parent[parent_key] = replaced
        fobj = open(os.path.join(self.checkout,
                              "SOURCES",
                              os.path.basename(self.source_file)), "w")
        try:
            yaml.dump(src_mmd_parsed_copy, fobj)
        finally:
            fobj.close()

    def handle_re_line(self, data):
        if 'file' in data:
            fname = os.path.join(self.checkout, data['file'])
        else:
            fname = self.find_spec()
        self.logger.info('Applying regex substitutions to %s', fname)
        fobj = open(fname, 'r')
        lines = fobj.readlines()
        fobj.close()
        prog = re.compile(data['match'])
        count = int(data.get('count', '0'))
        # count is how many replacements to make, zero means unlimited
        n_match = 0
        for lineno, line in enumerate(lines):
            if count:
                remain = count - n_match
                if remain <= 0:
                    break
                line2, total = prog.subn(data['replace'], line, remain)
            else:
                line2, total = prog.subn(data['replace'], line)
            n_match += total
            if total > 0:
                self.logger.debug("Replacing line %i:\n-%s+%s", lineno, line, line2)
                lines[lineno] = line2
        if n_match > 0:
            self.logger.info('Replaced %i lines', n_match)
        else:
            self.logger.error('No matches for pattern %r', prog.pattern)
        # write it back out
        fobj = open(fname, 'w')
        fobj.writelines(lines)
        fobj.close()

    def rule_handler_patch(self, data):
        """Add or remove a patch in the spec file"""

        method = data['method'].lower()
        if method == 'add':
            self.handle_add_patch(data)

        elif method == 'del':
            self.handle_rm_patch(data)

    def handle_add_patch(self, data):
        """Add a patch in the spec file"""

        patchfile = os.path.join(self.options.config['rulesdir'], data['patch'])
        patchname = os.path.basename(patchfile)
        patchnum = int(data.get('num', '-1'))
        patchstrip = int(data.get('strip', '1'))
        self.logger.debug("Adding patch: %r", data)
        specfile = self.find_spec()
        fobj = open(specfile, 'r')
        lines = fobj.readlines()
        fobj.close()
        # find highest patch number and last patch line location
        patch_re = re.compile(r'^\s*([pP]atch)(\d*):(\s+)(\S+)\s*$')
        alt_re = re.compile(r'(?i)^\s*(?:name|version|release|source\d*):\s+')
        pnum = -1
        lnum = -1
        l_alt = -1
        patch_tag = 'Patch'
        patch_sep = '\t'
        for lineno, line in enumerate(lines):
            match = patch_re.search(line)
            if match:
                lnum = lineno
                patch_tag = match.group(1)
                pnum = max(pnum, int(match.group(2) or "0"))
                patch_sep = match.group(3)
                # unnumbered patch equivalent to zero
                # http://www.rpm.org/max-rpm/s1-rpm-inside-tags.html
                if patchnum == pnum:
                    self.logger.error("Patch %s already present: %s", patchnum, line)
                    raise SanityError("Duplicate patch number")
            elif alt_re.search(line):
                l_alt = lineno
        if patchnum == -1:
            if lnum == -1:
                # no existing patches
                patchnum = 1
            else:
                patchnum = pnum + 1
        if lnum == -1:
            lnum = l_alt

        # insert the PatchNN entry
        entry = "%s%d:%s%s\n"  % (patch_tag, patchnum, patch_sep, patchname)
        self.logger.debug("Inserting spec line: %i: %s", lnum+1, entry)
        lines.insert(lnum + 1, entry)

        # copy the patch file
        self.copy_new_source(patchfile)

        # add the entry for applying
        if data.get('apply', '') == 'kernel-optional':
            entry = "ApplyOptionalPatch %s\n"  % patchname
            apply_re = re.compile(r'^\s*ApplyOptionalPatch\s+\w')
            setup_re = re.compile(r'\s*%setup\b')
            alt_re = re.compile(r'Any further pre-build tree manipulations happen here')
            lnum = -1
            for lineno, line in enumerate(lines):
                if apply_re.search(line):
                    lnum = lineno
                elif lnum < 0 and setup_re.search(line):
                    lnum = lineno
                elif lnum < 0 and alt_re.search(line):
                    lnum = lineno
            if lnum > -1:
                # after last ApplyOptionalPatch line
                lines.insert(lnum + 1, entry)
                self.logger.debug("Inserting spec line: %i: %s", lnum+1, entry)
            else:
                raise SanityError("Unable to apply patch %s" % patchname)
        elif data.get('apply', 'y').lower() in ('y', 'yes', '1', 'true'):
            entry = "%%patch%d -p%d\n" % (patchnum, patchstrip)
            apply_re = re.compile(r'^\s*%patch\d+\s+-p\d')
            auto_re = re.compile(r'^\s*%autosetup\b')
            setup_re = re.compile(r'\s*%setup\b')
            lnum = -1
            lsetup = -1
            auto = False
            for lineno, line in enumerate(lines):
                if apply_re.search(line):
                    lnum = lineno
                elif auto_re.search(line):
                    auto = True
                elif lsetup < 0 and setup_re.search(line):
                    lsetup = lineno
            if lnum > -1:
                # after last %patch line
                lines.insert(lnum + 1, entry)
                self.logger.debug("Inserting spec line: %i: %s", lnum+1, entry)
            elif auto:
                # TODO add a flag to indicate this is expected
                self.logger.warning('Patches appear to be applied by %%autosetup. Omitting %patch entry')
            elif lsetup > -1:
                # after first %setup line
                lines.insert(lsetup + 1, entry)
                self.logger.debug("Inserting spec line: %i: %s", lsetup+1, entry)
            else:
                raise SanityError("Unable to apply patch %s" % patchname)

        # write it back out
        fobj = open(specfile, 'w')
        fobj.writelines(lines)
        fobj.close()

    def copy_new_source(self, path):
        """Copy a new source file into checkout source dir"""
        sourcedir = os.path.join(self.checkout, 'SOURCES')
        name = os.path.basename(path)
        dest = os.path.join(sourcedir, name)
        if os.path.isfile(dest):
            self.logger.error("Source already present, overwriting: %s", dest)
            os.remove(dest)
        self.logger.debug("Copy %s -> %s", path, sourcedir)
        shutil.copy2(path, sourcedir)

    def handle_rm_patch(self, data):
        """Remove specified patch from spec"""

        patchnum = data.get('num')
        patchname = None
        if 'patch' in data:
            patchname = os.path.basename(data['patch'])
            patch_re = re.compile(r'^\s*[pP]atch(\d+):\s+(' + patchname + r')\s*$')
        elif patchnum != None:
            patch_re = re.compile(r'^\s*[pP]atch(' + str(patchnum) + r'):\s+(\S+?)\s*$')
        else:
            self.logger.error('No patch specified for removal')
            raise SanityError('Invalid rule')

        specfile = self.find_spec()
        fobj = open(specfile, 'r')
        lines = fobj.readlines()
        fobj.close()

        # find PatchNN line
        lineno = None
        for lineno, line in enumerate(lines):
            match = patch_re.search(line)
            if match:
                patchnum = match.group(1)
                patchname = match.group(2)
                break
        else:
            self.logger.error("No match for pattern: %r", patch_re.pattern)
            raise SanityError("Could not find patch to remove")
        # remove the matching line
        if lineno:
            del lines[lineno]

        # also remove the line that applies the patch
        apply_re = re.compile(r'^\s*%patch' + patchnum + r'(?:\D.*)?$')
        setup_re = re.compile(r'^\s*%autosetup\b')
        auto = False
        for lineno, line in enumerate(lines):
            if apply_re.search(line):
                del lines[lineno]
                break
            elif not auto and setup_re.search(line):
                auto = True
        else:
            if auto:
                # TODO add a flag to indicate this is expected
                self.logger.warning('Patch %s appears to be applied by %%autosetup', patchname)
            else:
                self.logger.error('No %%patch line for patch %s', patchname)
                raise SanityError("Unable to remove patch")

        # write it back out
        fobj = open(specfile, 'w')
        fobj.writelines(lines)
        fobj.close()

    def rule_handler_source(self, data):
        """Add a source to the specfile"""

        method = data['method'].lower()
        if method == 'add':
            self.handle_add_source(data)
        elif method == 'replace':
            self.handle_replace_source(data)
        #XXX support del?
        else:
            self.logger.error('Unknown source rule method: %s', method)
            raise ConfigError('Invalid method in source rule')

    def handle_add_source(self, data):
        """Add a source entry in spec file"""

        sourcenum = int(data.get('num', '-1'))
        sourcefile = os.path.join(self.options.config['rulesdir'], data['source'])
        sourcename = os.path.basename(sourcefile)
        specfile = self.find_spec()
        fobj = open(specfile, 'r')
        lines = fobj.readlines()
        fobj.close()

        source_re = re.compile(r'^\s*[sS]ource(\d*):\s+(\S+)\s*$')
        name_re = re.compile(r'^\s*[nN]ame:\s+')
        snum = -1
        lnum = -1
        lname = -1
        for lineno, line in enumerate(lines):
            match = source_re.search(line)
            if match:
                lnum = lineno
                snum = max(snum, int(match.group(1) or "0"))
                # unnumbered source equivalent to zero
                # http://www.rpm.org/max-rpm/s1-rpm-inside-tags.html
                if sourcenum == snum:
                    self.logger.error("Source %s already present: %s", sourcenum, line)
                    raise SanityError("Duplicate source number")
            elif name_re.search(line):
                lname = lineno
        if sourcenum == -1:
            if lnum == -1:
                # no existing sources
                sourcenum = 1
            else:
                sourcenum = snum + 1
        if lnum == -1:
            lnum = lname

        # insert the SourceNN entry
        entry = "Source%d:\t%s\n" % (sourcenum, sourcename)
        lines.insert(lnum + 1, entry)

        # copy source file
        self.copy_new_source(sourcefile)

        # write it back out
        fobj = open(specfile, 'w')
        fobj.writelines(lines)
        fobj.close()

    def handle_replace_source(self, data):
        """Replace a source entry in spec file"""

        sourcefile = os.path.join(self.options.config['rulesdir'], data['source'])
        sourcename = os.path.basename(sourcefile)
        specfile = self.find_spec()
        fobj = open(specfile, 'r')
        lines = fobj.readlines()
        fobj.close()

        # find the original source entry
        if 'num' in data:
            num = int(data['num'])
            source_re = re.compile(r'^(\s*[sS]ource' + str(num) + r':\s+)(\S+)\s*$')
        elif 'name' in data:
            name = data['name']
            source_re = re.compile(r'^(\s*[sS]ource\d*:\s+)(' + name + r')\s*$')
        lnum = -1
        for lineno, line in enumerate(lines):
            match = source_re.search(line)
            if match:
                lnum = lineno
                head = match.group(1)
                break
        else:
            self.logger.error('Could not find source, no match for %r', source_re.pattern)
            raise SanityError('No such source')
        # ... and replace it
        entry = "%s%s\n" % (head, sourcename)
        lines[lnum] = entry

        # copy source file
        self.copy_new_source(sourcefile)

        #TODO - option to remove old

        # write it back out
        fobj = open(specfile, 'w')
        fobj.writelines(lines)
        fobj.close()

    def rule_handler_script(self, data):
        """Run an arbitary script"""
        fname = data['script']
        script = os.path.join(self.options.config['rulesdir'], fname)
        if not os.path.isfile(script):
            raise ConfigError('Script missing: %s' % script)

        cmd = [script, self.checkout, self.find_spec()]
        self.log_cmd(cmd, cwd=self.checkout)

    def remake_srpm(self):
        """Remake the srpm"""
        # This is mainly a test
        cmd = ['rpmbuild', '-bs',
                '--define', '_topdir %s' % self.checkout,
                '--define', '_srcrpmdir %s' % self.workdir,
                '--define', 'dist .TEST',
                self.find_spec()]
        self.log_cmd(cmd, cwd=self.workdir)

    def notify(self):
        subject = 'Successfully staged %s' % self.nvr
        body = """\
Staging completed for %(nvr)s.

Working directory: %(workdir)s
""" % vars(self)
        body = body % locals()
        #TODO : be more informative
        self.send_email_notice('info', subject, body)


class Pusher(BaseProcessor):

    def run(self):
        self.add_error_logger()
        self.read_source_file()
        self.check_package()
        if self.duplicate_check() and not self.options.repush:
            self.logger.warning('Skipping push for duplicate content')
            return
        state = self.check_workdir()
        if state == 'PUSHED':
            return
        self.setup_logfile('push.log')
        if state == 'STAGED':
            self.add_changelog()
            self.push_lookaside()
        self.push_git(state)
        self.set_state('PUSHED')
        self.notify()

    def check_workdir(self):
        self.workdir = dirname = self.get_workdir()
        self.checkout = os.path.join(self.workdir, "checkout")
        self.logger.info('Checking working directory: %s', dirname)
        if os.path.islink(dirname):
            raise SanityError("%s is a symlink" % dirname)
        if not os.path.isdir(dirname):
            raise SanityError("Not staged. No such directory: %s" % dirname)
        state = self.get_state()
        if state == 'UNTAGGED':
            if self.options.config['push_tags']:
                self.logger.info('Same content already on remote, will push tag only')
                return state
            else:
                self.set_state('PUSHED')
                state = 'PUSHED'
        if state == 'PUSHED':
            self.logger.warn('Already pushed')
            return state
        if state != 'STAGED':
            raise SanityError("Staging incomplete")
        return state

    def add_changelog(self):
        """Check for a prepared changelog entry and add to spec if found"""

        fname = os.path.join(self.workdir, 'changelog.txt')
        if not os.path.exists(fname):
            self.logger.info("No prepared changelog found")
            return

        # make sure we're still on the stage branch
        stage_branch = "altsrc-stage-%s" % self.options.branch
        stage_branch = self.sanitize_ref_segment(stage_branch)
        self.log_cmd(['git', 'checkout', stage_branch], cwd=self.checkout)

        # get the changelog entry
        fobj = open(fname, 'r')
        clog = fobj.read()
        now = datetime.datetime.now().strftime('%a %b %d %Y')
        if clog.find('INSERT_DATE_HERE') == -1:
            self.logger.error("Prepared changelog is malformed")
            return
        clog = clog.replace('INSERT_DATE_HERE', now, 1)

        # insert the entry into spec
        spec = self.find_spec()
        prog = re.compile(r'^(\s*%changelog.*)$', re.MULTILINE)
        inf = open(spec, 'r')
        parts = prog.split(inf.read())
        inf.close()
        if len(parts) == 1:
            self.logger.error('Could not find changelog in spec')
            return
        elif len(parts) == 2:
            # should not be possible
            raise SanityError('Unable to split changelog from spec')
        outf = open(spec, 'w')
        for part in parts[:2]:
            outf.write(part)
        outf.write('\n')
        outf.write(clog)
        for part in parts[2:]:
            outf.write(part)
        if len(parts) > 3:
            self.logger.error('Found multiple %changelog macros in spec')
            # keep going
            self.logger.debug('Context:\n%s', parts)
        outf.close()

        # add commit
        relpath = os.path.join('SPECS', os.path.basename(spec))
        self.log_cmd(['git', 'add', relpath], cwd=self.checkout)
        cmd = self.git_base_cmd()
        cmd.extend(['commit', '-m', 'add changelog entry'])
        self.log_cmd(cmd, cwd=self.checkout)

    def push_git(self, state):
        """Get our checkout ready for the public push"""

        git_url = self.git_push_url()
        pushbranch = "altsrc-push-%s" % self.options.branch
        pushbranch = self.sanitize_ref_segment(pushbranch)

        # if state is UNTAGGED, then skip the following, just do push tag
        if state == 'STAGED':
            # fetch from public remote
            # see if remote has it
            cmd = ['git', 'ls-remote', git_url, "refs/heads/%s" % self.options.branch]
            output, retval = self.get_output(cmd, cwd=self.checkout, fatal=False)
            if retval:
                # error talking to remote. Could be that that repo does not exist,
                # or could be a network error
                self.logger.warning("Unable to reach remote repo: %s", self.package)
                if self.check_push_to_pagure():
                    self.init_pagure_remote_repo()
                else:
                    self.init_remote_repo()
            new_branch = False
            if not output:
                # XXX we should check the output more thoroughly
                self.logger.warning("Branch missing on remote: %s", self.options.branch)
                new_branch = True
            else:
                cmd = ['git', 'fetch', '-v', git_url, "+%s:%s" % (self.options.branch, pushbranch)]
                self.log_cmd(cmd, cwd=self.checkout)

            # now apply changes on pushbranch to stage branch
            our_import_tag = "altsrc-stage-import-%s" % self.options.branch
            our_import_tag = self.sanitize_ref_segment(our_import_tag)
            stage_branch = "altsrc-stage-%s" % self.options.branch
            stage_branch = self.sanitize_ref_segment(stage_branch)
            output, _ = self.get_output(['git', 'rev-parse', our_import_tag], cwd=self.checkout, fatal=True)
            import_rev = output.strip()
            output, _ = self.get_output(['git', 'rev-parse', stage_branch], cwd=self.checkout, fatal=True)
            stage_rev = output.strip()
            #TODO assert that stage_branch is a descendant of our_import_tag
            if new_branch:
                # branch from master if new
                # repos on pagure might not have a master available
                cmd = ['git', 'checkout', '-b', pushbranch]
                if not self.check_push_to_pagure():
                    cmd.append('master')
            else:
                cmd = ['git', 'checkout', pushbranch]
            self.log_cmd(cmd, cwd=self.checkout)

            # set push branch to match import
            cmd = ['git', 'rm', '-rf', '--ignore-unmatch', '.']
            self.log_cmd(cmd, cwd=self.checkout)
            cmd = ['git', 'checkout', our_import_tag, '--', '.']
            self.log_cmd(cmd, cwd=self.checkout)
            # check that we actually have something to commit
            cmd = ['git', 'diff', '--cached', '--name-only']
            output, _ = self.get_output(cmd, cwd=self.checkout, stderr='keep', fatal=False)

            if output:
                cmd = self.git_base_cmd()
                msg_data = koji.util.dslice(vars(self), ['nvr', 'package', 'version', 'release', 'summary'])
                msg_data['branch'] = self.options.branch
                commit_msg = self.options.config['commit_format'] % msg_data
                cmd.extend(['commit', '-m', commit_msg])
                self.log_cmd(cmd, cwd=self.checkout)

        #tag
        if self.options.config['push_tags']:
            tagname = self.get_import_tagname()
            if tagname in self.list_local_tags():
                self.logger.info("Deleting local tag %s", tagname)
                self.delete_local_tag(tagname)

            cmd = self.git_base_cmd()
            cmd.extend(['tag', '-a', '-m', 'import %s' % self.nvr, tagname])
            self.log_cmd(cmd, cwd=self.checkout)

        if state == 'STAGED':
            if stage_rev != import_rev:
                # grab the rest of the stage branch (debranding)
                cmd = ['git', 'rm', '-rf', '--ignore-unmatch', '.']
                self.log_cmd(cmd, cwd=self.checkout)
                cmd = ['git', 'checkout', stage_branch, '--', '.']
                self.log_cmd(cmd, cwd=self.checkout)
                # check that we actually have something to commit
                cmd = ['git', 'diff', '--cached', '--name-only']
                output, _ = self.get_output(cmd, cwd=self.checkout, stderr='keep', fatal=False)
                if not output:
                    raise SanityError("Debranding commits resulted in no changes?")
                #commit
                cmd = self.git_base_cmd()
                cmd.extend(['commit', '-m', 'debrand %s' % self.nvr])
                #XXX need a better commit message
                self.log_cmd(cmd, cwd=self.checkout)
                #TODO - another tag?

            # ...and push
            cmd = ['git', 'push', git_url, "%s:%s" % (pushbranch, self.options.branch)]
            self.log_cmd(cmd, cwd=self.checkout)

        if self.options.config['push_tags']:
            cmd = ['git', 'push', git_url, "refs/tags/%s" % tagname]
            self.log_cmd(cmd, cwd=self.checkout)

        #TODO retry loop

    def init_remote_repo(self):
        # we should have a base repo staged here
        src = os.path.join(self.workdir, "repo_init.git/")
        # note the trailing slash for rsync arg
        dst = self.git_push_url()
        cmd = ['rsync', '-ivrpt', src, dst]
        self.log_cmd(cmd, cwd=self.workdir)

    def init_pagure_remote_repo(self):
        keyfile = None
        try:
            keyfile = open(self.options.config['pagure_api_key_file'], 'r')
            key = keyfile.read()
        finally:
            if keyfile:
                keyfile.close()

        values = {
            'name': self.package,
            'description': self.summary,
            'namespace': 'rpms',
            'private': False,
            'wait': True,
        }
        if self.mmd:
            values['namespace'] = 'modules'

        headers = {
            'Authorization': key,
        }

        self.logger.info("Creating pagure repo:: %s", values)
        data = urlencode(values)
        req = Request(
            self.options.config['pagure_repo_init_api'],
            data=data,
            headers=headers,
        )

        resp = urlopen(req)
        resp = json.loads(resp.read())
        self.logger.info(resp)


    def push_lookaside(self):
        meta = open(os.path.join(self.checkout, ".%s.metadata" % self.package), 'r')
        for line in meta.readlines():
            line = line.strip()
            digest, _ = line.split(None, 1)
            self.push_lookaside_file(digest)

    def push_lookaside_file(self, digest):
        relpath = os.path.join(self.package, self.options.branch, digest)
        cmd = ['rsync', '-ivpt', '--relative', relpath, self.options.config['lookaside_rsync_dest']]
        # --relative option preserves the relative path from the command line
        # this is a way to ensure we create the necessary subdirs
        self.log_cmd(cmd, cwd=self.options.config['lookaside'])

    def notify(self):
        subject = 'Successfully pushed %s' % self.nvr
        body = """\
Push completed for %(nvr)s.

Working directory: %(workdir)s
""" % vars(self)
        body = body % locals()
        #TODO : be more informative
        self.send_email_notice('info', subject, body)


def acquire_lock(lock_file_path, wait_time, sleep_interval, logger):
    """
    try to acquire the lock, if the unable to get it, wait for sleep_interval
    secs, and retry. Until time out or get the locker.
    """
    times = int(wait_time/sleep_interval)
    for _ in range(times):
        try:
            lock_file = open(lock_file_path, 'w+')
            fcntl.lockf(lock_file.fileno(), fcntl.LOCK_EX|fcntl.LOCK_NB)
        except IOError:
            logger.info('Another task is processing the current directory, waiting..')
            time.sleep(sleep_interval)
        else:
            logger.info('Lock acquired')
            return lock_file
    logger.error('Failed to acquire lock within %ss', wait_time)
    raise RuntimeError('Time out > %s' % wait_time)


def explode_srpm(srpm, destdir=None, logfile=None):
    # explode our srpm to the given directory
    header = koji.get_rpm_header(srpm)
    if header[rpm.RPMTAG_SOURCEPACKAGE] != 1:
        # we checked this earlier, but since we're about to rpm -i it,
        # let's check again
        raise SanityError("%s is not a source package" % srpm)
    if destdir is None:
        destdir = os.getcwd()
    else:
        destdir = os.path.abspath(destdir)
        koji.ensuredir(destdir)
    cmd = ['rpm', '--nosignature', '-i', '--define', '_topdir %s' % destdir, srpm]
    #print "Running: %r" % cmd
    popts = {'close_fds':True}
    if logfile:
        popts['stdout'] = logfile
        popts['stderr'] = subprocess.STDOUT
    proc = subprocess.Popen(cmd, **popts)
    ret = proc.wait()
    if ret:
        raise CommandError("command failed: %r" % cmd)


def wipe_git_dir(dirname):
    for fname in os.listdir(dirname):
        if fname == '.git':
            continue
        path = os.path.join(dirname, fname)
        if os.path.isdir(path):
            koji.util.rmtree(path)
        else:
            os.unlink(path)


def die(msg):
    self.logger.error(msg)
    sys.exit(1)


def setup_logging(options):
    logger = logging.getLogger("altsrc")
    logger.setLevel(logging.DEBUG)

    #determine log levels
    output_log_level = logging.WARN #default
    if options.debug:
        output_log_level = logging.DEBUG
    elif options.verbose:
        output_log_level = logging.INFO
    elif options.quiet:
        output_log_level = logging.ERROR
    config_warning = None
    file_log_level = getattr(logging, options.config['log_level'], None)
    if file_log_level is None:
        # just use sane default and warn later
        file_log_level = logging.WARN
        config_warning = "Invalid log level: %s" % options.config['log_level']
    # file level should be at least as verbose as output level
    file_log_level = min(file_log_level, output_log_level)
    options.file_log_level = file_log_level

    # set up handlers
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter(options.config['log_format']))
    handler.setLevel(output_log_level)
    logger.addHandler(handler)
    if options.config['log_file']:
        handler = logging.FileHandler(options.config['log_file'])
        handler.setFormatter(logging.Formatter(options.config['log_format']))
        handler.setLevel(file_log_level)
        logger.addHandler(handler)
        #XXX: fix handlers
        #pylint:disable=undefined-variable
        handlers.append(handler)
    # TODO - setup koji's logger?

    if config_warning:
        logger.warning(config_warning)
    return logger


def _(args):
    """Stub function for translation"""
    return args


def main(args):
    """process options from command line"""

    #pylint:disable=used-before-assignment
    usage = _("%prog [options] branch source\n"
              "source can be <nvr>.src.rpm or <nvr>:modulemd.src.txt only when used with --koji,\n"
              "without --koji srpm as source is supported only, <nvr>[.src.rpm] is accepted then.")
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--config", dest="cfile", default='/etc/altsrc.conf',
                      help=_("use alternate configuration file"), metavar="FILE")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help=_("be more verbose"))
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help=_("be less verbose"))
    parser.add_option("-d", "--debug", action="store_true", default=False,
                      help=_("show debug output"))
    parser.add_option("--restage", action="store_true", default=False,
                      help=_("remove and recreate staged content"))
    parser.add_option("--repush", action="store_true", default=False,
                      help=_("push content even if it appears to be present already"))
    parser.add_option("--push", action="store_true", default=False,
                      help=_("push staged sources"))
    parser.add_option("--koji", "--brew", action="store_true", default=False,
                      help=_("pull sources from Koji"))
    parser.add_option("--keep-sources", action="store_true", default=False,
                      help=_("keep lookaside sources in staging checkout"))
    parser.add_option("-o", "--option", dest="copts", action="append", metavar="OPT=VALUE",
                      help=_("set config option"))
    (options, args) = parser.parse_args(args)

    options.branch = args[0]
    options.source = args[1]

    options.config = get_config(options.cfile, options.copts)

    logger = setup_logging(options)
    tasks = [Stager(options)]
    # always run stager. it's a no-op if already staged
    if options.push:
        tasks.append(Pusher(options))
    for task in tasks:
        #pylint: disable=broad-except
        try:
            task.run()
            task.notify_errors()
        except SystemExit:
            msg = ''.join(traceback.format_exception_only(*sys.exc_info()[:2]))
            logger.warn("Exiting (%s)", msg)
            raise
        except KeyboardInterrupt:
            msg = ''.join(traceback.format_exception_only(*sys.exc_info()[:2]))
            logger.warn("Exiting (%s)", msg)
            sys.exit(1)
        except Exception:
            task.handle_error()
            sys.exit(2)


def entry_point():
    main(sys.argv[1:])
