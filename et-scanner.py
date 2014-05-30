#!/usr/bin/python

import ConfigParser
import datetime
import kerberos
import koji
import logging
import os
import os.path
import pdb
import pprint
import re
import requests
import socket
import sys
import subprocess
import time
import traceback
from optparse import OptionParser

try:
    import json
except ImportError:
    import simplejson as json


try:
    default_cacert = os.path.join(
                       os.path.abspath(os.path.dirname(__file__)), 
                       'certs/redhat-is-ca.crt')
except:
    default_cacert = os.path.join(
                       os.path.abspath(os.path.dirname(sys.argv[0])),
                       'certs/redhat-is-ca.crt')


def _(args):
    """Stub function for translation"""
    return args


def get_options():
    """process options from command line"""

    usage = _("%prog [options]")
    parser = OptionParser(usage=usage)
    parser.add_option("-c", "--config", dest="cfile", default='/etc/altsrc.conf',
                      help=_("use alternate configuration file"), metavar="FILE")
    parser.add_option("-v", "--verbose", action="store_true", default=False,
                      help=_("be more verbose"))
    parser.add_option("-q", "--quiet", action="store_true", default=False,
                      help=_("be less verbose"))
    parser.add_option("-d", "--debug", action="store_true", default=False,
                      help=_("show debug output"))
    #parser.add_option("--force", action="store_true", default=False,
    #                  help=_("force operation"))
    parser.add_option("-o", "--option", dest="copts", action="append", metavar="OPT=VALUE",
                      help=_("set config option"))
    (options, args) = parser.parse_args()

    if args:
        parser.print_help()
        print
        die("Error: This script takes no arguments. ")

    options.config = get_config(options.cfile, options.copts)

    return options


config_defaults = {
    'stage_script' : '/usr/bin/stage-alt-src',
    'log_level' : 'WARN',
    'log_file' : None,
    'log_format' : '%(asctime)s [%(levelname)s] %(message)s',
    'cacert' : None,
    'cachefile' : '/var/cache/et-scan/advisories',
    'errata_filter' : 441,
    'product_whitelist' : '',
    'product_blacklist' : '',
    'release_whitelist' : '',
    'release_blacklist' : '',
    'max_retries' : 3,
}

config_int_opts = set(['errata_filter'])
config_bool_opts = set()

def get_config(cfile, overrides):
    if not os.access(cfile, os.F_OK):
        die("Missing config file: %s" % cfile)
    cp = ConfigParser.RawConfigParser()
    cp.read(cfile)
    if not cp.has_section('altsrc'):
        die("Configuration file missing [altsrc] section: %s" % cfile)

    #apply overrides from command line
    overrides = overrides or []
    for opt in overrides:
        parts = opt.split("=", 1)
        if len(parts) != 2:
            die('Invalid option specification: %s\nUse OPT=VALUE' % opt)
        key, value = parts
        cp.set('altsrc', key, value)

    #generate config dictionary
    config = dict(config_defaults)  #copy
    for key in cp.options('altsrc'):
        if key in config_int_opts:
            config[key] = cp.getint('altsrc', key)
        elif key in config_bool_opts:
            config[key] = cp.getboolean('altsrc', key)
        else:
            config[key] = cp.get('altsrc', key)

    #sanity checks
    if not os.path.isdir(config['stagedir']):
        die("No such directory: %s" % config['stagedir'])

    return config


def die(msg):
    # XXX almost every use of this function is a bug
    # we need to handle errors more carefully
    print msg
    sys.exit(1)


def setup_logging(options):
    logger = logging.getLogger("etscan")
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter(options.config['log_format']))
    handler.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    if options.config['log_file']:
        handler = logging.FileHandler(options.config['log_file'])
        handler.setFormatter(logging.Formatter(options.config['log_format']))
        handler.setLevel(logging.DEBUG)
        logger.addHandler(handler)
    level = options.config['log_level']
    if options.debug:
        level = 'DEBUG'
    elif options.verbose:
        level = 'INFO'
    elif options.quiet:
        level = 'ERROR'
    lvl = getattr(logging, level, None)
    if lvl is None:
        die("Invalid log level: %s" % options.config['log_level'])
    logger.setLevel(lvl)



class KerberizedJSON(object):
    def __init__(self, host, cacert=None, max_retries=1, verify=True):
        self.host = host
        self.headers = {'Accept': 'application/json', 'content-type': 'application/json'}
        self.hooks=dict(response=self.__parse_json)
        self.auth_header = None
        self.auth_time = 0
        if max_retries > 0:
            self.max_retries = max_retries
        else:
            self.max_retries = 1
        self.cacert = cacert
        if cacert is None and os.path.exists(default_cacert):
            self.cacert = default_cacert
        if verify:
            self.verify = self.cacert
        else:
            self.verify = False

    def __kerb_auth(self):
        if not self.auth_header or (time.time() - self.auth_time) > 300:
            service = "HTTP@" + self.host
            try:
                rc, vc = kerberos.authGSSClientInit(service);
            except kerberos.GSSError, e:
                raise kerberos.GSSError(e)
            try:
                kerberos.authGSSClientStep(vc, "");
            except kerberos.GSSError, e:
                raise kerberos.GSSError(e)
            self.auth_header = "negotiate %s" % kerberos.authGSSClientResponse(vc)
            self.auth_time = time.time()
        self.headers['Authorization'] = self.auth_header

    def __parse_json(self, response, **kwargs):
        response._content = json.loads(response.content)

    def __url_for(self, service):
        return 'https://' + self.host + service

    def get(self, service):
        self.__kerb_auth()
        for retry in xrange(self.max_retries):
            try:
                return requests.get(self.__url_for(service),  headers=self.headers, hooks=self.hooks, verify=self.verify)
            except:
                pass
        raise

    def post(self, service, data):
        self.__kerb_auth()
        for retry in xrange(self.max_retries):
            try:
                return requests.post(self.__url_for(service), json.dumps(data), headers=self.headers, hooks=self.hooks, verify=self.verify)
            except:
                pass
        raise

    def put(self, service, data):
        self.__kerb_auth()
        for retry in xrange(self.max_retries):
            try:
                return requests.put(self.__url_for(service), json.dumps(data), headers=self.headers, hooks=self.hooks, verify=self.verify)
            except:
                pass
        raise

    def delete(self, service):
        self.__kerb_auth()
        for retry in xrange(self.max_retries):
            try:
                return requests.delete(self.__url_for(service), headers=self.headers, hooks=self.hooks, verify=self.verify)
            except Exception:
                pass
        raise


class ErrataScanner(object):

    def __init__(self, options):
        self.options = options
        self.logger = logging.getLogger("etscan")
        self.logger.debug("Config: %s", pprint.pformat(options.config))
        self.rpc = KerberizedJSON('errata.devel.redhat.com', cacert=options.config['cacert'],
                    max_retries=options.config['max_retries'])

    def run(self):
        self.read_cache()
        self.read_advisories()
        self.read_builds()
        self.stage_builds()
        self.write_cache()

    def read_cache(self):
        self.cache = {'builds': [], 'advisories' : {}}
        cache = self.options.config['cachefile']
        if not os.path.exists(cache):
            self.logger.info('Cache file missing: %s', cache)
            return
        self.logger.info('Reading cache file: %s', cache)
        try:
            self.cache = json.load(file(cache))
        except Exception, e:
            exc = ''.join(traceback.format_exception_only(*sys.exc_info()[:2]))
            self.logger.error(exc)
            self.logger.error('Unable to load cache file')

    def read_advisories(self):
        data = self.rpc.get('/filter/%i.json' % self.options.config['errata_filter']).content
        #XXX default 441 filter is owned by mikem, need a better way to specify our parameters
        self.logger.info('Loaded %i advisories', len(data))
        self.advisories = dict([(d['id'], d) for d in data])

    def adv_changed(self, adv):
        last = self.cache['advisories'].get(str(adv['id']))
        if not last:
            self.logger.debug('No cache for advisory: %(id)s', adv)
            return True
        if adv['revision'] != last['revision']:
            self.logger.debug('Revision changed for advisory %s, %s -> %s', adv['id'], last['revision'], adv['revision'])
            return True
        if last['timestamps']['status_time'] is None:
            self.logger.debug('No previous status time for %(id)s', adv)
            return True
        if adv['status'] != last['status']:
            self.logger.debug('Status changed for %s: %s -> %s', adv['id'], last['status'], adv['status'])
            return True
        if adv['timestamps']['status_time'] > last['timestamps']['status_time']:
            # errata tool returns timestamps in a sort stable string format
            # e.g. 2014-04-17T03:00:13Z
            self.logger.debug('Status time changed for %(id)s', adv)
            return True
        #otherwise
        return False

    def log_advisory(self, adv):
        self.logger.debug("Advisory %(id)s: %(advisory_name)s: %(synopsis)s", adv)
        self.logger.debug("  Product: %s, Release: %s, Status: %s",
                    adv['product']['short_name'], adv['release']['name'], adv['status'])

    def read_builds(self):
        builds = set()
        for adv_id in self.advisories:
            adv = self.advisories[adv_id]
            if self.logger.isEnabledFor(logging.DEBUG):
                self.log_advisory(adv)
            # TODO apply filtering rules
            if self.check_advisory_filters(adv):
                self.logger.info('Skipping advisory due to filters: %(id)s', adv)
                continue
            if not self.adv_changed(adv):
                self.logger.info('Skipping unchanged advisory: %(id)s', adv)
                continue
            try:
                bdata = self.rpc.get('/advisory/%(id)s/builds' % adv).content
            except:
                exc = ''.join(traceback.format_exception_only(*sys.exc_info()[:2]))
                self.logger.error(exc)
                self.logger.error("Unable to read builds for advisory %(id)s", adv)
                # don't let one error keep us from the rest of the advisories
                continue
            #if len(bdata) > 1:
            #    pprint.pprint(bdata)
            for chan in bdata:
                # XXX not sure if this value really maps to a channel or not, but it seems to be channel-ish
                for entry in bdata[chan]:
                    #each entry is a single entry dictionary with the build nvr as the key
                    for nvr in entry:
                        builds.add(nvr)
        self.builds = builds

    def check_advisory_filters(self, adv):
        """Check filters. Return True if we should skip the advisory"""
        if self.check_product_filters(adv):
            return True
        elif self.check_release_filters(adv):
            return True
        # TODO more filters?
        #otherwise
        return False

    def check_product_filters(self, adv):
        product = adv['product']['short_name']
        # XXX should we also match the full name?
        whitelist = self.options.config['product_whitelist'].split()
        blacklist = self.options.config['product_blacklist'].split()
        return self.check_wblist(product, whitelist, blacklist)

    def check_release_filters(self, adv):
        release = adv['release']['name']
        whitelist = self.options.config['release_whitelist'].split()
        blacklist = self.options.config['release_blacklist'].split()
        return self.check_wblist(release, whitelist, blacklist)

    def check_wblist(self, name, whitelist=[], blacklist=[]):
        if whitelist:
            whitelisted = koji.util.multi_fnmatch(name, whitelist)
        else:
            whitelisted = False
        if not whitelisted:
            if blacklist and koji.util.multi_fnmatch(name, blacklist):
                return True
        #otherwise
        return False

    def stage_builds(self):
        last = self.cache['builds']
        last = set(last)
        staged = []
        for nvr in self.builds:
            if nvr in last:
                self.logger.info('Skipping already seen build: %s', nvr)
            self.logger.info('Staging build: %s', nvr)
            # TODO: actually run staging script
            # TODO: check for errors
            staged.append(nvr)
        self.staged = staged

    def write_cache(self):
        fn = self.options.config['cachefile']
        cache = {}
        cache['advisories'] = self.advisories
        builds = self.cache['builds']
        builds.extend(self.staged)
        cache['builds'] = builds
        self.logger.info('Writing cache file: %s', fn)
        try:
            fo = file(fn, 'w')
            self.cache = json.dump(cache, fo, indent=2)
            fo.close()
        except Exception, e:
            exc = ''.join(traceback.format_exception_only(*sys.exc_info()[:2]))
            self.logger.error(exc)
            self.logger.error('Unable to write cache file')


def main():
    #pdb.set_trace()
    scanner = ErrataScanner(options)
    scanner.run()


if __name__ == '__main__':
    options = get_options()
    setup_logging(options)
    main()
    #TODO - trap errors and notify

# the end
