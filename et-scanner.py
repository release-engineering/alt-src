#!/usr/bin/python

import ConfigParser
import datetime
import kerberos
import logging
import os
import os.path
import re
import requests
import socket
import sys
import subprocess
import tempfile
import time
from optparse import OptionParser
from pprint import pprint

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

    usage = _("%prog [options] branch srpm")
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

    options.args = args
    # TODO: process args here?

    options.config = get_config(options.cfile, options.copts)

    return options


config_defaults = {
    'stage_script' : '/usr/bin/stage-alt-src',
    'log_level' : 'WARN',
    'log_file' : None,
    'log_format' : '%(asctime)s [%(levelname)s] %(message)s',
    'cacert' : None,
}

config_int_opts = set()
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


def get_errata_json():
    #cacert = os.path.dirname(os.path.abspath(sys.argv[0])) + \
    #    '/certs/redhat-is-ca.crt'
    return KerberizedJSON('errata.devel.redhat.com', cacert=options.config['cacert'])


def main():
    logger = logging.getLogger("etscan")
    #XXX just test code here
    json_server = get_errata_json()

    argv = options.args
    if len(argv) > 1:
        for advisory in argv[1:]:
            logger.info('Querying advisory: %s', advisory)
            advisory_info = json_server.get('/advisory/%s' % advisory).content
            pprint(advisory_info)
            advisory_builds = json_server.get('/advisory/%s/builds' % advisory).content
            pprint(advisory_builds)
            release_info = json_server.get('/release/show/%s' % advisory_info['release']['id']).content
            pprint(release_info)
            product_info = json_server.get('/products/%s.json' % advisory_info['product']['id']).content
            pprint(product_info)
    else:
        logger.info('Querying all advisories')
        advisories = json_server.get('/errata?format=json').content
        pprint(advisories)
        logger.info('Got %i advisories', len(advisories))


if __name__ == '__main__':
    options = get_options()
    setup_logging(options)
    main()
    #TODO - trap errors and notify

# the end
