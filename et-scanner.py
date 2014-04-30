#!/usr/bin/python

import datetime
import kerberos
import os
import re
import requests
import socket
import sys
import subprocess
import tempfile
import time
from pprint import pprint

try:
    import json
except ImportError:
    import simplejson as json


try:
    # XXX - config
    default_cacert = os.path.join(
                       os.path.abspath(os.path.dirname(__file__)), 
                       'certs/redhat-is-ca.crt')
except:
    default_cacert = os.path.join(
                       os.path.abspath(os.path.dirname(sys.argv[0])),
                       'certs/redhat-is-ca.crt')


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
    cacert = os.path.dirname(os.path.abspath(sys.argv[0])) + \
        '/certs/redhat-is-ca.crt'
    return KerberizedJSON('errata.devel.redhat.com', cacert=cacert)

json_server = get_errata_json()


if len(sys.argv) > 1:
    for advisory in sys.argv[1:]:
        advisory_info = json_server.get('/advisory/%s' % advisory).content
        pprint(advisory_info)
        advisory_builds = json_server.get('/advisory/%s/builds' % advisory).content
        pprint(advisory_builds)
        release_info = json_server.get('/release/show/%s' % advisory_info['release']['id']).content
        pprint(release_info)
        product_info = json_server.get('/products/%s.json' % advisory_info['product']['id']).content
        pprint(product_info)
else:
    advisories = json_server.get('/errata?format=json').content
    pprint(advisories)

