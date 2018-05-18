#!/usr/local/bin/python2

import sys
import json
import pprint
import logging
import urllib3
import urllib3.response as response
import base64
import time
import datetime
import argparse
import threading
import re

THREAD_TIMEOUT = 30
CONNECTION_POOL = 40
CONNECTION_POOL_MAX = 80
CONNECTION_RETRY = 3
CONNECTION_TIMEOUT = 60


class HttpObject(object):

    def __init__(self, basicurl=None, auth=None, log=None):
        super(HttpObject, self).__init__()
        self.http = urllib3.PoolManager(num_pools=CONNECTION_POOL,
                                        maxsize=CONNECTION_POOL_MAX,
                                        block=True,
                                        retries=CONNECTION_RETRY,
                                        timeout=CONNECTION_TIMEOUT)
        self.auth = auth
        self.basicurl = basicurl
        self.headers = {
            'Authorization': 'Basic {}'.format(self.__basic_auth()),
            'Accept': 'application/vnd.docker.distribution.manifest.v2+json'
        }
        if log:
            self.log = log
        else:
            self.log = logging.getLogger('Registry')
            self.log.addHandler(logging.StreamHandler(sys.stdout))
            self.log.setLevel(logging.WARNING)

    def __basic_auth(self):
        return base64.b64encode("{}:{}".format(self.auth[0], self.auth[1]))


class Registry(HttpObject):

    def __init__(self, basicurl=None, auth=None, log=None, days=90, whitelist=None, dryrun=True):
        super(Registry, self).__init__(basicurl, auth, log)
        self.repos = []
        self.dryrun=dryrun
        # Get repos
        self._repositories(days, whitelist)

    def _repositories(self, days, whitelist):
        repos = []
        try:
            r = self.http.request("GET", "{}/v2/_catalog".format(self.basicurl), headers=self.headers)
            repos = json.loads(r.data.decode('UTF-8'))['repositories']
        except KeyError as e:
            self.log.error("{} not found | Cannot get repository list".format(str(e)))
        self.log.warning("Found %d repos:" % len(repos))
        rexp = re.compile(whitelist)
        for reponame in repos:
            if rexp.search(reponame):
                self.log.warning("Get tags for [%s]" % reponame)
                r = Repository(repourl=reponame,
                               basicurl=self.basicurl,
                               days=days,
                               http=self.http,
                               log=self.log,
                               headers=self.headers,
                               dryrun=self.dryrun)
                self.repos.append(r)
                # Start thread
                r.start()
            else:
                self.log.info("Skipping [%s]" % reponame)

    def repositories(self):
        return self.repos

    def join(self, timeout=None):
        for repo in self.repos:
            repo.join(timeout)

    def __str__(self):
        return str(self.repos)

    def __repr__(self):
        return self.__str__()


class Repository(threading.Thread):

    def __init__(self, repourl, basicurl, days=90, headers=None, http=None, log=None, dryrun=True):
        super(Repository, self).__init__()
        self.repourl = repourl
        self.days = days
        self.basicurl = basicurl
        self.http = http
        self.log = log
        self.headers = headers
        self.tags = []
        self.dryrun = dryrun

    def __str__(self):
        return str((self.repourl, len(self.tags)))

    def __repr__(self):
        return str((self.repourl, len(self.tags)))

    def run(self):
        self._tags()

    def _tags(self):
        tags = []
        try:
            resp = self.http.request("GET", "{}/v2/{}/tags/list".format(self.basicurl, self.repourl),
                                     headers=self.headers)
            tags = json.loads(resp.data.decode('UTF-8'))['tags']
        except KeyError as e:
            self.log.error("{} not found | Repo: {} ".format(str(e), self.repourl))
        log.warning("\tFound %d tags on (%s)" % (len(tags), self.repourl))
        for tag in tags:
            dig = self._get_digest(tag)
            if dig:
                self.tags.append(tag)
                log.info("\t\tDELETE: %s" % str(self.delete(dig)))

    def _get_digest(self, tag):
        now = datetime.datetime.now()
        date = datetime.datetime.now()
        root_digest = ""
        try:
            r = self.http.request("GET", "{}/v2/{}/manifests/{}".format(self.basicurl, self.repourl, tag), headers=self.headers)
            digest = r.getheaders()['Docker-Content-Digest']
            root_digest = json.loads(r.data.decode('UTF-8'))['config']['digest']
            r = self.http.request("GET", "{}/v2/{}/manifests/{}".format(self.basicurl, self.repourl, root_digest),
                                  headers=self.headers)
            datestring = json.loads(r.data.decode('UTF-8'))['created']
            date = datetime.datetime.strptime(datestring.split('.')[0], '%Y-%m-%dT%H:%M:%S')
        except KeyError as e:
            self.log.error("{} not found | Repo: {} | Tag {} | root_digest {} ".format(str(e), self.repourl, tag, root_digest))

        if abs((now - date).days) >= self.days:
            return digest
        else:
            return None

    def delete(self, digest=None):
        if digest:
            uri = "{}/v2/{}/manifests/{}".format(self.basicurl, self.repourl, digest)
            if not self.dryrun:
                r = self.http.request("DELETE", uri, headers=self.headers)
                ret = [uri, r.status, r.getheaders(), r.data.decode('UTF-8')]
            else:
                ret = [uri, None, None, None]
        return ret


if __name__ == "__main__":
    # Disable ssl warning
    urllib3.disable_warnings()

    # Build cli
    cli = argparse.ArgumentParser(description="Cleanup remote docker registry ")
    cli.add_argument('-r', '--registry', dest='registry', help='Docker registry url', required=True)
    cli.add_argument('-u', '--user', dest='user', help='Docker registry username')
    cli.add_argument('-p', '--password', dest='passwd', help='Docker registry password')
    cli.add_argument('-d', '--days', dest='days', help='Days after select an images as "old"', default=90, type=int)
    cli.add_argument('-D', '--dryrun', dest='dryrun', help='Dry run mode (do nothing, print list of deletion)',
                     default=False, action='store_true')
    cli.add_argument('-v', '--verbose', dest='verbose', help='Verbose logging', default=False, action='store_true')
    cli.add_argument('-i', '--include', dest='whitelist', help='Include pattern', default="")
    args = cli.parse_args()

    # sanity checks
    if args.user is not None or args.passwd is not None:
        auth = [args.user, args.passwd]
    else:
        auth = None
    if args.verbose:
        loglevel = logging.INFO
    else:
        loglevel = logging.WARNING

    # Create new logger
    log = logging.getLogger('')
    fh = logging.StreamHandler(sys.stdout)
    log.addHandler(fh)
    log.setLevel(loglevel)

    if args.dryrun:
        log.error("Dry run")

    # Create new registry and wait for thread termination
    reg = Registry(args.registry, auth, log, args.days, args.whitelist, args.dryrun)
    reg.join()
    for r in reg.repos:
        log.warning("Deleted %d tags on %s" % (len(r.tags), r.repourl))
        for t in r.tags:
            log.info("Deleted %s:%s" % (r.repourl, t ))
    reg.http.clear()
