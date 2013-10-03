#! /usr/bin/env python
"""
Script that checks all uncommented domains in a nginx or apache config directory.

The domain is checked for the HTTP return code and
if the there is a DNS record for the domain.

Optionaly you can provide the ip of you server and the script will check
if the domain is hosted on your server or not.
"""


import collections
from optparse import OptionParser
import logging
import logging.handlers
import os
import sys
import urllib2
import socket

import dns.resolver

def get_logger(logdir, debug):
    """docstring for get_logger"""
    logname = 'dontpanic.log'

    logdir = logdir or '.'
    debug = debug or False

    logger = logging.getLogger()
    #formatter = logging.Formatter(
        #'%(asctime)s - %(levelname)s - %(message)s')

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logfile_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logdir, logname)
    )
    stream_handler = logging.StreamHandler()

    #logfile.setFormatter(formatter)
    logger.addHandler(logfile_handler)
    logger.addHandler(stream_handler)

    logger.debug("Dontpanic script started ...")

    return logger


class SmartRedirectHandler(urllib2.HTTPRedirectHandler):
    def http_error_301(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_301(
            self, req, fp, code, msg, headers)
        result.status = code
        return result

    def http_error_302(self, req, fp, code, msg, headers):
        result = urllib2.HTTPRedirectHandler.http_error_302(
            self, req, fp, code, msg, headers)
        result.status = code
        return result


class DefaultErrorHandler(urllib2.HTTPDefaultErrorHandler):
    def http_error_default(self, req, fp, code, msg, headers):
        result = urllib2.HTTPError(
            req.get_full_url(), code, msg, headers, fp)
        result.status = code
        return result


class Parser(object):

    def parser_nginx_conf(self, nginx_file):
        logger.debug("Starting parsing nginx conf file: %s", nginx_file)
        with open(nginx_file) as conf:
            for num, line in enumerate(conf, 1):
                if "server_name " in line and "#" not in line:
                    line_domains = line.strip().replace("server_name ", "")
                    line_domains = line_domains.replace(";", "").split()
                    for domain in line_domains:
                        yield nginx_file, num, domain
        logger.debug("Parsing nginx conf: %s completed\n", nginx_file)

    def parser_apache_conf(self, apache_file):
        logger.debug("Starting parsing apache conf file: %s", apache_file)
        with open(apache_file) as conf:
            for num, line in enumerate(conf, 1):
                if "ServerAlias" in line and "#" not in line:
                    line_domains = line.strip().replace("ServerAlias", "").split()
                    for domain in line_domains:
                        yield apache_file, num, domain.split(":")[0]
        logger.debug("Parsing apache conf completed\n")

    def _file_list(self, directory, excluded=""):
        for dirname, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                if filename not in excluded:
                    yield os.path.join(dirname, filename)


    def _tree(self):
        """
        This is a self expanding recursive dict superb for dict tree building.

        http://stackoverflow.com/questions/3009935/looking-for-a-good-python-tree-data-structure
        """
        return collections.defaultdict(self._tree)

    # DRY
    def parse_nginx_dir(self, nginx_dir):
        """docstring for parse_nginx_dir"""
        domains = self._tree()
        for conf in self._file_list(nginx_dir):
            for file_, num, domain in self.parser_nginx_conf(conf):
                if not file_ in domains[domain]:
                    domains[domain]["nginx"]["config_file"][file_]["line_numbers"] = []
                domains[domain]["nginx"]["config_file"][file_]["line_numbers"].append(num)
                logger.info("Added %s domain from nginx conf file: %s in line %s", domain, file_, num)
        return domains

    def parse_apache_dir(self, apache_dir):
        """docstring for parse_apache_dir"""
        domains = self._tree()
        for conf in self._file_list(apache_dir):
            for file_, num, domain in self.parser_apache_conf(conf):
                if not file_ in domains[domain]:
                    domains[domain]["apache"]["config_file"][file_]["line_numbers"] = []
                domains[domain]["apache"]["config_file"][file_]["line_numbers"].append(num)
                logger.info("Added %s domain from apache conf file: %s in line %s", domain, file_, num)
        return domains


class DomainChecker(object):

    def __init__(self, timeout=3, agent="dontpanic/1.0"):
        self.timeout = timeout
        self.agent = agent
        self.opener = urllib2.build_opener()

    def _build_request(self, url):
        self.url = url
        if not self.url.startswith("http"):
            tmp = "http://" + url
            self.hurl = tmp
        request = urllib2.Request(self.hurl)
        request.add_header('User-Agent', self.agent)
        request.add_header('Accept-encoding', 'gzip')
        return request

    def get_code(self, url):
        response = self.opener.open(self._build_request(url), timeout=self.timeout)
        if hasattr(response, 'status'):
            return response.status
        else:
            return response.code

    def check_domain(self, domain, our_ip_list=None):
        oklist, foolist = [], []
        code = None
        our_shit = False
        # XXX
        if our_ip_list is None:
            our_shit = True
        else:
            try:
                answers = dns.resolver.query(domain, 'A')
                for answer in answers:
                    if answer.address in our_ip_list:
                        our_shit = True
            except dns.resolver.NoNameservers:
                logger.info("%s -- SUPER BAD (domain not registered or no NS records)", domain)
                return foolist
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                logger.info("%s -- SUPER BAD (name server found but no A record)", domain)
                return foolist
            except dns.exception.Timeout:
                logger.info("%s -- SUPER BAD (NS timeout)", domain)
                return foolist

        try:
            code = self.get_code(domain)
        except urllib2.HTTPError, e:
            if our_shit:
                logger.info("%s retuned %s -- BAD", domain, e.code)
            else:
                logger.info("%s retuned %s -- BAD (Not our problem hosted at %s)", domain, e.code, answer.address)
        except urllib2.URLError, e:
            if our_shit:
                logger.info("%s retuned %s -- BAD", domain, e.reason)
            else:
                logger.info("%s retuned %s -- BAD (Not our problem hosted at %s)", domain, e.reason, answer.address)
        except socket.timeout, e:
            if our_shit:
                logger.info("%s retuned %s -- BAD", domain, e)
            else:
                logger.info("%s retuned %s -- BAD (Not our problem hosted at %s)", domain, e, answer.address)

        if code in (200, 301, 302):

            if our_shit:
                logger.info("%s retuned %s -- OK", domain, code)
            else:
                logger.info("%s retuned %s -- OK (Not our problem hosted at %s)", domain, code, answer.address)
            oklist.append(domain)
        else:
            foolist.append(domain)
        return foolist


if __name__ == "__main__":

    parser = OptionParser()

    parser.usage = "%prog [options]" + __doc__

    parser.add_option("-n", "--nginx-conf-dir", dest="nginx_dir",
                      help="directory with nginx conf files", metavar="NDIR")
    parser.add_option("-a", "--apache-conf-dir", dest="apache_dir",
                      help="directory with apache conf files", metavar="ADIR")
    parser.add_option("-l", "--log-dir", dest="logdir",
                      help="write report to LOGDIR", metavar="LOGDIR")
    parser.add_option("-d", "--debug",
                      dest="debug", default=False,
                      help="debug mode")
    parser.add_option("-i", "--ips",
                      dest="ips", default=None,
                      help="ip or ips of our server (will activate dns resolver)")

    args = parser.parse_args()[0]

    logger = get_logger(args.logdir, args.debug)

    logger.info('Starting ...')

    p = Parser()

    nginx_domains, apache_domains = {}, {}
    if getattr(args, 'nginx_dir') is not None:
        nginx_domains = p.parse_nginx_dir(args.nginx_dir)
    if getattr(args, 'apache_dir') is not None:
        apache_domains = p.parse_apache_dir(args.apache_dir)


    if args.ips:
        try:
            import dns.resolver
        except ImportError:
            print 'You need to install python-pythondns package.'

    if not (nginx_domains or apache_domains):
        print 'No domains found !'
        logger.info('No domains found !')
        sys.exit(1)

    logger.info("Start checking the domains ...")

    domains = nginx_domains.keys() + apache_domains.keys()
    logger.info("Total numbers of domains %s ...", len(domains))
    if args.ips:
        dc = DomainChecker()
        for domain in domains:
            dc.check_domain(domain, args.ips)

    logger.info("Ending ...\n\n\n")
