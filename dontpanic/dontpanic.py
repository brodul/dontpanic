#! /usr/bin/env python
"""
Script lists all uncommented domains/subdomains in a nginx or apache config directory.

Domains/subdomains can be checked for current status. 

The domain is checked if the there is a DNS record for the domain and
(if possible) for the HTTP return code.

Optionaly you can provide the ip of you server and the script will check
if the domain is hosted on your server or not.
"""
from optparse import OptionParser
import logging
import logging.handlers
import os
import sys
import urllib2
import socket

import dns.resolver


logger = logging.getLogger(__name__)
logger.setLevel('CRITICAL')

def get_logger(logdir=None, debug=False):
    """Return a logger for the dontpanic script."""
    logname = 'dontpanic.log'

    logdir = logdir or '.'
    debug = debug or False

    logger = logging.getLogger(__name__)

    if debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)

    logfile_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logdir, logname)
    )
    stream_handler = logging.StreamHandler()

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


class default_dict(dict):
    """A dictionary that creates a dictionary for missing key.

    This dictionary extension makes writting dict trees more simple.

    """
    
    def __missing__(self, key):
        self[key] = default_dict()
        return self[key]


class Parser(object):

    def _file_list(self, directory, excluded=""):
        """Yield all files in a directory recursive.
    
        Optional a string files to exclude can be set.    

        """
        for dirname, dirnames, filenames in os.walk(directory):
            for filename in filenames:
                if filename not in excluded:
                    yield os.path.join(dirname, filename)
    
    def get_line(self, conf_file):
        """ Yield line by line of a file with its line number and filename"""
        logger.debug("Starting parsing %s conf file: %s", self.deamon, conf_file)
        with open(conf_file) as conf:
            for num, line in enumerate(conf, 1):
                yield conf_file, num, line
        logger.debug("Parsing %s conf: %s completed\n", self.deamon, conf_file)

    def parser(self):
        raise NotImplementedError("Subclasses should implement this !")

    def create_tree_from_file(self, conf, tree=None):
        domains = tree or default_dict()
        for conf, num, line in self.get_line(conf):
            for domain in self.parser(line):
                if not conf in domains[domain]:
                    domains[domain]["config_files"][self.deamon][conf]["line_numbers"] = []
                domains[domain]["config_files"][self.deamon][conf]["line_numbers"].append(num)
                logger.info("Added %s domain from %s conf file: %s in line %s", self.deamon, domain, conf, num)
        return domains

    def create_tree_from_dir(self, directory):
        domains = default_dict()
        for conf in self._file_list(directory):
            domains = self.create_tree_from_file(conf, domains)
        return domains


class NginxParser(Parser):

    def __init__(self):
        self.deamon = "nginx"

    def parser(self, line):
        if "server_name " in line and not line.strip().startswith('#'):
            line_domains = line.strip().replace("server_name ", "")
            line_domains = line_domains.replace(";", "").split()
            for domain in line_domains:
                yield domain


class ApacheParser(Parser):

    def __init__(self):
        self.deamon = "apache"

    def parser(self, line):
        if "ServerAlias" in line and not line.strip().startswith('#'):
            line_domains = line.strip().replace("ServerAlias", "").split()
            for domain in line_domains:
                yield domain.split(":")[0]


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
