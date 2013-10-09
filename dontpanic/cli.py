#! /usr/bin/env python
"""
Script lists all uncommented domains/subdomains in a nginx or apache config directory.

Domains/subdomains can be checked for current status.

The domain is checked if the there is a DNS record for the domain and
(if possible) for the HTTP return code.

Optionaly you can provide the ip of you server and the script will check
if the domain is hosted on your server or not.
"""
import argparse

from log import get_logger
from parse import NginxParser
from parse import ApacheParser
from domain import DomainChecker


def main(args):

    logger = get_logger(args.logdir, args.debug)

    logger.info('Starting ...')

    nginx_parser = NginxParser()
    apache_parser = ApacheParser()

    nginx_domains, apache_domains = {}, {}
    if getattr(args, 'nginx_dir') is not None:
        nginx_domains = nginx_parser.create_tree_from_dir(args.nginx_dir)
    if getattr(args, 'apache_dir') is not None:
        apache_domains = apache_parser.create_tree_from_dir(args.apache_dir)

    logger.info("Start checking the domains ...")

    domains = nginx_domains.keys() + apache_domains.keys()
    logger.info("Total numbers of domains %s ...", len(domains))
    if args.ips:
        dc = DomainChecker()
        for domain in domains:
            dc.check_domain(domain, args.ips)

    logger.info("Ending ...\n")

if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("-n", "--nginx-conf-dir", dest="nginx_dir",
                      help="directory with nginx conf files", metavar="NDIR")
    parser.add_argument("-a", "--apache-conf-dir", dest="apache_dir",
                      help="directory with apache conf files", metavar="ADIR")
    parser.add_argument("-l", "--log-dir", dest="logdir",
                      help="write report to LOGDIR", metavar="LOGDIR")
    parser.add_argument("-d", "--debug",
                      dest="debug", default=False,
                      help="debug mode")
    parser.add_argument("-i", "--ips",
                      dest="ips", default=None,
                      help="ip or ips of our server (will activate dns resolver)")

    args = parser.parse_args()

    if not (args.nginx_dir or args.apache_dir):
        parser.error('No action requested, add -n or -a.')

    main(args)
