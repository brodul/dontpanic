import urllib2
import socket

import dns.resolver

from log import logger


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
        response = self.opener.open(
            self._build_request(url),
            timeout=self.timeout
        )
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
                logger.info(
                    "%s -- SUPER BAD (domain not registered or no NS records)",
                    domain
                )
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
