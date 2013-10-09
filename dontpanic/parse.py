import os

from utils import default_dict


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

