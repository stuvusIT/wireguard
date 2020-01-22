#!/usr/bin/env python3
"""
TODO
"""

# standard imports
import argparse
import collections
import json
import logging
import signal
import socket
import subprocess
import sys

# installed modules
import pyroute2


class Prefix(collections.namedtuple('Prefix', 'network prefix_len')):
    """
    TODO
    """
    @staticmethod
    def parse(prefix_str):
        """
        TODO
        """
        split = prefix_str.split("/")
        return Prefix(parse_ip(split[0]), int(split[1]))

    @staticmethod
    def is_subset(lhs, rhs):  # lhs and rhs of type Prefix
        """
        TODO
        """
        suffix_len = 32 - rhs.prefix_len
        return lhs.prefix_len >= rhs.prefix_len and (
            lhs.network >> suffix_len) == (rhs.network >> suffix_len)

    @staticmethod
    def is_strict_subset(lhs, rhs):  # lhs and rhs of type Prefix
        """
        TODO
        """
        suffix_len = 32 - rhs.prefix_len
        return lhs.prefix_len > rhs.prefix_len and (
            lhs.network >> suffix_len) == (rhs.network >> suffix_len)

    def __str__(self):
        result = ""
        network = self.network
        for i in [24, 16, 8, 0]:
            result += str(network // (1 << i))
            network %= (1 << i)
            if i != 0:
                result += "."
        result += "/"
        result += str(self.prefix_len)
        return result


def main():
    """
    TODO
    """
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigterm)

    args = parse_args()

    logging.getLogger().setLevel(args.log_level)

    config_path = args.config
    try:
        with open(config_path, "r") as config:
            config = json.load(config)
    except (OSError, json.JSONDecodeError) as exc:
        logging.error("Failed to parse config. The error is printed below.")
        logging.info(exc)
        sys.exit(2)

    if 'instances' not in config:
        logging.error("Configuration key 'instances' is required.")
        sys.exit(3)
    instances = config['instances']

    if not isinstance(instances, dict):
        logging.error("Configuration key 'instances' must be a dict.")
        sys.exit(4)

    if instances == {}:
        logging.warning("wgsyncer was not configured to sync anything.")
    else:
        try:
            instances = {interface_name: table_lookup(
                table) for interface_name, table in instances.items()}
        except ValueError as exc:
            logging.error(
                "Failed to parse a table name in the config. The error is printed below.")
            logging.info(exc)
            sys.exit(5)
        for interface_name, table in instances.items():
            logging.info("Configured to sync table %s into dev %s.", table, interface_name)

    run_wgsyncer(instances)

    sys.exit(1)


def handle_sigint(_sig, _frame):
    """
    TODO
    """
    logging.info("Received SIGINT. Exiting.")
    sys.exit(0)


def handle_sigterm(_sig, _frame):
    """
    TODO
    """
    logging.info("Received SIGTERM. Exiting.")
    sys.exit(0)


def parse_args():
    """
    TODO
    """
    parser = argparse.ArgumentParser(
        description="Synchronize routes into WireGuard allowed-ips.")
    parser.add_argument("-c", "--config", nargs=1, metavar="config_path",
                        default="wgsyncer.json", help="Path to the configuration file")
    parser.add_argument("--log-level", metavar="log_level",
                        default="INFO", help="Logging level")
    return parser.parse_args()


def table_lookup(table_name):
    """
    TODO
    """
    table_name = table_name.lower()
    if table_name == "local":
        return 255
    if table_name == "main":
        return 254
    if table_name == "default":
        return 253
    if table_name == "unspecified":
        return 0
    if table_name == "none":
        return -1
    return int(table_name)


def run_wgsyncer(instances):
    """
    TODO
    """
    with pyroute2.IPRoute() as ipr:
        sync_allowed_ips(ipr, instances)
        command = ["ip", "monitor", "route"]
        proc = subprocess.Popen(
            command, stdout=subprocess.PIPE, encoding="utf-8")
        logging.info("+ %s", " ".join(command))
        for line in iter(proc.stdout.readline, ""):
            logging.info("Monitored: %s", line.rstrip())
            sync_allowed_ips(ipr, instances)
        returncode = proc.wait()
        logging.error("`%s` exited with code %s.", " ".join(command), returncode)


def sync_allowed_ips(ipr, instances):
    """
    TODO
    """
    for interface_name, table in instances.items():
        interface = next(iter(ipr.link_lookup(ifname=interface_name)), None)
        if interface is None:
            logging.warning(
                "Attempted to sync table %s into dev %s, but dev %s does not exist.",
                table, interface_name, interface_name)
            continue
        logging.info("Starting to sync table %s into dev %s.", table, interface_name)
        old_allowed_ips = read_allowed_ips(interface_name)
        new_allowed_ips_dict = calc_new_allowed_ips_dict(
            ipr, old_allowed_ips, table, interface)
        set_allowed_ips(interface_name, new_allowed_ips_dict)
        logging.info("Finished syncing table %s into dev %s.", table, interface_name)


def read_allowed_ips(interface_name):
    """
    TODO
    """
    allowed_ips = []
    command = ["wg", "show", interface_name, "allowed-ips"]
    logging.info("+ %s", " ".join(command))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, encoding="utf-8")
    for line in iter(proc.stdout.readline, ""):
        line = line.rstrip()
        line_split = line.split("\t")
        pubkey = line_split[0]
        if line_split[1] != '(none)':
            for ip_str in line_split[1].split(" "):
                prefix = Prefix.parse(ip_str)
                allowed_ips.append((pubkey, prefix))
    returncode = proc.wait()
    if returncode != 0:
        logging.error("subprocess exited with code %s.", returncode)
    return sorted(allowed_ips, key=lambda a: -a[1].prefix_len)


def calc_new_allowed_ips_dict(ipr, old_allowed_ips, table, interface):
    """
    TODO
    """
    new_allowed_ips_dict = collections.defaultdict(lambda: [])
    for route in ipr.get_routes(
            family=socket.AF_INET, table=table, oif=interface):
        attrs = dict(route["attrs"])
        prefix_len = route["dst_len"]
        prefix = Prefix(0 if prefix_len == 0 else parse_ip(attrs["RTA_DST"]), prefix_len)
        if route["scope"] == 253:
            generator = convert_link_route(old_allowed_ips, prefix)
        else:
            generator = convert_global_route(
                old_allowed_ips, prefix, parse_ip(attrs["RTA_GATEWAY"]))
        for allowed_ip in generator:
            new_allowed_ips_dict[allowed_ip[0]].append(allowed_ip[1])

    def filtered_prefix_list(prefix_list):
        def should_keep(prefix):
            return all(map(lambda other_prefix: not Prefix.is_strict_subset(
                prefix, other_prefix), prefix_list))
        return list(filter(should_keep, prefix_list))
    return {pubkey: filtered_prefix_list(
        prefix_list) for pubkey, prefix_list in new_allowed_ips_dict.items()}


def parse_ip(ip_str):
    """
    TODO
    """
    split = ip_str.split(".")
    ip_int = 0
    for block in split:
        ip_int *= 256
        ip_int += int(block)
    return ip_int


def convert_link_route(old_allowed_ips, prefix):
    """
    TODO
    """
    for entry in old_allowed_ips:
        if Prefix.is_subset(prefix, entry[1]):
            yield (entry[0], prefix)
            break
        if Prefix.is_subset(entry[1], prefix):
            yield entry


def convert_global_route(old_allowed_ips, prefix, gateway):
    """
    TODO
    """
    for entry in old_allowed_ips:
        if Prefix.is_subset(Prefix(gateway, 32), entry[1]):
            yield (entry[0], prefix)
            break


def set_allowed_ips(interface_name, allowed_ips_dict):
    """
    TODO
    """
    for pubkey, prefix_list in sorted(allowed_ips_dict.items()):
        comma_separated_prefix_list = ",".join(map(str, prefix_list))
        command = ["wg", "set", interface_name, "peer",
                   pubkey, "allowed-ips", comma_separated_prefix_list]
        logging.info("+ %s", " ".join(command))
        try:
            subprocess.run(command, check=True)
        except subprocess.CalledProcessError as exc:
            logging.error("subprocess exited with code %s.", exc.returncode)


if __name__ == "__main__":
    main()
