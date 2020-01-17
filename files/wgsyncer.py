#!/usr/bin/env python3

import argparse
import collections
import json
import logging
import pyroute2
import signal
import socket
import subprocess


def parse_ip(ip_str):
    split = ip_str.split(".")
    ip = 0
    for block in split:
        ip *= 256
        ip += int(block)
    return ip


def parse_prefix(prefix_str):
    split = prefix_str.split("/")
    return Prefix(parse_ip(split[0]), int(split[1]))


class Prefix:
    def __init__(self, network, prefix_len):
        self.network = network
        self.prefix_len = prefix_len

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


def read_allowed_ips(interface_name):
    allowed_ips = []
    command = ["wg", "show", interface_name, "allowed-ips"]
    logging.info("+ " + " ".join(command))
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, encoding="utf-8")
    for line in iter(proc.stdout.readline, ""):
        line = line.rstrip()
        line_split = line.split("\t")
        pubkey = line_split[0]
        if line_split[1] != '(none)':
            for ip_str in line_split[1].split(" "):
                prefix = parse_prefix(ip_str)
                allowed_ips.append((pubkey, prefix))
    returncode = proc.wait()
    if returncode != 0:
        logging.error("subprocess exited with code {}.".format(returncode))
    return sorted(allowed_ips, key=lambda a: -a[1].prefix_len)


def is_ip_subset(lhs, rhs):  # lhs and rhs of type Prefix
    suffix_len = 32 - rhs.prefix_len
    return lhs.prefix_len <= rhs.prefix_len and (lhs.network >> suffix_len) == (rhs.network >> suffix_len)


def convert_link_route(old_allowed_ips, prefix):
    for entry in old_allowed_ips:
        if is_ip_subset(prefix, entry[1]):
            yield (entry[0], prefix)
            break
        elif is_ip_subset(entry[1], prefix):
            yield entry


def convert_global_route(old_allowed_ips, prefix, gateway):
    for entry in old_allowed_ips:
        if is_ip_subset(Prefix(gateway, 32), entry[1]):
            yield (entry[0], prefix)
            break

def calc_new_allowed_ips(old_allowed_ips, table, interface):
    new_allowed_ips_dict = collections.defaultdict(lambda: [])
    for route in ipr.get_routes(family=socket.AF_INET, table=table, oif=interface):
        attrs = dict(route["attrs"])
        prefix_len = route["dst_len"]
        print(route)
        prefix = Prefix(0 if prefix_len == 0 else parse_ip(attrs["RTA_DST"]), prefix_len)
        if route["scope"] == 253:
            generator = convert_link_route(old_allowed_ips, prefix)
        else:
            generator = convert_global_route(
                old_allowed_ips, prefix, parse_ip(attrs["RTA_GATEWAY"]))
        for allowed_ip in generator:
            new_allowed_ips_dict[allowed_ip[0]].append(allowed_ip[1])
    return new_allowed_ips_dict


def set_allowed_ips(allowed_ips_dict):
    for pubkey, prefix_list in sorted(allowed_ips_dict.items()):
        comma_separated_prefix_list = ",".join(map(str, prefix_list))
        command = ["wg", "set", interface_name, "peer",
                    pubkey, "allowed-ips", comma_separated_prefix_list]
        logging.info("+ " + " ".join(command))
        completed_proc = subprocess.run(command)
        if completed_proc.returncode != 0:
            logging.error("subprocess exited with code {}.".format(
                completed_proc.returncode))


def sync_allowed_ips(ipr, instances):
    for interface_name, table in instances.items():
        interface = next(iter(ipr.link_lookup(ifname=interface_name)), None)
        if interface is None:
            logging.warning("Attempted to sync table {} into dev {}, but dev {} does not exist.".format(
                table, interface_name, interface_name))
            continue
        logging.info("Starting to sync table {} into dev {}.".format(
            table, interface_name))
        old_allowed_ips = read_allowed_ips(interface_name)
        new_allowed_ips_dict = calc_new_allowed_ips(old_allowed_ips, table, interface)
        set_allowed_ips(new_allowed_ips_dict)
        logging.info("Finished syncing table {} into dev {}.".format(
            table, interface_name))


def table_lookup(table_name):
    table_name = table_name.lower()
    if table_name == "local":
        return 255
    elif table_name == "main":
        return 254
    elif table_name == "default":
        return 253
    elif table_name == "unspecified":
        return 0
    elif table_name == "none":
        return -1
    else:
        return int(table_name)


def handle_sigint(sig, frame):
    logging.info("Received SIGINT. Exiting.")
    exit(0)


def handle_sigterm(sig, frame):
    logging.info("Received SIGTERM. Exiting.")
    exit(0)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Synchronize routes into WireGuard allowed-ips.")
    parser.add_argument("-c", "--config", nargs=1, metavar="config_path",
                        default="wgsyncer.json", help="Path to the configuration file")
    parser.add_argument("--log-level", metavar="log_level",
                        default="INFO", help="Logging level")
    return parser.parse_args()


if __name__ == "__main__":
    signal.signal(signal.SIGINT, handle_sigint)
    signal.signal(signal.SIGTERM, handle_sigterm)

    args = parse_args()

    logging.getLogger().setLevel(args.log_level)

    config_path = args.config
    try:
        with open(config_path, "r") as config:
            config = json.load(config)
    except Exception as e:
        logging.error("Failed to parse config. The error is printed below.")
        logging.info(e)
        exit(2)

    if 'instances' not in config:
        logging.error("Configuration key 'instances' is required.")
        exit(3)
    instances = config['instances']

    if type(instances) != dict:
        logging.error("Configuration key 'instances' must be a dict.")
        exit(4)

    if instances == {}:
        logging.warning("wgsyncer was not configured to sync anything.")
    else:
        try:
            instances = {interface_name: table_lookup(
                table) for interface_name, table in instances.items()}
        except Exception as e:
            logging.error(
                "Failed to parse a table name in the config. The error is printed below.")
            logging.info(e)
            exit(5)
        for interface_name, table in instances.items():
            logging.info("Configured to sync table {} into dev {}.".format(
                table, interface_name))

    with pyroute2.IPRoute() as ipr:
        sync_allowed_ips(ipr, instances)
        command = ["ip", "monitor", "route"]
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, encoding="utf-8")
        logging.info("+ " + " ".join(command))
        for line in iter(proc.stdout.readline, ""):
            logging.info("Monitored: " + line.rstrip())
            sync_allowed_ips(ipr, instances)
        returncode = proc.wait()
        logging.error("`{}` exited with code {}.".format(
            " ".join(command), returncode))

    exit(1)
