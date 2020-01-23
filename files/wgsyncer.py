#!/usr/bin/env python3
"""
See:
    $ python3 wgsyncer.py --help
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
    Data structure for storing an (IP) prefix.

    Attributes:
        network (int): Network address, represented as int. See parse_ip.
        prefix_len (int): Prefix length of the network.
    """
    @staticmethod
    def parse(prefix_str: str):
        """
        Converts a prefix given as str into a Prefix object.

        Example:
            Prefix.parse("192.168.100.0/24")
        """
        split = prefix_str.split("/")
        return Prefix(parse_ip(split[0]), int(split[1]))

    @staticmethod
    def is_subset(lhs: "Prefix", rhs: "Prefix"):
        """Returns true iff all IPs belonging to lhs also belong to rhs."""
        suffix_len = 32 - rhs.prefix_len
        return lhs.prefix_len >= rhs.prefix_len and (
            lhs.network >> suffix_len) == (rhs.network >> suffix_len)

    @staticmethod
    def is_strict_subset(lhs: "Prefix", rhs: "Prefix"):
        """Returns true iff lhs != rhs and all IPs belonging to lhs also belong to rhs."""
        suffix_len = 32 - rhs.prefix_len
        return lhs.prefix_len > rhs.prefix_len and (
            lhs.network >> suffix_len) == (rhs.network >> suffix_len)

    def __str__(self):
        """
        Implements conversion to str.

        Example:
            str(Prefix.parse("192.168.100.0/24")) == "192.168.100.0/24"
        """
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
    """This is the main function called when wgsyncer.py is run."""
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
    """Exit successfully on SIGINT. This handler is registered in main()."""
    logging.info("Received SIGINT. Exiting.")
    sys.exit(0)


def handle_sigterm(_sig, _frame):
    """Exit successfully on SIGTERM. This handler is registered in main()."""
    logging.info("Received SIGTERM. Exiting.")
    sys.exit(0)


def parse_args():
    """
    Parses arguments. See:
        $ python3 wgsyncer.py --help
    """
    parser = argparse.ArgumentParser(
        description="""
When using dynamic routing one is inclined to give every (trusted) peer of a
WireGuard interface the allowed IPs 0.0.0.0/0. However, multiple peers of a
WireGuard interface cannot have overlapping allowed IPs.

The solution is this script which synchronizes a routing table into the allowed
IPs of a WireGuard interface.

In fact, this script can run multiple such instances. For each WireGuard
interface, at most one routing table can by synchronized into its allowed IPs.
This script needs a configuration file (defaults to "./wgsyncer.json")
specifying those instances.

Example:

```json
{
    "instances": {
        "wg0": "main"
    }
}
```""", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("-c", "--config", nargs=1, metavar="config_path",
                        default="wgsyncer.json", help="Path to the configuration file")
    parser.add_argument("--log-level", metavar="log_level",
                        default="INFO", help="Logging level")
    return parser.parse_args()


def table_lookup(table_name):
    """
    Turns the name of a routing table into the respective table ID. Note that only the standard
    table names and integers (possibly given as str) are supported.
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


def run_wgsyncer(instances: dict):
    """
    Runs the main logic.

    Args:
        instances (dict):
            a pair of a WireGuard interface name and a routing table (as int) to synchronize into
            the allowed IPs of that interface. instances is a dict, because for each WireGuard
            interface, at most one routing table can by synchronized into its allowed IPs. Since the
            tables are expected as int, you might want to use table_lookup beforehand.

    Example:
        run_wgsyncer({ "wg0": table_lookup("main") })
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


def sync_allowed_ips(ipr: pyroute2.IPRoute, instances: dict):
    """
    For each instance:
    1) Read the allowed IPs from the WireGuard interface.
    2) Compute the desired allowed IPs (based on the routing table).
    3) Set the allowed IPs for the WireGuard interface.

    Args:
        instances (dict): See documentation of run_wgsyncer(instances).
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


def read_allowed_ips(interface_name: str):
    """
    Read the allowed IPs from the WireGuard interface.

    Args:
        interface_name (str): Name of the WireGuard interface.

    Returns:
        list of pairs (pubkey: str, prefix: Prefx). That list is sorted by decreasing
        prefix.prefix_len (in order to allow faster lookup of smallest superset).
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


def calc_new_allowed_ips_dict(ipr: pyroute2.IPRoute, old_allowed_ips, table, interface):
    """
    Computes the desired allowed IPs for a WireGuard interface, based on the given routing table.

    Args:
        ipr (pyroute2.IPRoute): See https://docs.pyroute2.org/iproute.html
        old_allowed_ips (list):
            Old allowed IPs on the WireGuard interface. This is needed to match gateway IPs. The
            list should be as returned by read_allowed_ips.
        table (int): routing table to synchronize into the allowed IPs of the WireGuard interface.
        interface (int): ID of the WireGuard interface (as obtained by ipr.link_lookup).

    Returns:
        dict with pubkeys as key where each value is the respective list of allowed IPs (as Prefix
        objects).
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
    """Converts an ip from str to int."""
    split = ip_str.split(".")
    ip_int = 0
    for block in split:
        ip_int *= 256
        ip_int += int(block)
    return ip_int


def convert_link_route(old_allowed_ips, prefix):
    """
    Args:
        old_allowed_ips (list): See documentation of calc_new_allowed_ips_dict.
        prefix (Prefix): A prefix that is sent to the WireGuard interface for link-local routing.

    Returns:
        A generator yielding the allowed IPs that have to be added s.t. the prefix can be
        successfully routed to the WireGuard interface. Hereby each yielded element is a pair
        (pubkey: str, prefix: Prefx).
    """
    for entry in old_allowed_ips:
        if Prefix.is_subset(prefix, entry[1]):
            yield (entry[0], prefix)
            break
        if Prefix.is_subset(entry[1], prefix):
            yield entry


def convert_global_route(old_allowed_ips, prefix, gateway):
    """
    Args:
        old_allowed_ips (list): See documentation of calc_new_allowed_ips_dict.
        prefix (Prefix):
            A prefix that is sent to the WireGuard interface for global routing via some gateway.
        gateway (int): The gateway described above, given as int.

    Returns:
        See documentation of convert_link_route.
    """
    for entry in old_allowed_ips:
        if Prefix.is_subset(Prefix(gateway, 32), entry[1]):
            yield (entry[0], prefix)
            break


def set_allowed_ips(interface_name, allowed_ips_dict):
    """
    Sets the allowed IPs for a WireGuard interface.

    Args:
        interface_name (str): Name of the WireGuard interface.
        allowed_ips_dict (dict):
            dict with pubkeys as key where each value is the respective list of allowed IPs (as
            Prefix objects).
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
