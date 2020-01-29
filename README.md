# Ansible role for installing WireGuard from Debian testing

This role installs WireGuard from Debian testing.
WireGuard is not available in Debian stable, yet.

This role can not configure WireGuard.
For configuring WireGuard you can use our
[systemd-network role](https://github.com/stuvusIT/systemd-network).
If you wish so, then read [#configuring-wireguard](#configuring-wireguard).

## Example Playbook

The following is a minimal example playbook using this role.

```yml
- hosts: wg-server01
  become: true
  roles:
    - role: wireguard
```

## Configuring WireGuard

The following is an example playbook if you wish to additionally use our
[systemd-network role](https://github.com/stuvusIT/systemd-network)
in order to configure WireGuard.

```yml
- hosts: wg-server01
  become: true
  roles:
    - role: wireguard
    - role: systemd-network
      systemd_network_netdevs:
        # /etc/systemd/network/*.netdev files are configured here
      systemd_network_networks:
        # /etc/systemd/network/*.network files are configured here
```

Hereby you have to make yourself familiar with how to configure WireGuard
using systemd-networkd.
Then refer to our
[systemd-network role](https://github.com/stuvusIT/systemd-network)
documentation in order to learn how to accordingly populate the `systemd_network_netdevs`
and `systemd_network_networks` role variables.

## Synchronize a routing table into WireGuard allowed-ips

This role supports synchronizing a routing table into the allowed-ips of a
WireGuard interface.
To do so, simply use the role variable `wireguard_synchronize_allowed_ips` as
in the following example, where the `main` routing table is synchronized into
the allowed-ips of the WireGuard interface `wg0`.

```yml
- hosts: wg-server01
  become: true
  roles:
    - role: wireguard
      wireguard_synchronize_allowed_ips:
        wg0: main
    - role: systemd-network
      systemd_network_netdevs:
        # /etc/systemd/network/*.netdev files are configured here
      systemd_network_networks:
        # /etc/systemd/network/*.network files are configured here
```

You can do this for any number of WireGuard interfaces.
Note that they also have to be configured, for example using our
[systemd-network role](https://github.com/stuvusIT/systemd-network).
