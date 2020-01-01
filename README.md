# Ansible role for installing WireGuard from Debian testing

This role installs WireGuard from Debian testing.
WireGuard is not available in Debian stable, yet.

That's it!
This role is not configurable at all.
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
