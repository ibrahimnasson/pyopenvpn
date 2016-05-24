pyopenvpn
=========

Finally, a simple OpenVPN client entierely in python as a module.  
This is still mostly a WIP but can connect to some OpenVPN servers and use the
tunnel to send and receive data and even integrates nicely with scapy.  

There is an example ping program that can ping a remote host through an OpenVPN
server when given an OpenVPN configuration file, without requiring root
privileges or a tun device.


## Why would you do that?

- To try to understand and implement the OpenVPN protocol in less than
  a fuckton of old C.
- A small and self contained client, that can be used to test and monitor
  OpenVPN servers without root privileges and tun.
  It will make a nice nagios/zabbix plugin.
- A basic client to use when tun is not available.


## OpenVPN Compatibility / TODO list

- Config file: It get parsed (including inline files), some options are even used.
- Mode: Only tls-client.
- Ciphers: Only BF-CBC is implemented. (default)
- Protocol: Only UDPv4.
- HMAC: Only SHA1. (default)
- Compression: TODO
- tls-auth: TODO
- Bridged/Routed: Only routed networks are supported for now (tun).

