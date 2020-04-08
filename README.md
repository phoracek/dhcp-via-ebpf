# DHCP via eBPF

The goal of this project is to present a proof-of-concept of a DHCP server
listening on a tap device and answering all DHCP requests from a VM with static
IP assignment. This should be done for both IPv4 and IPv6, where with IPv6 we
also need to figure out router advertisement. All these tasks should be done via
eBPF, without a need to keep a process running in user-space.

## Dependencies

```bash
dnf install -y bcc-tools
```

## TODO

- [ ] Setup testing infrastracture, a simple QEMU VM connected to a TAP device
      and console access.
- [ ] Static IPv4 DHCP server
- [ ] Static IPv6 DHCP server
- [ ] IPv6 router advertisement
