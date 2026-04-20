#!/usr/bin/env python3
"""
Campus 3-layer topology (Core -> Distribution -> Access) + DMZ on Mininet.

Confirmed IP plan (summary):
- VLAN subnets (Inside):
  VLAN10  Admin        10.10.10.0/24   GW 10.10.10.1
  VLAN20  Sales        10.10.20.0/24   GW 10.10.20.1
  VLAN30  Engineering  10.10.30.0/24   GW 10.10.30.1
  VLAN40  QA           10.10.40.0/24   GW 10.10.40.1
  VLAN50  Finance      10.10.50.0/24   GW 10.10.50.1
  VLAN60  HR           10.10.60.0/24   GW 10.10.60.1
  VLAN70  IT           10.10.70.0/24   GW 10.10.70.1
  VLAN99  Mgmt         10.10.99.0/24   GW 10.10.99.1
- DMZ: 172.16.200.0/24, GW 172.16.200.1
- Public/Outside: 203.0.113.0/24
  core outside: 203.0.113.2/24, internet host: 203.0.113.1/24
- OSPF/Router links (/30):
  core <-> dist1: 10.255.0.0/30  core=10.255.0.1  dist1=10.255.0.2
  core <-> dist2: 10.255.0.4/30  core=10.255.0.5  dist2=10.255.0.6

NAT plan (on core router):
- PAT (MASQUERADE) for 10.10.0.0/16 out to 203.0.113.0/24
- Static NAT (DNAT) for DMZ servers:
  203.0.113.11 -> 172.16.200.11 (web1, tcp 80/443)
  203.0.113.12 -> 172.16.200.12 (web2, tcp 80/443)
  203.0.113.53 -> 172.16.200.53 (dns, udp/tcp 53)

ACLs are applied by source/acl.sh via ip netns exec. This file creates
/var/run/netns/<node> symlinks so acl.sh can target namespaces by name.
"""

import os
import sys
import time
from dataclasses import dataclass

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import Node, OVSSwitch
from mininet.topo import Topo


class LinuxRouter(Node):
    """A Node with IPv4 forwarding enabled (acts as a router)."""

    def config(self, **params):
        super().config(**params)
        self.cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null")
        self.cmd("sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null")
        self.cmd("sysctl -w net.ipv4.conf.default.rp_filter=0 >/dev/null")

    def terminate(self):
        self.cmd("sysctl -w net.ipv4.ip_forward=0 >/dev/null")
        super().terminate()


@dataclass(frozen=True)
class Subnet:
    cidr: str
    gw: str


VLAN_SUBNETS = {
    "admin": Subnet("10.10.10.0/24", "10.10.10.1"),
    "sales": Subnet("10.10.20.0/24", "10.10.20.1"),
    "eng": Subnet("10.10.30.0/24", "10.10.30.1"),
    "qa": Subnet("10.10.40.0/24", "10.10.40.1"),
    "finance": Subnet("10.10.50.0/24", "10.10.50.1"),
    "hr": Subnet("10.10.60.0/24", "10.10.60.1"),
    "it": Subnet("10.10.70.0/24", "10.10.70.1"),
    "mgmt": Subnet("10.10.99.0/24", "10.10.99.1"),
}

DMZ_SUBNET = Subnet("172.16.200.0/24", "172.16.200.1")

# Router links
CORE_DIST1_CORE_IP = "10.255.0.1/30"
CORE_DIST1_DIST_IP = "10.255.0.2/30"
CORE_DIST2_CORE_IP = "10.255.0.5/30"
CORE_DIST2_DIST_IP = "10.255.0.6/30"

# Outside
CORE_OUTSIDE_IP = "203.0.113.2/24"
INTERNET_IP = "203.0.113.1/24"


class CampusTopo(Topo):
    def build(self):
        # Routers (Linux namespaces)
        core = self.addHost("core", cls=LinuxRouter, ip=None)
        dist1 = self.addHost("dist1", cls=LinuxRouter, ip=None)
        dist2 = self.addHost("dist2", cls=LinuxRouter, ip=None)

        # Internet host (outside)
        internet = self.addHost("internet", ip=None)

        # Distribution <-> Core links
        self.addLink(core, dist1, intfName1="core-d1", intfName2="d1-core")
        self.addLink(core, dist2, intfName1="core-d2", intfName2="d2-core")

        # Core <-> Internet link (outside)
        self.addLink(core, internet, intfName1="core-out", intfName2="inet0")

        def add_ovs_switch(name: str, dpid_int: int) -> str:
            """
            Explicit DPID is required on some systems; otherwise OVSSwitch may fail with:
              'Unable to derive default datapath ID'
            """
            return self.addSwitch(name, cls=OVSSwitch, stp=True, dpid=f"{dpid_int:016x}")

        # Access switches (one per department/VLAN) with explicit DPIDs
        access_switches = {
            "admin": add_ovs_switch("acc_admin", 101),
            "sales": add_ovs_switch("acc_sales", 102),
            "eng": add_ovs_switch("acc_eng", 103),
            "qa": add_ovs_switch("acc_qa", 104),
            "finance": add_ovs_switch("acc_fin", 105),
            "hr": add_ovs_switch("acc_hr", 106),
            "it": add_ovs_switch("acc_it", 107),
        }

        # Map VLANs to one of the two distributions (load share)
        dist_map = {
            "admin": dist1,
            "sales": dist1,
            "finance": dist1,
            "hr": dist1,
            "eng": dist2,
            "qa": dist2,
            "it": dist2,
        }

        # Uplink each access switch to its distribution router
        for dept, sw in access_switches.items():
            if dept not in dist_map:
                continue
            dist = dist_map[dept]
            dist_name = "dist1" if dist is dist1 else "dist2"
            self.addLink(dist_name, sw, intfName1=f"{dist_name}-{dept}", intfName2=f"{sw}-uplink")

        # Hosts per department (PC, IP phone, printer) - small but representative
        # You can scale counts later without changing routing/NAT/ACL design.
        for dept, subnet in VLAN_SUBNETS.items():
            if dept == "mgmt":
                continue
            if dept not in access_switches:
                continue
            sw = access_switches[dept]
            # Use .11, .21, .31 for (pc, phone, printer) in each /24
            base = int(subnet.gw.split(".")[-1])  # 1
            del base
            host_specs = [
                (f"{dept}_pc1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".11/24"),
                (f"{dept}_phone1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".21/24"),
                (f"{dept}_printer1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".31/24"),
            ]
            for hname, hip in host_specs:
                h = self.addHost(hname, ip=None)
                self.addLink(h, sw)

        # DMZ segment: switch + servers (explicit DPID)
        dmz_sw = add_ovs_switch("dmz_sw", 201)
        self.addLink("dist1", dmz_sw, intfName1="dist1-dmz", intfName2="dmz-uplink")

        dmz_web1 = self.addHost("dmz_web1", ip=None)
        dmz_web2 = self.addHost("dmz_web2", ip=None)
        dmz_dns = self.addHost("dmz_dns", ip=None)

        self.addLink(dmz_web1, dmz_sw)
        self.addLink(dmz_web2, dmz_sw)
        self.addLink(dmz_dns, dmz_sw)


def _ensure_netns_symlinks(net: Mininet) -> None:
    """
    Create /var/run/netns/<node> symlinks so scripts can use:
      ip netns exec <node> ...
    """
    os.system("mkdir -p /var/run/netns 2>/dev/null")
    for name, node in net.nameToNode.items():
        if hasattr(node, "pid"):
            pid = getattr(node, "pid")
            os.system(f"ln -sf /proc/{pid}/ns/net /var/run/netns/{name}")


def _config_host_ip(host, ip_cidr: str, gw_ip: str) -> None:
    host.cmd("ip addr flush dev " + host.defaultIntf().name)
    host.cmd(f"ip addr add {ip_cidr} dev {host.defaultIntf().name}")
    host.cmd("ip route flush default")
    host.cmd(f"ip route add default via {gw_ip}")


def _try_enable_ospf_or_static(net: Mininet) -> str:
    """
    Attempt to enable OSPF (FRR/quagga) if available; otherwise install static routes.
    Returns the mode: 'ospf' or 'static'.
    """
    # Minimal detection: vtysh presence and ospfd binary.
    has_vtysh = os.path.exists("/usr/bin/vtysh") or os.path.exists("/usr/local/bin/vtysh")
    has_ospfd = os.path.exists("/usr/lib/frr/ospfd") or os.path.exists("/usr/lib/quagga/ospfd")
    has_zebra = os.path.exists("/usr/lib/frr/zebra") or os.path.exists("/usr/lib/quagga/zebra")

    if has_vtysh and has_ospfd and has_zebra:
        info("*** Detected FRR/Quagga. Attempting OSPF enable via vtysh (best-effort)...\n")

        def vty(node, cmds: str) -> None:
            node.cmd(f"bash -lc 'printf \"%s\" \"{cmds}\" | vtysh -b' >/dev/null 2>&1")

        # Start daemons if service isn't running inside namespaces. Best-effort.
        for r in ["core", "dist1", "dist2"]:
            node = net[r]
            node.cmd("mkdir -p /var/run/frr /tmp/frr 2>/dev/null")
            node.cmd("touch /tmp/frr/zebra.conf /tmp/frr/ospfd.conf")
            node.cmd("chown -R frr:frr /tmp/frr 2>/dev/null || true")
            node.cmd("/usr/lib/frr/zebra -d -A 127.0.0.1 -f /tmp/frr/zebra.conf -i /tmp/frr/zebra.pid >/dev/null 2>&1 || true")
            node.cmd("/usr/lib/frr/ospfd -d -A 127.0.0.1 -f /tmp/frr/ospfd.conf -i /tmp/frr/ospfd.pid >/dev/null 2>&1 || true")

        # Router-IDs
        vty(net["core"], "conf t\nrouter ospf\nospf router-id 1.1.1.1\nend\n")
        vty(net["dist1"], "conf t\nrouter ospf\nospf router-id 2.2.2.2\nend\n")
        vty(net["dist2"], "conf t\nrouter ospf\nospf router-id 3.3.3.3\nend\n")

        # Network statements (keep small: p2p + VLANs + DMZ + outside on core)
        vty(net["core"], "conf t\nrouter ospf\nnetwork 10.255.0.0/30 area 0\nnetwork 10.255.0.4/30 area 0\nnetwork 203.0.113.0/24 area 0\nend\n")
        vty(net["dist1"], "conf t\nrouter ospf\nnetwork 10.255.0.0/30 area 0\nnetwork 10.10.10.0/24 area 0\nnetwork 10.10.20.0/24 area 0\nnetwork 10.10.50.0/24 area 0\nnetwork 10.10.60.0/24 area 0\nnetwork 172.16.200.0/24 area 0\nend\n")
        vty(net["dist2"], "conf t\nrouter ospf\nnetwork 10.255.0.4/30 area 0\nnetwork 10.10.30.0/24 area 0\nnetwork 10.10.40.0/24 area 0\nnetwork 10.10.70.0/24 area 0\nend\n")

        info("*** OSPF configured (best-effort). Waiting 5s for convergence...\n")
        time.sleep(5)
        return "ospf"

    info("*** FRR/Quagga not available. Using static routes.\n")

    # Static routes:
    # - Dist routers default route to core.
    net["dist1"].cmd("ip route replace default via 10.255.0.1")
    net["dist2"].cmd("ip route replace default via 10.255.0.5")
    # - Core routes to VLANs behind dist routers, plus DMZ behind dist1.
    for cidr in ["10.10.10.0/24", "10.10.20.0/24", "10.10.50.0/24", "10.10.60.0/24", "172.16.200.0/24"]:
        net["core"].cmd(f"ip route replace {cidr} via 10.255.0.2")
    for cidr in ["10.10.30.0/24", "10.10.40.0/24", "10.10.70.0/24"]:
        net["core"].cmd(f"ip route replace {cidr} via 10.255.0.6")

    # Default route out from core to internet host (simulate ISP gateway)
    net["core"].cmd("ip route replace default via 203.0.113.1")
    return "static"


def _setup_nat(core) -> None:
    """
    Configure PAT + Static NAT for DMZ on core router using iptables.
    """
    core.cmd("iptables -t nat -F")
    core.cmd("iptables -F")

    # Allow forwarding (baseline)
    core.cmd("iptables -P FORWARD DROP")
    core.cmd("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # PAT overload for inside users
    core.cmd("iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o core-out -j MASQUERADE")

    # DMZ servers static NAT (DNAT) from public pool
    # Web1 203.0.113.11 -> 172.16.200.11
    core.cmd("iptables -t nat -A PREROUTING -i core-out -p tcp -d 203.0.113.11 -m multiport --dports 80,443 -j DNAT --to-destination 172.16.200.11")
    core.cmd("iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.11 -m multiport --dports 80,443 -j ACCEPT")

    # Web2 203.0.113.12 -> 172.16.200.12
    core.cmd("iptables -t nat -A PREROUTING -i core-out -p tcp -d 203.0.113.12 -m multiport --dports 80,443 -j DNAT --to-destination 172.16.200.12")
    core.cmd("iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.12 -m multiport --dports 80,443 -j ACCEPT")

    # DNS 203.0.113.53 -> 172.16.200.53
    core.cmd("iptables -t nat -A PREROUTING -i core-out -p udp -d 203.0.113.53 --dport 53 -j DNAT --to-destination 172.16.200.53")
    core.cmd("iptables -t nat -A PREROUTING -i core-out -p tcp -d 203.0.113.53 --dport 53 -j DNAT --to-destination 172.16.200.53")
    core.cmd("iptables -A FORWARD -i core-out -o core-d1 -p udp -d 172.16.200.53 --dport 53 -j ACCEPT")
    core.cmd("iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.53 --dport 53 -j ACCEPT")

    # Allow inside -> internet (basic). ACL hardening is done by acl.sh, not here.
    core.cmd("iptables -A FORWARD -i core-d1 -o core-out -s 10.10.0.0/16 -j ACCEPT")
    core.cmd("iptables -A FORWARD -i core-d2 -o core-out -s 10.10.0.0/16 -j ACCEPT")

    # Allow DMZ -> internet (useful for DNS updates etc.)
    core.cmd("iptables -A FORWARD -i core-d1 -o core-out -s 172.16.200.0/24 -j ACCEPT")
    core.cmd("iptables -t nat -A POSTROUTING -s 172.16.200.0/24 -o core-out -j MASQUERADE")


def configure(net: Mininet) -> None:
    info("*** Linking network namespaces for ip netns exec...\n")
    _ensure_netns_symlinks(net)

    info("*** Configuring router interfaces (core/dist)...\n")
    core = net["core"]
    dist1 = net["dist1"]
    dist2 = net["dist2"]
    internet = net["internet"]

    # Core <-> Dist links
    core.cmd(f"ip addr add {CORE_DIST1_CORE_IP} dev core-d1")
    dist1.cmd(f"ip addr add {CORE_DIST1_DIST_IP} dev d1-core")
    core.cmd(f"ip addr add {CORE_DIST2_CORE_IP} dev core-d2")
    dist2.cmd(f"ip addr add {CORE_DIST2_DIST_IP} dev d2-core")

    # Core outside and internet host
    core.cmd(f"ip addr add {CORE_OUTSIDE_IP} dev core-out")
    internet.cmd(f"ip addr add {INTERNET_IP} dev inet0")
    internet.cmd("ip route replace default via 203.0.113.2")

    # Dist VLAN gateway interfaces to access switches
    # dist1 owns: admin,sales,finance,hr + DMZ
    dist1_vlan_ifaces = {
        "admin": ("dist1-admin", VLAN_SUBNETS["admin"].gw + "/24"),
        "sales": ("dist1-sales", VLAN_SUBNETS["sales"].gw + "/24"),
        "finance": ("dist1-finance", VLAN_SUBNETS["finance"].gw + "/24"),
        "hr": ("dist1-hr", VLAN_SUBNETS["hr"].gw + "/24"),
        "dmz": ("dist1-dmz", DMZ_SUBNET.gw + "/24"),
    }
    for _, (ifname, ip_cidr) in dist1_vlan_ifaces.items():
        dist1.cmd(f"ip addr add {ip_cidr} dev {ifname}")

    # dist2 owns: eng,qa,it
    dist2_vlan_ifaces = {
        "eng": ("dist2-eng", VLAN_SUBNETS["eng"].gw + "/24"),
        "qa": ("dist2-qa", VLAN_SUBNETS["qa"].gw + "/24"),
        "it": ("dist2-it", VLAN_SUBNETS["it"].gw + "/24"),
    }
    for _, (ifname, ip_cidr) in dist2_vlan_ifaces.items():
        dist2.cmd(f"ip addr add {ip_cidr} dev {ifname}")

    # Configure department hosts: /24 + default GW at their VLAN gateway
    info("*** Configuring access hosts IP/gateway...\n")
    for dept, subnet in VLAN_SUBNETS.items():
        if dept == "mgmt":
            continue
        for suffix, role in [("11", "pc1"), ("21", "phone1"), ("31", "printer1")]:
            hname = f"{dept}_{role}"
            if hname not in net:
                continue
            ip_prefix = subnet.cidr.split("/")[0].rsplit(".", 1)[0]
            hip = f"{ip_prefix}.{suffix}/24"
            _config_host_ip(net[hname], hip, subnet.gw)

    # DMZ servers
    _config_host_ip(net["dmz_web1"], "172.16.200.11/24", DMZ_SUBNET.gw)
    _config_host_ip(net["dmz_web2"], "172.16.200.12/24", DMZ_SUBNET.gw)
    _config_host_ip(net["dmz_dns"], "172.16.200.53/24", DMZ_SUBNET.gw)

    # Routing: OSPF if available else static
    info("*** Configuring routing (OSPF if available, else static routes)...\n")
    mode = _try_enable_ospf_or_static(net)
    info(f"*** Routing mode: {mode}\n")

    # NAT/PAT on core
    info("*** Configuring NAT/PAT (core)...\n")
    _setup_nat(core)

    info("*** Done. You can now test in CLI.\n")
    info("    Examples:\n")
    info("      mininet> admin_pc1 ping -c 2 203.0.113.1\n")
    info("      mininet> admin_pc1 ping -c 2 8.8.8.8   (if you add further upstream)\n")
    info("      mininet> internet ping -c 2 203.0.113.11   (public -> dmz_web1)\n")
    info("      mininet> internet nc -zv 203.0.113.11 80   (if netcat is installed)\n")
    info("      Apply ACLs: sudo bash source/acl.sh\n")
    info("      Drop ACLs : sudo bash source/acl.sh dropacl\n")


def mn_cleanup() -> None:
    info("*** Cleanup old Mininet state...\n")
    os.system("rm -f /var/run/netns/core /var/run/netns/dist1 /var/run/netns/dist2 /var/run/netns/internet 2>/dev/null")
    os.system("sudo mn -c 2>/dev/null")
    os.system("iptables -t nat -F 2>/dev/null")
    os.system("iptables -F 2>/dev/null")


def run() -> None:
    topo = CampusTopo()
    net = Mininet(topo=topo, controller=None, autoSetMacs=True, autoStaticArp=True)
    net.start()
    configure(net)
    CLI(net)
    net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    if os.geteuid() != 0:
        print("Hãy chạy với quyền root: sudo python3 source/topology.py")
        sys.exit(1)
    if "--clean" in sys.argv or "-c" in sys.argv:
        mn_cleanup()
        sys.exit(0)
    mn_cleanup()
    run()

