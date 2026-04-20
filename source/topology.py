#!/usr/bin/env python3
"""
Mô hình Campus 3 lớp (Core -> Distribution -> Access) + vùng DMZ trên Mininet.

Tóm tắt IP plan đã chốt:
- Các VLAN Inside:
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
  core outside: 203.0.113.2/24, host internet: 203.0.113.1/24
- Các link giữa router (/30):
  core <-> dist1: 10.255.0.0/30  core=10.255.0.1  dist1=10.255.0.2
  core <-> dist2: 10.255.0.4/30  core=10.255.0.5  dist2=10.255.0.6

Kế hoạch NAT (đặt trên router core):
- PAT (MASQUERADE) cho 10.10.0.0/16 đi ra ngoài qua core-out
- Static NAT (DNAT) cho các server DMZ (Public -> DMZ):
  203.0.113.11 -> 172.16.200.11 (web1, tcp 80/443)
  203.0.113.12 -> 172.16.200.12 (web2, tcp 80/443)
  203.0.113.53 -> 172.16.200.53 (dns, udp/tcp 53)

ACL được áp bởi source/acl.sh thông qua `ip netns exec`.
File này tạo symlink `/var/run/netns/<node>` để script gọi namespace theo tên.
"""

import os
import sys
import time
from dataclasses import dataclass

from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.net import Mininet
from mininet.node import LinuxBridge, Node
from mininet.topo import Topo


class LinuxRouter(Node):
    """Node chạy như Router Linux (bật IPv4 forwarding)."""

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

# Linux giới hạn tên interface 15 ký tự (IFNAMSIZ=15). Mininet thường tạo tên:
#   <host>-eth0
# nên cần giữ hostname ngắn để tránh lỗi: "name not a valid ifname".
DEPT_ABBR = {
    "admin": "ad",
    "sales": "sa",
    "eng": "en",
    "qa": "qa",
    "finance": "fi",
    "hr": "hr",
    "it": "it",
}

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
        # Router L3 (Linux namespace)
        core = self.addHost("core", cls=LinuxRouter, ip=None)
        dist1 = self.addHost("dist1", cls=LinuxRouter, ip=None)
        dist2 = self.addHost("dist2", cls=LinuxRouter, ip=None)

        # Host Internet giả lập (Outside)
        internet = self.addHost("internet", ip=None)

        # Link Core <-> Distribution
        self.addLink(core, dist1, intfName1="core-d1", intfName2="d1-core")
        self.addLink(core, dist2, intfName1="core-d2", intfName2="d2-core")

        # Link Core <-> Internet (Outside)
        self.addLink(core, internet, intfName1="core-out", intfName2="inet0")

        # Switch L2: dùng LinuxBridge để tránh phụ thuộc Controller của OVS.
        # (OVS nếu failMode=secure + không có controller có thể không forward -> ping không thông)
        def add_l2_switch(name: str) -> str:
            return self.addSwitch(name, cls=LinuxBridge)

        # Switch Access (mỗi phòng ban/VLAN một switch)
        access_switches = {
            "admin": add_l2_switch("acc_admin"),
            "sales": add_l2_switch("acc_sales"),
            "eng": add_l2_switch("acc_eng"),
            "qa": add_l2_switch("acc_qa"),
            "finance": add_l2_switch("acc_fin"),
            "hr": add_l2_switch("acc_hr"),
            "it": add_l2_switch("acc_it"),
        }

        # Chia VLAN về 2 Distribution để cân bằng mô phỏng (load share)
        dist_map = {
            "admin": dist1,
            "sales": dist1,
            "finance": dist1,
            "hr": dist1,
            "eng": dist2,
            "qa": dist2,
            "it": dist2,
        }

        # Uplink mỗi access switch lên Distribution.
        # LƯU Ý: KHÔNG đặt tên interface dài phía switch (ví dụ "acc_admin-uplink" sẽ lỗi)
        # do giới hạn 15 ký tự. Để Mininet tự sinh "acc_admin-ethX" cho an toàn.
        for dept, sw in access_switches.items():
            if dept not in dist_map:
                continue
            dist = dist_map[dept]
            dist_name = "dist1" if dist is dist1 else "dist2"
            self.addLink(dist_name, sw, intfName1=f"{dist_name}-{dept}")

        # Host mỗi phòng ban (PC, IP phone, printer) - tạo ít nhưng đủ đại diện để test.
        # Có thể tăng số lượng sau mà không phải đổi thiết kế routing/NAT/ACL.
        for dept, subnet in VLAN_SUBNETS.items():
            if dept == "mgmt":
                continue
            if dept not in access_switches:
                continue
            sw = access_switches[dept]
            ab = DEPT_ABBR.get(dept, dept[:2])
            # Dùng .11, .21, .31 tương ứng (pc, phone, printer) trong mỗi /24
            host_specs = [
                (f"{ab}_pc1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".11/24"),
                (f"{ab}_ph1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".21/24"),
                (f"{ab}_pr1", subnet.cidr.split("/")[0].rsplit(".", 1)[0] + ".31/24"),
            ]
            for hname, hip in host_specs:
                h = self.addHost(hname, ip=None)
                self.addLink(h, sw)

        # Vùng DMZ: 1 switch + các server DMZ
        dmz_sw = add_l2_switch("dmz_sw")
        # Cũng không đặt tên interface dài phía switch; để Mininet tự sinh dmz_sw-ethX
        self.addLink("dist1", dmz_sw, intfName1="dist1-dmz")

        dmz_web1 = self.addHost("dmz_web1", ip=None)
        dmz_web2 = self.addHost("dmz_web2", ip=None)
        dmz_dns = self.addHost("dmz_dns", ip=None)

        self.addLink(dmz_web1, dmz_sw)
        self.addLink(dmz_web2, dmz_sw)
        self.addLink(dmz_dns, dmz_sw)


def _ensure_netns_symlinks(net: Mininet) -> None:
    """
    Tạo symlink /var/run/netns/<node> để script bên ngoài gọi:
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
    Thử bật OSPF (FRR/Quagga) nếu máy có sẵn; nếu không thì dùng static route.
    Trả về mode: 'ospf' hoặc 'static'.
    """
    # Dò nhanh: có vtysh và ospfd/zebra hay không.
    has_vtysh = os.path.exists("/usr/bin/vtysh") or os.path.exists("/usr/local/bin/vtysh")
    has_ospfd = os.path.exists("/usr/lib/frr/ospfd") or os.path.exists("/usr/lib/quagga/ospfd")
    has_zebra = os.path.exists("/usr/lib/frr/zebra") or os.path.exists("/usr/lib/quagga/zebra")

    if has_vtysh and has_ospfd and has_zebra:
        info("*** Phát hiện FRR/Quagga. Thử cấu hình OSPF bằng vtysh (best-effort)...\n")

        def vty(node, cmds: str) -> None:
            node.cmd(f"bash -lc 'printf \"%s\" \"{cmds}\" | vtysh -b' >/dev/null 2>&1")

        # Khởi chạy zebra/ospfd trong namespace (best-effort).
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

        # Khai báo network (gọn: p2p + VLANs + DMZ + outside trên core)
        vty(net["core"], "conf t\nrouter ospf\nnetwork 10.255.0.0/30 area 0\nnetwork 10.255.0.4/30 area 0\nnetwork 203.0.113.0/24 area 0\nend\n")
        vty(net["dist1"], "conf t\nrouter ospf\nnetwork 10.255.0.0/30 area 0\nnetwork 10.10.10.0/24 area 0\nnetwork 10.10.20.0/24 area 0\nnetwork 10.10.50.0/24 area 0\nnetwork 10.10.60.0/24 area 0\nnetwork 172.16.200.0/24 area 0\nend\n")
        vty(net["dist2"], "conf t\nrouter ospf\nnetwork 10.255.0.4/30 area 0\nnetwork 10.10.30.0/24 area 0\nnetwork 10.10.40.0/24 area 0\nnetwork 10.10.70.0/24 area 0\nend\n")

        info("*** Đã cấu hình OSPF (best-effort). Đợi 5s cho hội tụ...\n")
        time.sleep(5)
        return "ospf"

    info("*** Không có FRR/Quagga. Chuyển sang static route.\n")

    # Static routes:
    # - dist1/dist2 default route về core
    net["dist1"].cmd("ip route replace default via 10.255.0.1")
    net["dist2"].cmd("ip route replace default via 10.255.0.5")
    # - core route về các VLAN phía dist và DMZ phía dist1
    for cidr in ["10.10.10.0/24", "10.10.20.0/24", "10.10.50.0/24", "10.10.60.0/24", "172.16.200.0/24"]:
        net["core"].cmd(f"ip route replace {cidr} via 10.255.0.2")
    for cidr in ["10.10.30.0/24", "10.10.40.0/24", "10.10.70.0/24"]:
        net["core"].cmd(f"ip route replace {cidr} via 10.255.0.6")

    # Default route từ core ra internet host (mô phỏng ISP gateway)
    net["core"].cmd("ip route replace default via 203.0.113.1")
    return "static"


def _setup_nat(core) -> None:
    """
    Cấu hình PAT + Static NAT cho DMZ trên router core bằng iptables.
    """
    core.cmd("iptables -t nat -F")
    core.cmd("iptables -F")

    # Baseline: chặn forward mặc định, chỉ cho phép ESTABLISHED/RELATED
    core.cmd("iptables -P FORWARD DROP")
    core.cmd("iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")

    # PAT (Overload) cho người dùng inside
    core.cmd("iptables -t nat -A POSTROUTING -s 10.10.0.0/16 -o core-out -j MASQUERADE")

    # Static NAT inbound (DNAT) từ Public IP về DMZ server
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

    # Cho phép inside -> internet (mức cơ bản). ACL chi tiết nằm trong acl.sh.
    core.cmd("iptables -A FORWARD -i core-d1 -o core-out -s 10.10.0.0/16 -j ACCEPT")
    core.cmd("iptables -A FORWARD -i core-d2 -o core-out -s 10.10.0.0/16 -j ACCEPT")

    # Cho phép DMZ -> internet (phục vụ lab; có thể siết chặt thêm ở ACL)
    core.cmd("iptables -A FORWARD -i core-d1 -o core-out -s 172.16.200.0/24 -j ACCEPT")
    core.cmd("iptables -t nat -A POSTROUTING -s 172.16.200.0/24 -o core-out -j MASQUERADE")


def configure(net: Mininet) -> None:
    info("*** Liên kết namespace để dùng ip netns exec...\n")
    _ensure_netns_symlinks(net)

    info("*** Cấu hình IP các cổng router (core/dist)...\n")
    core = net["core"]
    dist1 = net["dist1"]
    dist2 = net["dist2"]
    internet = net["internet"]

    # Link core <-> dist
    core.cmd(f"ip addr add {CORE_DIST1_CORE_IP} dev core-d1")
    dist1.cmd(f"ip addr add {CORE_DIST1_DIST_IP} dev d1-core")
    core.cmd(f"ip addr add {CORE_DIST2_CORE_IP} dev core-d2")
    dist2.cmd(f"ip addr add {CORE_DIST2_DIST_IP} dev d2-core")

    # Cổng outside của core và host internet
    core.cmd(f"ip addr add {CORE_OUTSIDE_IP} dev core-out")
    internet.cmd(f"ip addr add {INTERNET_IP} dev inet0")
    internet.cmd("ip route replace default via 203.0.113.2")

    # Gateway VLAN trên Distribution nối xuống Access
    # dist1 quản lý: admin,sales,finance,hr + DMZ
    dist1_vlan_ifaces = {
        "admin": ("dist1-admin", VLAN_SUBNETS["admin"].gw + "/24"),
        "sales": ("dist1-sales", VLAN_SUBNETS["sales"].gw + "/24"),
        "finance": ("dist1-finance", VLAN_SUBNETS["finance"].gw + "/24"),
        "hr": ("dist1-hr", VLAN_SUBNETS["hr"].gw + "/24"),
        "dmz": ("dist1-dmz", DMZ_SUBNET.gw + "/24"),
    }
    for _, (ifname, ip_cidr) in dist1_vlan_ifaces.items():
        dist1.cmd(f"ip addr add {ip_cidr} dev {ifname}")

    # dist2 quản lý: eng,qa,it
    dist2_vlan_ifaces = {
        "eng": ("dist2-eng", VLAN_SUBNETS["eng"].gw + "/24"),
        "qa": ("dist2-qa", VLAN_SUBNETS["qa"].gw + "/24"),
        "it": ("dist2-it", VLAN_SUBNETS["it"].gw + "/24"),
    }
    for _, (ifname, ip_cidr) in dist2_vlan_ifaces.items():
        dist2.cmd(f"ip addr add {ip_cidr} dev {ifname}")

    # Cấu hình IP host phòng ban: /24 + default GW theo VLAN
    info("*** Cấu hình IP/gateway cho các host Access...\n")
    for dept, subnet in VLAN_SUBNETS.items():
        if dept == "mgmt":
            continue
        ab = DEPT_ABBR.get(dept, dept[:2])
        for suffix, role in [("11", "pc1"), ("21", "phone1"), ("31", "printer1")]:
            # Đồng bộ với hostname ngắn đã tạo ở phần build()
            if role == "pc1":
                hname = f"{ab}_pc1"
            elif role == "phone1":
                hname = f"{ab}_ph1"
            else:
                hname = f"{ab}_pr1"
            if hname not in net:
                continue
            ip_prefix = subnet.cidr.split("/")[0].rsplit(".", 1)[0]
            hip = f"{ip_prefix}.{suffix}/24"
            _config_host_ip(net[hname], hip, subnet.gw)

    # Server DMZ
    _config_host_ip(net["dmz_web1"], "172.16.200.11/24", DMZ_SUBNET.gw)
    _config_host_ip(net["dmz_web2"], "172.16.200.12/24", DMZ_SUBNET.gw)
    _config_host_ip(net["dmz_dns"], "172.16.200.53/24", DMZ_SUBNET.gw)

    # Cực kỳ quan trọng: sau khi tự gán IP bằng tay, cần tạo lại ARP tĩnh (nếu dùng staticArp).
    # Nếu để autoStaticArp=True ngay từ đầu trong khi host ip=None, Mininet có thể tạo ARP sai/thiếu,
    # dẫn tới ping trong cùng VLAN cũng "Destination Host Unreachable".
    info("*** Cập nhật bảng ARP tĩnh theo IP mới...\n")
    net.staticArp()

    # Định tuyến: ưu tiên OSPF nếu có, nếu không thì static route
    info("*** Cấu hình định tuyến (OSPF nếu có, nếu không thì static route)...\n")
    mode = _try_enable_ospf_or_static(net)
    info(f"*** Chế độ định tuyến: {mode}\n")

    # NAT/PAT trên core
    info("*** Cấu hình NAT/PAT (trên core)...\n")
    _setup_nat(core)

    info("*** Hoàn tất. Bạn có thể test trong CLI.\n")
    info("    Ví dụ:\n")
    info("      mininet> ad_pc1 ping -c 2 203.0.113.1\n")
    info("      mininet> internet ping -c 2 203.0.113.11\n")
    info("      Áp ACL  : sudo bash source/acl.sh\n")
    info("      Gỡ ACL  : sudo bash source/acl.sh dropacl\n")


def mn_cleanup() -> None:
    info("*** Dọn dẹp trạng thái Mininet cũ...\n")
    os.system("rm -f /var/run/netns/core /var/run/netns/dist1 /var/run/netns/dist2 /var/run/netns/internet 2>/dev/null")
    os.system("sudo mn -c 2>/dev/null")
    # QUAN TRỌNG: KHÔNG flush iptables của máy Ubuntu VM tại đây.
    # Ta chỉ cấu hình iptables bên trong namespace router của Mininet (ví dụ core.cmd("iptables ..."))
    # để tránh làm VM mất mạng/DNS.


def run() -> None:
    topo = CampusTopo()
    # KHÔNG bật autoStaticArp ngay từ đầu vì ta gán IP thủ công sau khi net.start().
    # Ta sẽ gọi net.staticArp() sau khi cấu hình IP xong.
    net = Mininet(topo=topo, controller=None, autoSetMacs=True, autoStaticArp=False)
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

