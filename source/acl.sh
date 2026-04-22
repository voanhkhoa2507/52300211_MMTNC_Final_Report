#!/bin/bash
#
# ACL bảo mật đa lớp (iptables) cho mô hình Campus:
# - Standard ACL (lọc theo nguồn)
# - Extended ACL (lọc theo dịch vụ: port 80/443)
# - Firewall biên (Internet <-> DMZ)
#
# Script này áp rule lên các namespace do source/topology.py tạo:
#   ip netns exec core/dist1/dist2/...
#
# Cách dùng:
#   sudo bash source/acl.sh          # apply_acl (áp ACL)
#   sudo bash source/acl.sh dropacl  # drop_acl (gỡ/flush ACL)

set -euo pipefail

NS() { ip netns exec "$1" "${@:2}"; }

# -------------------------------
# Áp ACL
# -------------------------------
apply_acl() {
  echo "[ACL] Applying multi-layer ACL rules..."

  # ---------- Dọn rule cũ ----------
  for n in core dist1 dist2; do
    NS "$n" iptables -F || true
    NS "$n" iptables -t nat -F || true
    NS "$n" iptables -X || true
  done

  # ---------- Chính sách mặc định ----------
  # Giữ INPUT thoáng để tránh “tự khóa” khi lab; siết chủ yếu ở FORWARD.
  for n in core dist1 dist2; do
    NS "$n" iptables -P INPUT ACCEPT
    NS "$n" iptables -P OUTPUT ACCEPT
    NS "$n" iptables -P FORWARD DROP
    NS "$n" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  # =========================================================
  # STANDARD ACL (lọc theo nguồn) - theo kế hoạch đã chốt:
  # - Chặn Sales (10.10.20.0/24) truy cập DMZ (172.16.200.0/24)
  # - Áp gần đích (dist1 là nơi nối DMZ)
  # =========================================================
  echo "[ACL] Standard ACL: chặn Sales -> DMZ (lọc theo nguồn)"
  NS dist1 iptables -A FORWARD -s 10.10.20.0/24 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "STD: Deny Sales VLAN20 -> DMZ"

  # Các luồng inside -> DMZ còn lại sẽ được kiểm soát bởi Extended ACL bên dưới.

  # =========================================================
  # EXTENDED ACL (lọc theo dịch vụ) Inside -> DMZ
  # - Cho phép inside (10.10.0.0/16) vào DMZ đúng dịch vụ:
  #     Web TCP 80/443, DNS UDP/TCP 53
  # - Còn lại: chặn (default deny)
  # - Áp trên dist1 (biên DMZ ở lớp Distribution)
  # =========================================================
  echo "[ACL] Extended ACL: Inside -> DMZ chỉ cho web(80/443) + dns(53)"

  # Cho phép HTTP/HTTPS tới Web servers DMZ
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.11/32 -p tcp -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_web1 TCP 80/443 permit"
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.12/32 -p tcp -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_web2 TCP 80/443 permit"

  # Cho phép truy vấn DNS tới DNS server DMZ
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.53/32 -p udp --dport 53 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_dns UDP 53 permit"
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.53/32 -p tcp --dport 53 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_dns TCP 53 permit"

  # Chặn tất cả inside -> DMZ còn lại (drop tường minh để dễ đọc rule)
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "EXT: Inside -> DMZ deny all other services"

  # =========================================================
  # FIREWALL BIÊN (Internet <-> DMZ)
  # Áp trên core: lưu lượng từ outside (core-out) vào trong (core-d1).
  # Chỉ cho phép:
  # - Internet -> DMZ Web: TCP 80/443 (DNAT đã cấu hình trong topology NAT)
  # - Internet -> DMZ DNS: UDP/TCP 53
  # Còn lại: chặn.
  # =========================================================
  echo "[ACL] Firewall biên: Internet -> DMZ chỉ cho web/dns (static NAT)"

  # Cho phép inbound tới Web DMZ
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.11/32 -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_web1 TCP 80/443 permit"
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.12/32 -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_web2 TCP 80/443 permit"

  # Cho phép inbound tới DNS DMZ
  NS core iptables -A FORWARD -i core-out -o core-d1 -p udp -d 172.16.200.53/32 --dport 53 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_dns UDP 53 permit"
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.53/32 --dport 53 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_dns TCP 53 permit"

  # Chặn inbound khác vào DMZ
  NS core iptables -A FORWARD -i core-out -o core-d1 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "FW: Internet -> DMZ deny all other"

  # =========================================================
  # Cho phép inside -> internet (để người dùng đi ra ngoài qua PAT)
  # =========================================================
  # LƯU Ý: vì dist1/dist2 đặt policy FORWARD=DROP, cần cho phép inside đi lên core ở lớp distribution.
  # Nếu không có 2 rule dưới, inside sẽ bị chặn trước khi tới core-out.
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -o d1-core -j ACCEPT \
    -m comment --comment "FW: Inside (dist1) -> Core permit"
  NS dist2 iptables -A FORWARD -s 10.10.0.0/16 -o d2-core -j ACCEPT \
    -m comment --comment "FW: Inside (dist2) -> Core permit"

  NS core iptables -A FORWARD -i core-d1 -o core-out -s 10.10.0.0/16 -j ACCEPT \
    -m comment --comment "FW: Inside via dist1 -> Internet permit"
  NS core iptables -A FORWARD -i core-d2 -o core-out -s 10.10.0.0/16 -j ACCEPT \
    -m comment --comment "FW: Inside via dist2 -> Internet permit"

  # (Tùy chọn) cho phép DMZ -> internet (để lab thuận tiện)
  NS core iptables -A FORWARD -i core-d1 -o core-out -s 172.16.200.0/24 -j ACCEPT \
    -m comment --comment "FW: DMZ -> Internet permit"

  echo "[ACL] Applied successfully."
}

# -------------------------------
# Gỡ/flush toàn bộ ACL
# -------------------------------
drop_acl() {
  echo "[ACL] Dropping (flushing) all ACL rules on core/dist1/dist2..."
  for n in core dist1 dist2; do
    NS "$n" iptables -F || true
    NS "$n" iptables -t nat -F || true
    NS "$n" iptables -X || true
    NS "$n" iptables -P INPUT ACCEPT || true
    NS "$n" iptables -P OUTPUT ACCEPT || true
    NS "$n" iptables -P FORWARD ACCEPT || true
  done
  echo "[ACL] Dropped successfully."
}

# -------------------------------
# Main
# -------------------------------
if [[ "${1:-}" == "dropacl" ]]; then
  drop_acl
else
  apply_acl
fi

