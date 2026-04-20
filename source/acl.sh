#!/bin/bash
#
# Campus multi-layer ACL (iptables) for:
# - Standard ACL (source-based)
# - Extended ACL (service-based: port 80/443)
# - Boundary firewall rules (internet <-> DMZ)
#
# This script targets Mininet namespaces created by source/topology.py:
#   ip netns exec core/dist1/dist2/...
#
# Usage:
#   sudo bash source/acl.sh          # apply_acl
#   sudo bash source/acl.sh dropacl  # drop_acl (flush)

set -euo pipefail

NS() { ip netns exec "$1" "${@:2}"; }

# -------------------------------
# Apply ACLs
# -------------------------------
apply_acl() {
  echo "[ACL] Applying multi-layer ACL rules..."

  # ---------- Base flush (clean old rules) ----------
  for n in core dist1 dist2; do
    NS "$n" iptables -F || true
    NS "$n" iptables -t nat -F || true
    NS "$n" iptables -X || true
  done

  # ---------- Default policies ----------
  # Keep router INPUT permissive for lab (avoid locking yourself out in Mininet),
  # enforce policy mainly on FORWARD.
  for n in core dist1 dist2; do
    NS "$n" iptables -P INPUT ACCEPT
    NS "$n" iptables -P OUTPUT ACCEPT
    NS "$n" iptables -P FORWARD DROP
    NS "$n" iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  done

  # =========================================================
  # STANDARD ACL (source-based) - example policy per confirmed plan:
  # - Block Sales (10.10.20.0/24) from reaching DMZ subnet (172.16.200.0/24)
  #   Apply near the destination: on dist1 (which connects to DMZ).
  # =========================================================
  echo "[ACL] Standard ACL: deny Sales -> DMZ (source-based)"
  NS dist1 iptables -A FORWARD -s 10.10.20.0/24 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "STD: Deny Sales VLAN20 -> DMZ"

  # Permit remaining inside -> DMZ is governed by Extended ACL below.

  # =========================================================
  # EXTENDED ACL (service-based) inside -> DMZ
  # - Permit inside users (10.10.0.0/16) to DMZ Web (80/443) and DNS (53)
  # - Deny other inside -> DMZ services (default deny)
  # Apply on dist1 (DMZ boundary at Distribution layer).
  # =========================================================
  echo "[ACL] Extended ACL: allow Inside -> DMZ only web(80/443) + dns(53)"

  # Allow HTTP/HTTPS to DMZ web servers
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.11/32 -p tcp -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_web1 TCP 80/443 permit"
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.12/32 -p tcp -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_web2 TCP 80/443 permit"

  # Allow DNS queries to DMZ DNS server
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.53/32 -p udp --dport 53 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_dns UDP 53 permit"
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.53/32 -p tcp --dport 53 -j ACCEPT \
    -m comment --comment "EXT: Inside -> dmz_dns TCP 53 permit"

  # Deny all other Inside -> DMZ traffic (explicit drop for clarity)
  NS dist1 iptables -A FORWARD -s 10.10.0.0/16 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "EXT: Inside -> DMZ deny all other services"

  # =========================================================
  # BOUNDARY FIREWALL (internet <-> DMZ)
  # Apply on core router: traffic coming from outside (core-out) into inside (core-d1).
  # Permit only:
  # - Internet -> DMZ Web: TCP 80/443 to public VIPs (DNAT done by topology NAT)
  # - Internet -> DMZ DNS: UDP/TCP 53 to public VIP
  # Deny other inbound to DMZ.
  # =========================================================
  echo "[ACL] Boundary FW: allow Internet -> DMZ (only web/dns) via static NAT public IPs"

  # Allow inbound to DMZ web VIPs
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.11/32 -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_web1 TCP 80/443 permit"
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.12/32 -m multiport --dports 80,443 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_web2 TCP 80/443 permit"

  # Allow inbound to DMZ DNS
  NS core iptables -A FORWARD -i core-out -o core-d1 -p udp -d 172.16.200.53/32 --dport 53 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_dns UDP 53 permit"
  NS core iptables -A FORWARD -i core-out -o core-d1 -p tcp -d 172.16.200.53/32 --dport 53 -j ACCEPT \
    -m comment --comment "FW: Internet -> dmz_dns TCP 53 permit"

  # Deny other inbound to DMZ (explicit)
  NS core iptables -A FORWARD -i core-out -o core-d1 -d 172.16.200.0/24 -j DROP \
    -m comment --comment "FW: Internet -> DMZ deny all other"

  # =========================================================
  # Permit inside -> internet (so users can reach outside through PAT)
  # =========================================================
  NS core iptables -A FORWARD -i core-d1 -o core-out -s 10.10.0.0/16 -j ACCEPT \
    -m comment --comment "FW: Inside via dist1 -> Internet permit"
  NS core iptables -A FORWARD -i core-d2 -o core-out -s 10.10.0.0/16 -j ACCEPT \
    -m comment --comment "FW: Inside via dist2 -> Internet permit"

  # (Optional) allow DMZ -> internet (kept open for lab convenience)
  NS core iptables -A FORWARD -i core-d1 -o core-out -s 172.16.200.0/24 -j ACCEPT \
    -m comment --comment "FW: DMZ -> Internet permit"

  echo "[ACL] Applied successfully."
}

# -------------------------------
# Drop/remove all ACLs
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

