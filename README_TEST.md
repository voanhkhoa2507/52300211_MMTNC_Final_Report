## Checklist chạy/test & sinh output 

### 0) Cài gói cần thiết (Ubuntu)

```bash
sudo apt-get update
sudo apt-get install -y curl netcat-openbsd iperf3 python3-pip conntrack xterm
sudo pip3 install -U matplotlib numpy
```

### 1) Chạy topology (OSPF + NAT/PAT)

```bash
cd 52300211_Final_Report
sudo python3 source/topology.py --clean
sudo python3 source/topology.py
```

Bạn sẽ vào prompt `mininet>`.

### 2) (Tuỳ chọn) Áp ACL

Mở terminal Ubuntu khác (hoặc thoát Mininet tạm thời):

```bash
cd 52300211_Final_Report
sudo bash source/acl.sh
```

Gỡ ACL:

```bash
sudo bash source/acl.sh dropacl
```

### 3) Chạy **1 lệnh** để sinh toàn bộ output vào `logs/`

Mở terminal Ubuntu khác (ngoài Mininet) và chạy:

```bash
cd 52300211_Final_Report
sudo python3 source/run_all_outputs.py
```

Script sẽ:
- Sinh heatmap ACL **live** từ iptables runtime
- Snapshot NAT/PAT (static NAT table + PAT rules)
- Capture incident theo **conntrack** (fallback chắc chắn)
- Benchmark 4 case và vẽ bảng PNG
- Chạy load balancer nhanh để cập nhật line chart + event log

### 4) Vị trí output

- **ACL**: `logs/acl/`
  - `acl_heatmap_live.png`
  - `acl_heatmap_live.csv`
  - `acl_heatmap_live_detail.csv`

- **NAT**: `logs/nat/`
  - `nat_snapshot_*.txt`
  - `nat_static_table_*.csv`
  - `nat_pat_rules_*.txt`
  - `incident_conntrack_*.csv`

- **Load Balancer**: `logs/loadbalancer/`
  - `load_balancing_line_chart.png`
  - `load_balancing_timeseries.csv`
  - `load_balancer_events.log`

- **Performance**: `logs/perf/`
  - `perf_table.png`
  - (tuỳ chọn) `perf_table_*.csv`, `perf_raw_*.json`

### 5) Lệnh test nhanh (manual)

- **VIP trả nội dung WEB1/WEB2**:

```text
mininet> internet curl -m 3 -s http://203.0.113.11/ | head -n 1
```

- **Kiểm DNAT đang trỏ về đâu**:

```text
mininet> core iptables -t nat -nvL PREROUTING --line-numbers | grep 203.0.113.11 -n
```

- **OSPF neighbor** (nếu FRR chạy):

```text
mininet> core vtysh -c "show ip ospf neighbor"
mininet> dist1 vtysh -c "show ip ospf neighbor"
```

---

## Test plan theo rubric (Yêu cầu ↔ Lệnh ↔ Output)

### A) Routing OSPF (bắt buộc)
- **Yêu cầu**: các router core/dist tạo neighbor OSPF và route liên VLAN/DMZ hoạt động.
- **Lệnh** (trong `mininet>`):

```text
mininet> core vtysh -c "show ip ospf neighbor"
mininet> dist1 vtysh -c "show ip ospf neighbor"
mininet> dist2 vtysh -c "show ip ospf neighbor"
mininet> ad_pc1 ping -c 2 172.16.200.11
```

- **Output**:
  - Ảnh chụp màn hình `show ip ospf neighbor` (neighbor != empty)
  - Ping OK chứng minh reach DMZ qua routing

### B) NAT/PAT cho Inside (PAT overload)
- **Yêu cầu**: inside `10.10.0.0/16` đi ra `core-out` qua MASQUERADE.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/nat_audit.py snapshot
```

- **Output**:
  - `logs/nat/nat_pat_rules_*.txt`
  - `logs/nat/nat_snapshot_*.txt`

### C) Static NAT cho DMZ servers (Public VIP → DMZ)
- **Yêu cầu**: VIP public map về server DMZ (web/dns).
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/nat_audit.py snapshot
```

- **Output**:
  - `logs/nat/nat_static_table_*.csv`

### D) Multi-layer ACL (Standard / Extended / Boundary firewall) + dropacl
- **Yêu cầu**:
  - Standard ACL: chặn Sales → DMZ
  - Extended ACL: Inside → DMZ chỉ web(80/443) + dns(53)
  - Boundary: Internet → DMZ chỉ web/dns (qua static NAT)
  - Có lệnh gỡ: `dropacl`
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo bash source/acl.sh
sudo bash source/acl.sh dropacl
```

- **Output**:
  - Policy được minh chứng qua heatmap/live iptables + test curl/ping theo rule

### E) Heatmap ACL (bắt buộc)
- **Yêu cầu**: sinh heatmap minh hoạ rule ACL.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/heatmap_acl.py --mode live
```

- **Output**:
  - `logs/acl/acl_heatmap_live.png`
  - `logs/acl/acl_heatmap_live.csv`
  - `logs/acl/acl_heatmap_live_detail.csv`

### F) Load Balancing DMZ (ngưỡng 80/20) + Line chart (bắt buộc)
- **Yêu cầu**: khi tải >80% chuyển sang backup, <20% khôi phục; có line chart Mbps theo thời gian.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/load_balancer.py --interval 1 --plot-interval 0.1 --capacity-mbps 2000 --save-every 2
```

- **Traffic test** (trong `mininet>`):

```text
mininet> internet sh -lc 'for i in $(seq 1 60); do (curl -s http://203.0.113.11/big.bin -o /dev/null &) ; done; wait'
mininet> internet curl -m 3 -s http://203.0.113.11/ | head -n 1
```

- **Output**:
  - `logs/loadbalancer/load_balancing_line_chart.png`
  - `logs/loadbalancer/load_balancing_timeseries.csv`
  - `logs/loadbalancer/load_balancer_events.log`

### G) Incident log (NAT traceability)
- **Yêu cầu**: truy vết lưu lượng qua NAT/PAT có bảng log.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/nat_audit.py capture-incident --seconds 20
```

- **Traffic** (trong `mininet>` trong lúc capture):

```text
mininet> internet sh -lc 'for i in $(seq 1 30); do curl -m 2 -s --header "Connection: close" http://203.0.113.11/ -o /dev/null; done'
mininet> ad_pc1 ping -c 3 203.0.113.1
```

- **Output**:
  - `logs/nat/incident_conntrack_*.csv`

### H) Performance comparison table (Throughput & Latency) (bắt buộc)
- **Yêu cầu**: bảng so sánh throughput/latency với/không NAT/ACL.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/perf_benchmark.py --fail-soft --render-table --no-csv --repeat 5
```

- **Output**:
  - `logs/perf/perf_table.png`

### I) One-shot generate 
- **Yêu cầu**: 1 lệnh sinh gần như toàn bộ output.
- **Lệnh**:

```bash
cd 52300211_Final_Report
sudo python3 source/run_all_outputs.py
```

- **Output**:
  - Tất cả nằm trong `logs/acl/`, `logs/nat/`, `logs/perf/`, `logs/loadbalancer/`

