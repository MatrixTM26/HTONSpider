package lib

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type PortResult struct {
	Port     int
	State    string
	Service  string
	Banner   string
	Protocol string
}

type ScanResult struct {
	Target  string
	IP      string
	Ports   []PortResult
	Elapsed time.Duration
}

var ServiceMap = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
	67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP", 88: "Kerberos",
	110: "POP3", 111: "RPCBind", 119: "NNTP", 123: "NTP", 135: "MSRPC",
	137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN", 143: "IMAP",
	161: "SNMP", 162: "SNMP-Trap", 179: "BGP", 194: "IRC", 389: "LDAP",
	443: "HTTPS", 445: "SMB", 465: "SMTPS", 500: "IKE", 514: "Syslog",
	515: "LPD", 587: "SMTP-Submission", 631: "IPP", 636: "LDAPS",
	873: "Rsync", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
	1194: "OpenVPN", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
	1883: "MQTT", 2049: "NFS", 2121: "FTP-Alt", 2181: "Zookeeper",
	2375: "Docker", 2376: "Docker-TLS", 3000: "HTTP-Dev", 3306: "MySQL",
	3389: "RDP", 3690: "SVN", 4000: "HTTP-Alt", 4369: "EPMD",
	5000: "HTTP-Dev", 5432: "PostgreSQL", 5601: "Kibana", 5672: "AMQP",
	5900: "VNC", 5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis",
	6443: "K8s-API", 7001: "WebLogic", 7777: "HTTP-Dev", 8000: "HTTP-Alt",
	8008: "HTTP-Alt", 8080: "HTTP-Proxy", 8081: "HTTP-Alt", 8086: "InfluxDB",
	8088: "HTTP-Alt", 8090: "HTTP-Alt", 8161: "ActiveMQ", 8443: "HTTPS-Alt",
	8888: "Jupyter", 9000: "HTTP-Dev", 9090: "Prometheus", 9092: "Kafka",
	9200: "Elasticsearch", 9300: "Elasticsearch-Cluster", 9418: "Git",
	9999: "HTTP-Dev", 10000: "Webmin", 10250: "K8s-Kubelet", 11211: "Memcached",
	15672: "RabbitMQ-UI", 27017: "MongoDB", 27018: "MongoDB-Shard",
	50000: "SAP", 50070: "HDFS-NameNode",
}

var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139,
	143, 161, 179, 389, 443, 445, 465, 500, 514, 587, 631, 636, 873,
	993, 995, 1080, 1194, 1433, 1521, 1723, 1883, 2049, 2181, 2375, 2376,
	3000, 3306, 3389, 3690, 4369, 5000, 5432, 5601, 5672, 5900, 5985,
	5986, 6379, 6443, 7001, 8000, 8008, 8080, 8081, 8086, 8088, 8161,
	8443, 8888, 9000, 9090, 9092, 9200, 9300, 9418, 10000, 10250, 11211,
	15672, 27017, 27018, 50000, 50070,
}

func AllPorts() []int {
	Ports := make([]int, 65535)
	for I := range Ports {
		Ports[I] = I + 1
	}
	return Ports
}

type Scanner struct {
	Timeout     time.Duration
	Concurrency int
	GrabBanner  bool
}

func NewScanner(TimeoutMs int, Concurrency int, GrabBanner bool) *Scanner {
	if TimeoutMs < 100 {
		TimeoutMs = 100
	}
	return &Scanner{
		Timeout:     time.Duration(TimeoutMs) * time.Millisecond,
		Concurrency: Concurrency,
		GrabBanner:  GrabBanner,
	}
}

func (S *Scanner) ResolveTarget(Target string) (string, error) {
	Ctx, Cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer Cancel()
	Addrs, Err := net.DefaultResolver.LookupHost(Ctx, Target)
	if Err != nil {
		return "", Err
	}
	return Addrs[0], nil
}

func (S *Scanner) ScanTCP(Host string, Port int) PortResult {
	Result := PortResult{Port: Port, Protocol: "tcp", State: "closed", Service: "unknown"}
	if Svc, Ok := ServiceMap[Port]; Ok {
		Result.Service = Svc
	}

	Conn, Err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", Host, Port), S.Timeout)
	if Err != nil {
		if strings.Contains(Err.Error(), "refused") {
			Result.State = "closed"
		} else {
			Result.State = "filtered"
		}
		return Result
	}
	defer Conn.Close()
	Result.State = "open"

	if S.GrabBanner {
		Conn.SetReadDeadline(time.Now().Add(S.Timeout))
		Buf := make([]byte, 2048)
		N, _ := Conn.Read(Buf)
		if N > 0 {
			Raw := strings.Map(func(R rune) rune {
				if R < 32 || R == 127 {
					return ' '
				}
				return R
			}, string(Buf[:N]))
			Raw = strings.Join(strings.Fields(Raw), " ")
			if len(Raw) > 60 {
				Raw = Raw[:60] + "..."
			}
			Result.Banner = Raw
		}
	}
	return Result
}

func (S *Scanner) ScanUDP(Host string, Port int) PortResult {
	Result := PortResult{Port: Port, Protocol: "udp", State: "open|filtered", Service: "unknown"}
	if Svc, Ok := ServiceMap[Port]; Ok {
		Result.Service = Svc
	}
	Addr, Err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", Host, Port))
	if Err != nil {
		return Result
	}
	Conn, Err := net.DialUDP("udp", nil, Addr)
	if Err != nil {
		Result.State = "closed"
		return Result
	}
	defer Conn.Close()
	Conn.SetDeadline(time.Now().Add(S.Timeout))
	Conn.Write([]byte("\x00"))
	Buf := make([]byte, 512)
	N, Err := Conn.Read(Buf)
	if Err == nil && N > 0 {
		Result.State = "open"
	}
	return Result
}

func (S *Scanner) ScanPorts(Host string, Ports []int) ScanResult {
	Start := time.Now()
	IP, Err := S.ResolveTarget(Host)
	if Err != nil {
		IP = Host
		LogWarn(fmt.Sprintf("DNS resolution failed for %s, using as-is", Host))
	} else {
		LogInfo(fmt.Sprintf("Resolved %s -> %s", Host, IP))
	}

	Result := ScanResult{Target: Host, IP: IP}
	Sem := make(chan struct{}, S.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}
	var Counter int64
	Total := int64(len(Ports))

	LogInfo(fmt.Sprintf("TCP scan started — %d ports, threads: %d, timeout: %dms",
		len(Ports), S.Concurrency, S.Timeout.Milliseconds()))

	for _, Port := range Ports {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(P int) {
			defer Wg.Done()
			defer func() { <-Sem }()
			PR := S.ScanTCP(IP, P)
			Done := atomic.AddInt64(&Counter, 1)
			if Done%100 == 0 || Done == Total {
				Pct := Done * 100 / Total
				Mu.Lock()
				OpenCount := len(Result.Ports)
				Mu.Unlock()
				LogDebugV(fmt.Sprintf("[%d%%] %d/%d scanned — %d open", Pct, Done, Total, OpenCount))
			}
			if PR.State == "open" {
				Banner := PR.Banner
				if Banner == "" {
					Banner = "-"
				}
				LogSuccess(fmt.Sprintf("%d/tcp  open  %-20s %s", P, PR.Service, Banner))
				Mu.Lock()
				Result.Ports = append(Result.Ports, PR)
				Mu.Unlock()
			}
		}(Port)
	}

	Wg.Wait()
	Result.Elapsed = time.Since(Start)
	sort.Slice(Result.Ports, func(I, J int) bool {
		return Result.Ports[I].Port < Result.Ports[J].Port
	})
	LogInfo(fmt.Sprintf("Scan complete — %d open port(s) in %s",
		len(Result.Ports), Result.Elapsed.Round(time.Millisecond)))
	return Result
}

func (S *Scanner) ScanUDPPorts(Host string, Ports []int) []PortResult {
	var Results []PortResult
	Sem := make(chan struct{}, S.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}

	LogInfo(fmt.Sprintf("UDP scan started — %d ports", len(Ports)))

	for _, Port := range Ports {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(P int) {
			defer Wg.Done()
			defer func() { <-Sem }()
			PR := S.ScanUDP(Host, P)
			if PR.State != "closed" {
				LogSuccess(fmt.Sprintf("%d/udp  %-14s %s", P, PR.State, PR.Service))
				Mu.Lock()
				Results = append(Results, PR)
				Mu.Unlock()
			}
		}(Port)
	}

	Wg.Wait()
	sort.Slice(Results, func(I, J int) bool {
		return Results[I].Port < Results[J].Port
	})
	return Results
}

func (S *Scanner) ParsePortRange(Input string) []int {
	var Ports []int
	Parts := strings.Split(Input, ",")
	for _, Part := range Parts {
		Part = strings.TrimSpace(Part)
		if strings.EqualFold(Part, "all") {
			return AllPorts()
		}
		if strings.Contains(Part, "-") {
			Bounds := strings.SplitN(Part, "-", 2)
			var Start, End int
			fmt.Sscanf(strings.TrimSpace(Bounds[0]), "%d", &Start)
			fmt.Sscanf(strings.TrimSpace(Bounds[1]), "%d", &End)
			for P := Start; P <= End && P <= 65535; P++ {
				Ports = append(Ports, P)
			}
		} else {
			var P int
			fmt.Sscanf(Part, "%d", &P)
			if P > 0 && P <= 65535 {
				Ports = append(Ports, P)
			}
		}
	}
	return Ports
}

func (S *Scanner) RenderTable(Result ScanResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"PORT", "STATE", "SERVICE", "BANNER"}
	var Rows [][]string
	for _, PR := range Result.Ports {
		Banner := PR.Banner
		if Banner == "" {
			Banner = "-"
		}
		Rows = append(Rows, []string{
			fmt.Sprintf("%d/%s", PR.Port, PR.Protocol),
			PR.State,
			PR.Service,
			Banner,
		})
	}
	Widths := CalcColWidths(Headers, Rows, W-2)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  TARGET  : %s\n", Result.Target))
	B.WriteString(fmt.Sprintf("  IP      : %s\n", Result.IP))
	B.WriteString(fmt.Sprintf("  ELAPSED : %s\n", Result.Elapsed.Round(time.Millisecond)))
	B.WriteString(fmt.Sprintf("  OPEN    : %d port(s)\n", len(Result.Ports)))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	B.WriteString(TableRow(Headers, Widths))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	for _, Row := range Rows {
		B.WriteString(TableRow(Row, Widths))
	}
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	return B.String()
}
