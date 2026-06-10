package lib

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ArpHost struct {
	IP       string
	MAC      string
	Hostname string
	Alive    bool
}

type ArpScanResult struct {
	NetworkCIDR string
	Hosts       []ArpHost
	Elapsed     time.Duration
}

type ArpScanner struct {
	Timeout     time.Duration
	Concurrency int
}

func NewArpScanner(TimeoutSec int, Concurrency int) *ArpScanner {
	return &ArpScanner{
		Timeout:     time.Duration(TimeoutSec) * time.Second,
		Concurrency: Concurrency,
	}
}

func (A *ArpScanner) ExpandCIDR(CIDR string) ([]string, error) {
	_, Network, Err := net.ParseCIDR(CIDR)
	if Err != nil {
		return nil, Err
	}
	var IPs []string
	for IP := CloneIP(Network.IP.Mask(Network.Mask)); Network.Contains(IP); IncrementIP(IP) {
		IPs = append(IPs, IP.String())
	}
	if len(IPs) > 2 {
		IPs = IPs[1 : len(IPs)-1]
	}
	return IPs, nil
}

func CloneIP(IP net.IP) net.IP {
	Clone := make(net.IP, len(IP))
	copy(Clone, IP)
	return Clone
}

func IncrementIP(IP net.IP) {
	for I := len(IP) - 1; I >= 0; I-- {
		IP[I]++
		if IP[I] != 0 {
			break
		}
	}
}

func (A *ArpScanner) PingHost(IP string) bool {
	var Cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		Cmd = exec.Command("ping", "-n", "1", "-w", "500", IP)
	default:
		Cmd = exec.Command("ping", "-c", "1", "-W", "1", IP)
	}
	return Cmd.Run() == nil
}

func (A *ArpScanner) ReadArpTable() map[string]string {
	Table := make(map[string]string)
	var Cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		Cmd = exec.Command("arp", "-a")
	default:
		Cmd = exec.Command("arp", "-n")
	}
	Out, Err := Cmd.Output()
	if Err != nil {
		return Table
	}
	Lines := strings.Split(string(Out), "\n")
	for _, Line := range Lines {
		Line = strings.TrimSpace(Line)
		if Line == "" {
			continue
		}
		Fields := strings.Fields(Line)
		if len(Fields) >= 3 {
			IP := Fields[0]
			MAC := ""
			for _, F := range Fields[1:] {
				if strings.Contains(F, ":") || strings.Contains(F, "-") {
					MAC = F
					break
				}
			}
			if net.ParseIP(IP) != nil && MAC != "" && MAC != "(incomplete)" {
				Table[IP] = strings.ReplaceAll(MAC, "-", ":")
			}
		}
	}
	return Table
}

func (A *ArpScanner) ResolveHostname(IP string) string {
	Names, Err := net.LookupAddr(IP)
	if Err != nil || len(Names) == 0 {
		return "-"
	}
	return strings.TrimSuffix(Names[0], ".")
}

func (A *ArpScanner) Scan(CIDR string) ArpScanResult {
	Start := time.Now()
	Result := ArpScanResult{NetworkCIDR: CIDR}

	IPs, Err := A.ExpandCIDR(CIDR)
	if Err != nil {
		LogError(fmt.Sprintf("Invalid CIDR: %s", Err.Error()))
		return Result
	}

	LogInfo(fmt.Sprintf("ARP scan on %s — %d hosts, threads: %d", CIDR, len(IPs), A.Concurrency))

	Sem := make(chan struct{}, A.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}
	var Counter int64

	for _, IP := range IPs {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(Addr string) {
			defer Wg.Done()
			defer func() { <-Sem }()
			Done := atomic.AddInt64(&Counter, 1)
			if Done%10 == 0 {
				LogDebugV(fmt.Sprintf("Probing %d/%d", Done, int64(len(IPs))))
			}
			if A.PingHost(Addr) {
				Host := ArpHost{IP: Addr, Alive: true, Hostname: A.ResolveHostname(Addr)}
				LogSuccess(fmt.Sprintf("Alive: %s (%s)", Addr, Host.Hostname))
				Mu.Lock()
				Result.Hosts = append(Result.Hosts, Host)
				Mu.Unlock()
			}
		}(IP)
	}

	Wg.Wait()
	LogInfo("Reading ARP table for MAC addresses...")
	ArpTable := A.ReadArpTable()
	for I, H := range Result.Hosts {
		if MAC, Ok := ArpTable[H.IP]; Ok {
			Result.Hosts[I].MAC = MAC
		}
		if Result.Hosts[I].MAC == "" {
			Result.Hosts[I].MAC = "-"
		}
	}

	Result.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("ARP scan done — %d alive in %s", len(Result.Hosts), Result.Elapsed.Round(time.Millisecond)))
	return Result
}

func (A *ArpScanner) RenderTable(Result ArpScanResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"IP", "MAC", "HOSTNAME"}
	var Rows [][]string
	for _, H := range Result.Hosts {
		Rows = append(Rows, []string{H.IP, H.MAC, H.Hostname})
	}
	Widths := CalcColWidths(Headers, Rows, W-2)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  NETWORK : %s\n", Result.NetworkCIDR))
	B.WriteString(fmt.Sprintf("  ALIVE   : %d host(s)\n", len(Result.Hosts)))
	B.WriteString(fmt.Sprintf("  ELAPSED : %s\n", Result.Elapsed.Round(time.Millisecond)))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	B.WriteString(TableRow(Headers, Widths))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	for _, Row := range Rows {
		B.WriteString(TableRow(Row, Widths))
	}
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	return B.String()
}
