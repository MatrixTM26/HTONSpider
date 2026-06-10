package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"HTONSpider/lib"
)

func ShowBanner() {
	fmt.Print(lib.ColorCyan + lib.ColorBold)
	fmt.Println()
	fmt.Println(`  ██╗  ██╗████████╗ ██████╗ ███╗   ██╗███████╗██████╗ ██╗██████╗ ███████╗██████╗ `)
	fmt.Println(`  ██║  ██║╚══██╔══╝██╔═══██╗████╗  ██║██╔════╝██╔══██╗██║██╔══██╗██╔════╝██╔══██╗`)
	fmt.Println(`  ███████║   ██║   ██║   ██║██╔██╗ ██║███████╗██████╔╝██║██║  ██║█████╗  ██████╔╝`)
	fmt.Println(`  ██╔══██║   ██║   ██║   ██║██║╚██╗██║╚════██║██╔═══╝ ██║██║  ██║██╔══╝  ██╔══██╗`)
	fmt.Println(`  ██║  ██║   ██║   ╚██████╔╝██║ ╚████║███████║██║     ██║██████╔╝███████╗██║  ██║`)
	fmt.Println(`  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝     ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝`)
	fmt.Print(lib.ColorReset)
	fmt.Println()
	fmt.Printf("  %sv1.0.0%s  Full Network Recon & Security Scanner\n", lib.ColorGray, lib.ColorReset)
	fmt.Printf("  %sgithub.com/MatrixTM26%s\n", lib.ColorGray, lib.ColorReset)
	fmt.Println()
	lib.PrintFrame()
}

func ShowHelp() {
	ShowBanner()
	W := lib.TermWidth()
	Sep := strings.Repeat("-", W)

	fmt.Printf("\n%s%sUSAGE%s\n", lib.ColorCyan+lib.ColorBold, "  ", lib.ColorReset)
	fmt.Printf("  htonspider -m <mode> -s <target> [options]\n\n")

	fmt.Printf("%s%sMODES%s\n", lib.ColorCyan+lib.ColorBold, "  ", lib.ColorReset)
	fmt.Printf("%s\n", Sep)
	Modes := [][2]string{
		{"port", "TCP/UDP port scan (nmap-style, banner grab)"},
		{"dns", "DNS record lookup + trace (A, MX, NS, TXT, PTR, CNAME)"},
		{"sub", "Subdomain bruteforce discovery"},
		{"arp", "ARP + ping sweep — discover alive hosts in CIDR"},
		{"proxy", "Filter alive proxies/IPs from list or file"},
		{"path", "Sensitive path & file discovery"},
		{"vuln", "Service fingerprint + CVE reference"},
		{"full", "Run all modules in sequence"},
	}
	for _, M := range Modes {
		fmt.Printf("  %s%-10s%s %s\n", lib.ColorGreen+lib.ColorBold, M[0], lib.ColorReset, M[1])
	}

	fmt.Printf("%s\n\n", Sep)
	fmt.Printf("%s%sFLAGS%s\n", lib.ColorCyan+lib.ColorBold, "  ", lib.ColorReset)
	fmt.Printf("%s\n", Sep)
	Flags := [][3]string{
		{"-m", "mode", "Scan mode (port/dns/sub/arp/proxy/path/vuln/full)"},
		{"-s", "target", "Target host, IP, CIDR, or file path"},
		{"-p", "ports", "Port range: 80,443 | 1-1024 | all (default: common)"},
		{"-t", "ms", "Timeout in milliseconds (default: 800)"},
		{"-T", "threads", "Concurrent threads (default: 200)"},
		{"-W", "file", "Wordlist file for subdomain/path discovery"},
		{"-e", "file", "Export results to file"},
		{"-A", "", "Filter alive only — for proxy/IP checker"},
		{"-U", "", "Also run UDP scan alongside TCP"},
		{"-b", "", "Grab service banners"},
		{"-V", "", "Verbose / debug output"},
		{"-n", "", "No banner — skip ASCII art"},
	}
	for _, F := range Flags {
		if F[1] != "" {
			fmt.Printf("  %s%-4s%s %-10s %s\n", lib.ColorYellow+lib.ColorBold, F[0], lib.ColorReset, "<"+F[1]+">", F[2])
		} else {
			fmt.Printf("  %s%-4s%s %-10s %s\n", lib.ColorYellow+lib.ColorBold, F[0], lib.ColorReset, "", F[2])
		}
	}

	fmt.Printf("%s\n\n", Sep)
	fmt.Printf("%s%sEXAMPLES%s\n", lib.ColorCyan+lib.ColorBold, "  ", lib.ColorReset)
	fmt.Printf("%s\n", Sep)
	Examples := []string{
		"htonspider -m port -s example.com -p 1-1024 -b -e scan.txt",
		"htonspider -m port -s example.com -p all -T 500 -t 500 -U",
		"htonspider -m dns  -s example.com",
		"htonspider -m sub  -s example.com -W wordlist.txt -T 50",
		"htonspider -m arp  -s 192.168.1.0/24",
		"htonspider -m proxy -s proxies.txt -A -e alive.txt",
		"htonspider -m path -s https://example.com -W paths.txt -e found.txt",
		"htonspider -m vuln -s example.com -p 80,443,22",
		"htonspider -m full -s example.com -V -e report.txt",
	}
	for _, E := range Examples {
		fmt.Printf("  %s$%s %s\n", lib.ColorGray, lib.ColorReset, E)
	}
	fmt.Printf("%s\n\n", Sep)
}

var VerboseEnabled bool

func SetVerbose(V bool) {
	VerboseEnabled = V
	lib.VerboseMode = V
}

func LoadLines(Path string) ([]string, error) {
	F, Err := os.Open(Path)
	if Err != nil {
		return nil, Err
	}
	defer F.Close()
	var Lines []string
	Scanner := bufio.NewScanner(F)
	for Scanner.Scan() {
		Line := strings.TrimSpace(Scanner.Text())
		if Line != "" && !strings.HasPrefix(Line, "#") {
			Lines = append(Lines, Line)
		}
	}
	return Lines, nil
}

func ExportResult(Content string, Path string) {
	Exp := lib.NewExporter()
	if Err := Exp.SaveToFile(Content, Path); Err != nil {
		lib.LogError("Export failed: " + Err.Error())
	} else {
		lib.LogSuccess("Exported to: " + Path)
	}
}

func RunPort(Target string, PortInput string, TimeoutMs int, Threads int, Banner bool, UDP bool, Export string) {
	lib.PrintTitle("PORT SCAN")
	S := lib.NewScanner(TimeoutMs, Threads, Banner)
	var Ports []int
	switch strings.ToLower(PortInput) {
	case "", "common":
		Ports = lib.CommonPorts
		lib.LogInfo(fmt.Sprintf("Using %d common ports", len(Ports)))
	case "all":
		lib.LogWarn("Full 65535-port scan — this may take a while")
		Ports = lib.AllPorts()
	default:
		Ports = S.ParsePortRange(PortInput)
		lib.LogInfo(fmt.Sprintf("Parsed %d port(s) from range", len(Ports)))
	}

	Result := S.ScanPorts(Target, Ports)

	if UDP {
		UDPPorts := []int{53, 67, 68, 69, 123, 137, 138, 161, 162, 500, 514}
		lib.LogInfo("Running UDP scan on common UDP ports...")
		UDPResults := S.ScanUDPPorts(Target, UDPPorts)
		Result.Ports = append(Result.Ports, UDPResults...)
	}

	fmt.Println(S.RenderTable(Result))

	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: Target, ScanResult: &Result}), Export)
	}
}

func RunDns(Target string, Export string) {
	lib.PrintTitle("DNS RESOLVE & TRACE")
	R := lib.NewDnsResolver(5)
	Result := R.FullResolve(Target)
	fmt.Println(R.RenderTable(Result))
	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: Target, DnsResult: &Result}), Export)
	}
}

func RunSub(Target string, WordlistPath string, Threads int, TimeoutSec int, Export string) {
	lib.PrintTitle("SUBDOMAIN DISCOVERY")
	var Words []string
	if WordlistPath != "" {
		W, Err := LoadLines(WordlistPath)
		if Err != nil {
			lib.LogWarn("Could not read wordlist, using builtin")
		} else {
			Words = W
			lib.LogInfo(fmt.Sprintf("Loaded %d words from %s", len(Words), WordlistPath))
		}
	}
	S := lib.NewSubdomainScanner(TimeoutSec, Threads, Words)
	Result := S.Scan(Target)
	fmt.Println(S.RenderTable(Result))
	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: Target, SubdomainResult: &Result}), Export)
	}
}

func RunArp(CIDR string, Threads int, Export string) {
	lib.PrintTitle("ARP NETWORK SCAN")
	A := lib.NewArpScanner(1, Threads)
	Result := A.Scan(CIDR)
	fmt.Println(A.RenderTable(Result))
	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: CIDR, ArpResult: &Result}), Export)
	}
}

func RunProxy(Source string, AliveOnly bool, Threads int, TimeoutSec int, Export string) {
	lib.PrintTitle("PROXY / IP CHECKER")
	var Addresses []string

	if _, Err := os.Stat(Source); Err == nil {
		Lines, Err := LoadLines(Source)
		if Err != nil {
			lib.LogError("Cannot read file: " + Err.Error())
			return
		}
		Addresses = Lines
		lib.LogInfo(fmt.Sprintf("Loaded %d entries from %s", len(Addresses), Source))
	} else {
		for _, A := range strings.Split(Source, ",") {
			A = strings.TrimSpace(A)
			if A != "" {
				Addresses = append(Addresses, A)
			}
		}
	}

	if len(Addresses) == 0 {
		lib.LogError("No addresses to check")
		return
	}

	PC := lib.NewProxyChecker(TimeoutSec, Threads, "")
	Result := PC.CheckAll(Addresses)
	fmt.Println(PC.RenderTable(Result))

	if Export != "" {
		Exp := lib.NewExporter()
		var Content string
		if AliveOnly {
			Content = Exp.ExportAliveProxies(Result)
		} else {
			Content = Exp.BuildReport(lib.ExportData{Target: Source, ProxyResult: &Result})
		}
		ExportResult(Content, Export)
	}
}

func RunPath(Target string, WordlistPath string, Threads int, TimeoutSec int, Export string) {
	lib.PrintTitle("PATH & FILE DISCOVERY")
	var Paths []string
	if WordlistPath != "" {
		P, Err := LoadLines(WordlistPath)
		if Err != nil {
			lib.LogWarn("Could not read wordlist, using builtin")
		} else {
			Paths = P
			lib.LogInfo(fmt.Sprintf("Loaded %d paths from %s", len(Paths), WordlistPath))
		}
	}
	PS := lib.NewPathScanner(TimeoutSec, Threads, Paths)
	Result := PS.Scan(Target)
	fmt.Println(PS.RenderTable(Result))
	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: Target, PathResult: &Result}), Export)
	}
}

func RunVuln(Target string, PortInput string, TimeoutMs int, Threads int, Export string) {
	lib.PrintTitle("SERVICE & VULNERABILITY DETECTION")
	S := lib.NewScanner(TimeoutMs, Threads, true)
	var Ports []int
	if PortInput == "" || PortInput == "common" {
		Ports = lib.CommonPorts
	} else {
		Ports = S.ParsePortRange(PortInput)
	}
	lib.LogInfo("Running port scan first...")
	ScanRes := S.ScanPorts(Target, Ports)
	if len(ScanRes.Ports) == 0 {
		lib.LogWarn("No open ports found, aborting")
		return
	}
	SD := lib.NewServiceDetector(5)
	Result := SD.Detect(Target, ScanRes.Ports)
	fmt.Println(SD.RenderTable(Result))
	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(lib.ExportData{Target: Target, ScanResult: &ScanRes, ServiceResult: &Result}), Export)
	}
}

func RunFull(Target string, PortInput string, WordlistPath string, TimeoutMs int, Threads int, Export string) {
	lib.PrintTitle("FULL SCAN — ALL MODULES")
	Data := lib.ExportData{Target: Target}

	lib.LogInfo("[1/6] DNS Resolve & Trace")
	DnsR := lib.NewDnsResolver(5)
	DnsResult := DnsR.FullResolve(Target)
	Data.DnsResult = &DnsResult

	lib.LogInfo("[2/6] Subdomain Discovery")
	var Words []string
	if WordlistPath != "" {
		Words, _ = LoadLines(WordlistPath)
	}
	SubS := lib.NewSubdomainScanner(TimeoutMs/1000+1, Threads, Words)
	SubResult := SubS.Scan(Target)
	Data.SubdomainResult = &SubResult

	lib.LogInfo("[3/6] Port Scan")
	Scanner := lib.NewScanner(TimeoutMs, Threads, true)
	var Ports []int
	if PortInput == "" || PortInput == "common" {
		Ports = lib.CommonPorts
	} else {
		Ports = Scanner.ParsePortRange(PortInput)
	}
	ScanResult := Scanner.ScanPorts(Target, Ports)
	Data.ScanResult = &ScanResult

	if len(ScanResult.Ports) > 0 {
		lib.LogInfo("[4/6] Service & Vulnerability Detection")
		SD := lib.NewServiceDetector(5)
		SvcResult := SD.Detect(Target, ScanResult.Ports)
		Data.ServiceResult = &SvcResult
	} else {
		lib.LogWarn("[4/6] Skipping — no open ports")
	}

	lib.LogInfo("[5/6] Path & File Discovery")
	PS := lib.NewPathScanner(5, Threads, nil)
	PathResult := PS.Scan(Target)
	Data.PathResult = &PathResult

	lib.LogInfo("[6/6] Building report...")

	TotalVulns := 0
	if Data.ServiceResult != nil {
		for _, Svc := range Data.ServiceResult.Services {
			TotalVulns += len(Svc.Vulns)
		}
	}
	SensitiveCount := 0
	for _, PR := range PathResult.Found {
		if PR.Sensitive {
			SensitiveCount++
		}
	}

	lib.PrintFrame()
	fmt.Printf("  %s%sSUMMARY%s\n", lib.ColorCyan, lib.ColorBold, lib.ColorReset)
	lib.PrintFrame()
	fmt.Printf("  %-20s %s\n", "Target:", Target)
	fmt.Printf("  %-20s %d\n", "DNS Records:", len(DnsResult.Records))
	fmt.Printf("  %-20s %d\n", "Subdomains Found:", len(SubResult.Found))
	fmt.Printf("  %-20s %d\n", "Open Ports:", len(ScanResult.Ports))
	if Data.ServiceResult != nil {
		fmt.Printf("  %-20s %d  %s(CVEs: %d)%s\n", "Services:", len(Data.ServiceResult.Services), lib.ColorRed, TotalVulns, lib.ColorReset)
	}
	fmt.Printf("  %-20s %d  %s(sensitive: %d)%s\n", "Paths Found:", len(PathResult.Found), lib.ColorYellow, SensitiveCount, lib.ColorReset)
	lib.PrintFrame()

	if Export != "" {
		Exp := lib.NewExporter()
		ExportResult(Exp.BuildReport(Data), Export)
	}
}

func main() {
	Mode := flag.String("m", "", "Scan mode: port | dns | sub | arp | proxy | path | vuln | full")
	Source := flag.String("s", "", "Target: host, IP, CIDR, comma-list, or file path")
	Ports := flag.String("p", "", "Port range: 80,443 | 1-1024 | all | common (default: common)")
	TimeoutMs := flag.Int("t", 800, "Timeout in milliseconds")
	Threads := flag.Int("T", 200, "Concurrent threads")
	Wordlist := flag.String("W", "", "Wordlist file for subdomain/path discovery")
	Export := flag.String("e", "", "Export results to file")
	AliveOnly := flag.Bool("A", false, "Export alive-only (proxy mode)")
	UDP := flag.Bool("U", false, "Also run UDP scan")
	Banner := flag.Bool("b", false, "Grab service banners")
	Verbose := flag.Bool("V", false, "Verbose/debug output")
	NoBanner := flag.Bool("n", false, "Skip ASCII banner")

	flag.Usage = ShowHelp
	flag.Parse()

	if !*NoBanner {
		ShowBanner()
	}

	SetVerbose(*Verbose)

	if *Mode == "" || *Source == "" {
		if *Mode == "" && *Source == "" {
			ShowHelp()
			os.Exit(0)
		}
		lib.LogError("Both -m <mode> and -s <target> are required")
		fmt.Printf("  Run %shtonspider -h%s for usage\n\n", lib.ColorCyan, lib.ColorReset)
		os.Exit(1)
	}

	Start := time.Now()

	switch strings.ToLower(*Mode) {
	case "port":
		RunPort(*Source, *Ports, *TimeoutMs, *Threads, *Banner, *UDP, *Export)
	case "dns":
		RunDns(*Source, *Export)
	case "sub":
		TimeoutSec := *TimeoutMs/1000 + 1
		RunSub(*Source, *Wordlist, *Threads, TimeoutSec, *Export)
	case "arp":
		RunArp(*Source, *Threads, *Export)
	case "proxy":
		TimeoutSec := *TimeoutMs/1000 + 1
		RunProxy(*Source, *AliveOnly, *Threads, TimeoutSec, *Export)
	case "path":
		TimeoutSec := *TimeoutMs/1000 + 1
		RunPath(*Source, *Wordlist, *Threads, TimeoutSec, *Export)
	case "vuln":
		RunVuln(*Source, *Ports, *TimeoutMs, *Threads, *Export)
	case "full":
		RunFull(*Source, *Ports, *Wordlist, *TimeoutMs, *Threads, *Export)
	default:
		lib.LogError(fmt.Sprintf("Unknown mode: %s", *Mode))
		fmt.Printf("  Available: port, dns, sub, arp, proxy, path, vuln, full\n\n")
		os.Exit(1)
	}

	lib.LogDebug(fmt.Sprintf("Total elapsed: %s", time.Since(Start).Round(time.Millisecond)))
}
