package lib

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type ExportData struct {
	Target          string
	ScanResult      *ScanResult
	DnsResult       *DnsResult
	SubdomainResult *SubdomainScanResult
	ArpResult       *ArpScanResult
	ProxyResult     *ProxyCheckResult
	PathResult      *PathScanResult
	ServiceResult   *ServiceDetectResult
}

type Exporter struct{}

func NewExporter() *Exporter {
	return &Exporter{}
}

func (E *Exporter) BuildReport(Data ExportData) string {
	var B strings.Builder
	Line := strings.Repeat("=", 90)
	Sep := strings.Repeat("-", 90)

	B.WriteString(fmt.Sprintf("%s\n", Line))
	B.WriteString("  HTONSpider - Full Scan Report\n")
	B.WriteString(fmt.Sprintf("  Target  : %s\n", Data.Target))
	B.WriteString(fmt.Sprintf("  Time    : %s\n", time.Now().Format("2006-01-02 15:04:05")))
	B.WriteString(fmt.Sprintf("%s\n\n", Line))

	if Data.DnsResult != nil {
		B.WriteString(fmt.Sprintf("  [DNS RECORDS & TRACE]\n%s\n", Sep))
		for _, R := range Data.DnsResult.Records {
			B.WriteString(fmt.Sprintf("  %-10s %s\n", R.RecordType, R.Value))
		}
		B.WriteString("\n  DNS TRACE:\n")
		for _, T := range Data.DnsResult.Trace {
			B.WriteString(fmt.Sprintf("  %s\n", T))
		}
		B.WriteString("\n")
	}

	if Data.SubdomainResult != nil {
		B.WriteString(fmt.Sprintf("  [SUBDOMAIN DISCOVERY]\n%s\n", Sep))
		B.WriteString(fmt.Sprintf("  Found : %d / %d\n", len(Data.SubdomainResult.Found), Data.SubdomainResult.Tried))
		for _, SR := range Data.SubdomainResult.Found {
			B.WriteString(fmt.Sprintf("  %-45s %s\n", SR.Subdomain, strings.Join(SR.IP, ", ")))
		}
		B.WriteString("\n")
	}

	if Data.ScanResult != nil {
		B.WriteString(fmt.Sprintf("  [PORT SCAN]\n%s\n", Sep))
		B.WriteString(fmt.Sprintf("  Target : %s (%s)  Open: %d\n", Data.ScanResult.Target, Data.ScanResult.IP, len(Data.ScanResult.Ports)))
		for _, PR := range Data.ScanResult.Ports {
			Banner := PR.Banner
			if Banner == "" {
				Banner = "-"
			}
			B.WriteString(fmt.Sprintf("  %-12s %-10s %-22s %s\n",
				fmt.Sprintf("%d/tcp", PR.Port), "open", PR.Service, Banner))
		}
		B.WriteString("\n")
	}

	if Data.ServiceResult != nil {
		B.WriteString(fmt.Sprintf("  [SERVICE & VULNERABILITY DETECTION]\n%s\n", Sep))
		for _, Svc := range Data.ServiceResult.Services {
			B.WriteString(fmt.Sprintf("  PORT    : %d/tcp  SERVICE: %s\n", Svc.Port, Svc.ServiceName))
			if Svc.Fingerprint != "" && Svc.Fingerprint != Svc.ServiceName {
				B.WriteString(fmt.Sprintf("  VERSION : %s\n", Svc.Fingerprint))
			}
			if Svc.Banner != "" {
				B.WriteString(fmt.Sprintf("  BANNER  : %s\n", Svc.Banner))
			}
			if len(Svc.Headers) > 0 {
				B.WriteString("  HEADERS :\n")
				for K, V := range Svc.Headers {
					B.WriteString(fmt.Sprintf("    %-35s %s\n", K+":", V))
				}
			}
			if len(Svc.Vulns) > 0 {
				B.WriteString("  VULNS   :\n")
				for _, V := range Svc.Vulns {
					B.WriteString(fmt.Sprintf("    [%s] %s - %s\n", V.Severity, V.CVEID, V.Description))
					B.WriteString(fmt.Sprintf("           REF: %s\n", V.Reference))
				}
			}
			B.WriteString("\n")
		}
	}

	if Data.ArpResult != nil {
		B.WriteString(fmt.Sprintf("  [ARP NETWORK SCAN]\n%s\n", Sep))
		B.WriteString(fmt.Sprintf("  Network : %s  Alive: %d\n", Data.ArpResult.NetworkCIDR, len(Data.ArpResult.Hosts)))
		for _, H := range Data.ArpResult.Hosts {
			MAC := H.MAC
			if MAC == "" {
				MAC = "-"
			}
			Host := H.Hostname
			if Host == "" {
				Host = "-"
			}
			B.WriteString(fmt.Sprintf("  %-18s %-20s %s\n", H.IP, MAC, Host))
		}
		B.WriteString("\n")
	}

	if Data.ProxyResult != nil {
		B.WriteString(fmt.Sprintf("  [PROXY / IP CHECK]\n%s\n", Sep))
		B.WriteString(fmt.Sprintf("  Total: %d  Alive: %d  Dead: %d\n",
			Data.ProxyResult.Total, len(Data.ProxyResult.Alive), len(Data.ProxyResult.Dead)))
		for _, PE := range Data.ProxyResult.Alive {
			B.WriteString(fmt.Sprintf("  [ALIVE] %-32s  Latency: %s  Type: %s\n",
				PE.Address, PE.Latency.Round(time.Millisecond), PE.AnonymType))
		}
		B.WriteString("\n")
	}

	if Data.PathResult != nil {
		B.WriteString(fmt.Sprintf("  [PATH & SENSITIVE FILES]\n%s\n", Sep))
		B.WriteString(fmt.Sprintf("  Found : %d / %d\n", len(Data.PathResult.Found), Data.PathResult.Tried))
		for _, PR := range Data.PathResult.Found {
			Note := ""
			if PR.Sensitive {
				Note = "[!] HIGH SENSITIVITY"
			}
			if PR.Redirect != "" {
				Note = "-> " + PR.Redirect
			}
			B.WriteString(fmt.Sprintf("  [%d] %-45s %s\n", PR.StatusCode, PR.Path, Note))
		}
		B.WriteString("\n")
	}

	B.WriteString(fmt.Sprintf("%s\n", Line))
	B.WriteString("  End of Report - HTONSpider\n")
	B.WriteString(fmt.Sprintf("%s\n", Line))

	return B.String()
}

func (E *Exporter) ExportAliveProxies(Result ProxyCheckResult) string {
	var B strings.Builder
	for _, PE := range Result.Alive {
		B.WriteString(fmt.Sprintf("%s\n", PE.Address))
	}
	return B.String()
}

func (E *Exporter) ExportSubdomains(Result SubdomainScanResult) string {
	var B strings.Builder
	for _, SR := range Result.Found {
		B.WriteString(fmt.Sprintf("%s\n", SR.Subdomain))
	}
	return B.String()
}

func (E *Exporter) SaveToFile(Content string, Path string) error {
	return os.WriteFile(Path, []byte(Content), 0644)
}

func (E *Exporter) GenerateFilename(Target string, Suffix string) string {
	Clean := strings.ReplaceAll(Target, ".", "_")
	Clean = strings.ReplaceAll(Clean, "/", "_")
	Clean = strings.ReplaceAll(Clean, ":", "_")
	Ts := time.Now().Format("20060102_150405")
	return fmt.Sprintf("HTONSpider_%s_%s_%s.txt", Clean, Suffix, Ts)
}
