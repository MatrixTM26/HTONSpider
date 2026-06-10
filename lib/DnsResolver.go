package lib

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type DnsRecord struct {
	RecordType string
	Value      string
}

type DnsResult struct {
	Target  string
	IP      []string
	Records []DnsRecord
	Trace   []string
	Elapsed time.Duration
}

type DnsResolver struct {
	Timeout time.Duration
}

func NewDnsResolver(TimeoutSec int) *DnsResolver {
	return &DnsResolver{Timeout: time.Duration(TimeoutSec) * time.Second}
}

func (D *DnsResolver) TraceDns(Target string) []string {
	var Trace []string
	Trace = append(Trace, "[Root]  . (Root Zone)")
	Labels := strings.Split(Target, ".")
	for I := len(Labels) - 1; I >= 0; I-- {
		Zone := strings.Join(Labels[I:], ".")
		NSRecords, Err := net.LookupNS(Zone)
		if Err == nil && len(NSRecords) > 0 {
			NS := strings.TrimSuffix(NSRecords[0].Host, ".")
			Trace = append(Trace, fmt.Sprintf("[NS]    %s -> %s", Zone, NS))
			NSAddrs, Err2 := net.LookupHost(NS)
			if Err2 == nil && len(NSAddrs) > 0 {
				Trace = append(Trace, fmt.Sprintf("[A]     %s -> %s", NS, NSAddrs[0]))
			}
		}
	}
	FinalAddrs, Err := net.LookupHost(Target)
	if Err == nil {
		for _, Addr := range FinalAddrs {
			Trace = append(Trace, fmt.Sprintf("[FINAL] %s -> %s", Target, Addr))
		}
	}
	return Trace
}

func (D *DnsResolver) FullResolve(Target string) DnsResult {
	Start := time.Now()
	Result := DnsResult{Target: Target}

	LogInfo(fmt.Sprintf("Resolving DNS records for %s", Target))

	Addrs, Err := net.LookupHost(Target)
	if Err == nil {
		Result.IP = Addrs
		for _, Addr := range Addrs {
			RecType := "A"
			if strings.Contains(Addr, ":") {
				RecType = "AAAA"
			}
			Result.Records = append(Result.Records, DnsRecord{RecordType: RecType, Value: Addr})
			LogDebugV(fmt.Sprintf("%s record: %s", RecType, Addr))
		}
	} else {
		LogError(fmt.Sprintf("A/AAAA lookup failed: %s", Err.Error()))
	}

	CNAME, Err := net.LookupCNAME(Target)
	if Err == nil && CNAME != Target+"." && CNAME != "" {
		Val := strings.TrimSuffix(CNAME, ".")
		Result.Records = append(Result.Records, DnsRecord{RecordType: "CNAME", Value: Val})
		LogDebugV(fmt.Sprintf("CNAME record: %s", Val))
	}

	MXRecords, Err := net.LookupMX(Target)
	if Err == nil {
		for _, MX := range MXRecords {
			Val := fmt.Sprintf("%d %s", MX.Pref, strings.TrimSuffix(MX.Host, "."))
			Result.Records = append(Result.Records, DnsRecord{RecordType: "MX", Value: Val})
			LogDebugV(fmt.Sprintf("MX record: %s", Val))
		}
	}

	NSRecords, Err := net.LookupNS(Target)
	if Err == nil {
		for _, NS := range NSRecords {
			Val := strings.TrimSuffix(NS.Host, ".")
			Result.Records = append(Result.Records, DnsRecord{RecordType: "NS", Value: Val})
			LogDebugV(fmt.Sprintf("NS record: %s", Val))
		}
	}

	TXTRecords, Err := net.LookupTXT(Target)
	if Err == nil {
		for _, TXT := range TXTRecords {
			Result.Records = append(Result.Records, DnsRecord{RecordType: "TXT", Value: TXT})
			LogDebugV(fmt.Sprintf("TXT record: %s", TXT))
		}
	}

	if len(Result.IP) > 0 {
		ReverseNames, Err := net.LookupAddr(Result.IP[0])
		if Err == nil {
			for _, Name := range ReverseNames {
				Val := strings.TrimSuffix(Name, ".")
				Result.Records = append(Result.Records, DnsRecord{RecordType: "PTR", Value: Val})
				LogDebugV(fmt.Sprintf("PTR record: %s", Val))
			}
		}
	}

	LogInfo("Running DNS trace...")
	Result.Trace = D.TraceDns(Target)
	Result.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("DNS resolve done — %d records, %d trace steps in %s",
		len(Result.Records), len(Result.Trace), Result.Elapsed.Round(time.Millisecond)))
	return Result
}

func (D *DnsResolver) RenderTable(Result DnsResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"TYPE", "VALUE"}
	var Rows [][]string
	for _, R := range Result.Records {
		Rows = append(Rows, []string{R.RecordType, R.Value})
	}
	Widths := CalcColWidths(Headers, Rows, W-2)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  TARGET  : %s\n", Result.Target))
	B.WriteString(fmt.Sprintf("  ELAPSED : %s\n", Result.Elapsed.Round(time.Millisecond)))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	B.WriteString(TableRow(Headers, Widths))
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	for _, Row := range Rows {
		B.WriteString(TableRow(Row, Widths))
	}
	B.WriteString(fmt.Sprintf("%s\n\n", Sep))

	B.WriteString(fmt.Sprintf("  DNS TRACE\n%s\n", Sep))
	for _, T := range Result.Trace {
		B.WriteString(fmt.Sprintf("  %s\n", T))
	}
	B.WriteString(fmt.Sprintf("%s\n", Sep))
	return B.String()
}
