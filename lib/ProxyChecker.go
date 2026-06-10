package lib

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ProxyEntry struct {
	Address    string
	Alive      bool
	Latency    time.Duration
	StatusCode int
	AnonymType string
}

type ProxyCheckResult struct {
	Total   int
	Alive   []ProxyEntry
	Dead    []ProxyEntry
	Elapsed time.Duration
}

type ProxyChecker struct {
	Timeout     time.Duration
	Concurrency int
	TestURL     string
}

func NewProxyChecker(TimeoutSec int, Concurrency int, TestURL string) *ProxyChecker {
	URL := TestURL
	if URL == "" {
		URL = "http://httpbin.org/ip"
	}
	return &ProxyChecker{
		Timeout:     time.Duration(TimeoutSec) * time.Second,
		Concurrency: Concurrency,
		TestURL:     URL,
	}
}

func (P *ProxyChecker) CheckProxy(Address string) ProxyEntry {
	Entry := ProxyEntry{Address: Address}
	Start := time.Now()

	Dialer := &net.Dialer{Timeout: P.Timeout}
	Transport := &http.Transport{
		DialContext: func(Ctx context.Context, Network, Addr string) (net.Conn, error) {
			return Dialer.DialContext(Ctx, Network, Address)
		},
		DisableKeepAlives: true,
	}

	Client := &http.Client{Transport: Transport, Timeout: P.Timeout}
	Resp, Err := Client.Get(P.TestURL)
	Entry.Latency = time.Since(Start)

	if Err != nil {
		Entry.Alive = false
		return Entry
	}
	defer Resp.Body.Close()

	Entry.Alive = Resp.StatusCode < 500
	Entry.StatusCode = Resp.StatusCode
	if Resp.Header.Get("X-Forwarded-For") == "" {
		Entry.AnonymType = "Elite"
	} else {
		Entry.AnonymType = "Transparent"
	}
	return Entry
}

func (P *ProxyChecker) CheckAll(Addresses []string) ProxyCheckResult {
	Start := time.Now()
	Result := ProxyCheckResult{Total: len(Addresses)}

	Sem := make(chan struct{}, P.Concurrency)
	Mu := &sync.Mutex{}
	Wg := &sync.WaitGroup{}
	var Counter int64

	LogInfo(fmt.Sprintf("Proxy check — %d addresses, threads: %d", len(Addresses), P.Concurrency))

	for _, Addr := range Addresses {
		Wg.Add(1)
		Sem <- struct{}{}
		go func(A string) {
			defer Wg.Done()
			defer func() { <-Sem }()
			if strings.Contains(A, "://") {
				A = strings.SplitN(A, "://", 2)[1]
			}
			Entry := P.CheckProxy(A)
			Done := atomic.AddInt64(&Counter, 1)
			if Done%10 == 0 {
				LogDebugV(fmt.Sprintf("Progress %d/%d checked", Done, int64(len(Addresses))))
			}
			Mu.Lock()
			if Entry.Alive {
				LogSuccess(fmt.Sprintf("Alive: %s (%s, %s)", A, Entry.AnonymType, Entry.Latency.Round(time.Millisecond)))
				Result.Alive = append(Result.Alive, Entry)
			} else {
				Result.Dead = append(Result.Dead, Entry)
			}
			Mu.Unlock()
		}(Addr)
	}

	Wg.Wait()
	Result.Elapsed = time.Since(Start)
	LogInfo(fmt.Sprintf("Proxy check done — %d alive / %d dead in %s",
		len(Result.Alive), len(Result.Dead), Result.Elapsed.Round(time.Millisecond)))
	return Result
}

func (P *ProxyChecker) LoadFromFile(Path string) ([]string, error) {
	F, Err := os.Open(Path)
	if Err != nil {
		return nil, Err
	}
	defer F.Close()
	var List []string
	Scanner := bufio.NewScanner(F)
	for Scanner.Scan() {
		Line := strings.TrimSpace(Scanner.Text())
		if Line != "" && !strings.HasPrefix(Line, "#") {
			List = append(List, Line)
		}
	}
	return List, nil
}

func (P *ProxyChecker) RenderTable(Result ProxyCheckResult) string {
	var B strings.Builder
	W := TermWidth()
	Sep := strings.Repeat("-", W)

	Headers := []string{"ADDRESS", "LATENCY", "STATUS", "TYPE"}
	var Rows [][]string
	for _, E := range Result.Alive {
		Rows = append(Rows, []string{
			E.Address,
			E.Latency.Round(time.Millisecond).String(),
			fmt.Sprintf("%d", E.StatusCode),
			E.AnonymType,
		})
	}
	Widths := CalcColWidths(Headers, Rows, W-2)

	B.WriteString(fmt.Sprintf("\n%s\n", Sep))
	B.WriteString(fmt.Sprintf("  TOTAL   : %d\n", Result.Total))
	B.WriteString(fmt.Sprintf("  ALIVE   : %d\n", len(Result.Alive)))
	B.WriteString(fmt.Sprintf("  DEAD    : %d\n", len(Result.Dead)))
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
