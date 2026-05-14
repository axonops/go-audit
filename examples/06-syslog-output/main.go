// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Syslog-output demonstrates sending audit events to a syslog server
// using RFC 5424 format over TCP. A local TCP receiver is embedded so
// the example is self-contained — no external syslog server needed.
package main

import (
	"bufio"
	"context"
	_ "embed"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/outputconfig"
	_ "github.com/axonops/audit/outputs" // registers stdout, file, syslog, webhook, loki
)

//go:generate go run github.com/axonops/audit/cmd/audit-gen -input taxonomy.yaml -output audit_generated.go -package main

//go:embed taxonomy.yaml
var taxonomyYAML []byte

func main() {
	// 1. Start a local TCP syslog receiver on port 1514.
	//    In production, this would be rsyslog, syslog-ng, Splunk, etc.
	received := startSyslogReceiver("localhost:1514")

	// Give the listener time to bind.
	time.Sleep(50 * time.Millisecond)

	// 2. Parse taxonomy and load output config.
	// Single-call facade: parse taxonomy, load outputs, create auditor.
	auditor, err := outputconfig.New(context.Background(), taxonomyYAML, "outputs.yaml")
	if err != nil {
		log.Fatalf("create auditor: %v", err)
	}

	// 4. Emit audit events — they are formatted as RFC 5424 and sent
	//    over TCP to our local receiver.
	events := []audit.Event{
		NewAuthLoginEvent("alice", "success"),
		NewUserCreateEvent("bob", "success"),
		NewAuthFailureEvent("mallory", "failure", "invalid_password"),
		NewConfigChangeEvent("alice", "success", "max_retries", "3", "5"),
	}

	for _, e := range events {
		if auditErr := auditor.AuditEvent(e); auditErr != nil {
			log.Printf("audit error: %v", auditErr)
		}
	}

	// 5. Close flushes and delivers all pending events.
	if closeErr := auditor.Close(); closeErr != nil {
		log.Printf("close auditor: %v", closeErr)
	}

	// 6. Print what the syslog receiver captured, highlighting the
	//    RFC 5424 PRI field which now reflects the audit event severity.
	time.Sleep(100 * time.Millisecond) // allow receiver goroutine to finish
	messages := received()

	fmt.Fprintln(os.Stderr, "\n--- RFC 5424 messages received by syslog server ---")
	fmt.Fprintln(os.Stderr, "Note: PRI = facility(local0=128) + syslog severity")
	fmt.Fprintln(os.Stderr, "  <130> = LOG_CRIT (audit severity 10)")
	fmt.Fprintln(os.Stderr, "  <131> = LOG_ERR (audit severity 8-9)")
	fmt.Fprintln(os.Stderr, "  <132> = LOG_WARNING (audit severity 6-7)")
	fmt.Fprintln(os.Stderr, "  <133> = LOG_NOTICE (audit severity 4-5)")
	fmt.Fprintln(os.Stderr, "  <134> = LOG_INFO (audit severity 1-3)")
	for i, msg := range messages {
		fmt.Fprintf(os.Stderr, "\n[Message %d]\n", i+1)
		// Show the full RFC 5424 message (truncated for readability).
		if len(msg) > 200 {
			fmt.Fprintf(os.Stderr, "%s...\n", msg[:200])
		} else {
			fmt.Fprintln(os.Stderr, msg)
		}
	}
	fmt.Fprintf(os.Stderr, "\nTotal: %d RFC 5424 messages received\n", len(messages))
}

// startSyslogReceiver starts a TCP listener that collects RFC 5424
// syslog messages. It returns a function that, when called, returns
// all received messages. This simulates a syslog server for the
// example — in production you'd use rsyslog, syslog-ng, or a SIEM.
func startSyslogReceiver(addr string) func() []string {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("start syslog receiver: %v", err)
	}

	var (
		mu       sync.Mutex
		messages []string
		wg       sync.WaitGroup
	)

	// Accept connections in the background.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return // listener closed
			}
			wg.Add(1)
			go func(c net.Conn) {
				defer wg.Done()
				defer func() { _ = c.Close() }()
				scanner := bufio.NewScanner(c)
				for scanner.Scan() {
					line := strings.TrimSpace(scanner.Text())
					if line == "" {
						continue
					}
					mu.Lock()
					messages = append(messages, line)
					mu.Unlock()
				}
			}(conn)
		}
	}()

	// Return a function that closes the listener and returns messages.
	return func() []string {
		_ = ln.Close()
		wg.Wait()
		mu.Lock()
		defer mu.Unlock()
		return messages
	}
}
