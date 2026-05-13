@syslog @docker
Feature: Syslog Output
  As a library consumer, I want to send audit events to a syslog server
  so that they integrate with my centralised log management infrastructure.

  The syslog output supports TCP, UDP, and TCP+TLS (including mTLS)
  transports. Events are formatted as RFC 5424 structured syslog messages.
  UDP uses one-message-per-datagram (no octet-count framing). TCP uses
  RFC 5425 message-length framing. Reconnection uses bounded exponential
  backoff with jitter.

  Background:
    Given a standard test taxonomy

  # --- Transport variants ---

  Scenario: Deliver event over TCP plain
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over UDP
    Given an auditor with syslog output on "udp" to "127.0.0.1:5515"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over TLS with CA certificate
    Given an auditor with syslog TLS output to "localhost:6514" with CA cert
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Deliver event over mTLS with client certificate
    Given an auditor with syslog mTLS output to "localhost:6515"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Multiple events delivered over TCP
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit 5 uniquely marked events
    And I close the auditor
    Then the syslog server should contain all 5 markers within 10 seconds

  # --- RFC 5424 format ---

  Scenario: Syslog message contains app name
    Given an auditor with syslog output on "tcp" to "localhost:5514" with app name "bdd-audit"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds
    # Structural assertion (#572). The audit syslog client routes
    # Config.AppName into the RFC 5424 MSGID field per srslog's
    # wire mapping; APP-NAME is set to the process binary path.
    # Asserting on the parsed MSGID structurally rather than via
    # substring matching catches framing regressions that a
    # substring search would miss.
    And the syslog message with the marker should have msg-id "bdd-audit"
    And the syslog message with the marker should have well-formed RFC 5424 structure

  Scenario: Syslog message contains timestamp
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds
    And the syslog line with the marker should contain the current year

  # --- TLS configuration errors ---

  Scenario: Invalid CA certificate rejected at construction
    When I try to create a syslog output on "tcp+tls" to "localhost:6514" with invalid CA
    # Error message comes from Go crypto/tls and varies by platform;
    # substring match is intentional here.
    Then the syslog construction should fail with an error containing "certificate"

  Scenario: TLS cert without key is rejected with exact error
    When I try to create a syslog output with TLS cert but no key
    Then the syslog construction should fail with exact error:
      """
      audit: config validation failed: syslog tls_cert and tls_key must both be set or both empty
      """

  Scenario: TLS key without cert is rejected with exact error
    When I try to create a syslog output with TLS key but no cert
    Then the syslog construction should fail with exact error:
      """
      audit: config validation failed: syslog tls_cert and tls_key must both be set or both empty
      """

  # --- Config validation ---

  Scenario: Empty address is rejected with exact error
    When I try to create a syslog output with empty address
    Then the syslog construction should fail with exact error:
      """
      audit: config validation failed: syslog address must not be empty
      """

  Scenario: Invalid network type is rejected with exact error
    When I try to create a syslog output on "invalid" to "localhost:5514"
    Then the syslog construction should fail with exact error:
      """
      audit: config validation failed: syslog network "invalid" must be tcp, udp, or tcp+tls
      """

  Scenario: Invalid facility is rejected with exact error
    When I try to create a syslog output with facility "bogus"
    Then the syslog construction should fail with exact error:
      """
      audit/syslog: facility "bogus": audit: config validation failed: unknown syslog facility "bogus"
      """

  # --- Hostname configuration (#237) ---

  Scenario: Syslog hostname from Config appears in RFC 5424 header
    Given an auditor with syslog output on "tcp" to "localhost:5514" with hostname "bdd-custom-host"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds
    # Structural assertion (#572) — pins the configured hostname
    # to the RFC 5424 HOSTNAME field specifically, rather than a
    # substring-anywhere search that could match a body field.
    And the syslog message with the marker should have hostname "bdd-custom-host"

  Scenario: Syslog hostname defaults to os.Hostname when not configured
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Syslog invalid hostname with space is rejected
    When I try to create a syslog output on "tcp" to "localhost:5514" with hostname "host name"
    Then the syslog construction should fail with an error containing "invalid byte"

  Scenario: Syslog hostname exceeding 255 bytes is rejected
    When I try to create a syslog output on "tcp" to "localhost:5514" with hostname "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    Then the syslog construction should fail with an error containing "exceeds RFC 5424 maximum"

  Scenario: Default app name is "audit"
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds
    # Structural assertion (#572). The default `Config.AppName`
    # is the literal `audit` (syslog/config.go:29) and srslog
    # routes it into the MSGID position on the wire.
    And the syslog message with the marker should have msg-id "audit"

  Scenario Outline: Valid facility names are accepted
    Given an auditor with syslog output on "tcp" to "localhost:5514" with facility "<facility>"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

    Examples:
      | facility |
      | local0   |
      | local1   |
      | local7   |
      | auth     |
      | daemon   |

  # --- UDP edge cases ---

  Scenario: UDP large payload accepted without panic
    Given an auditor with syslog output on "udp" to "127.0.0.1:5515"
    When I audit an event with a 4096-byte payload
    Then the audit call should return no error

  Scenario: UDP does not use octet-count framing
    Given an auditor with syslog output on "udp" to "127.0.0.1:5515"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I close the auditor
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  # --- Reconnection ---

  Scenario: Syslog reconnects after server process restart
    Given an auditor with syslog output on "tcp" to "localhost:5514" with max retries 10
    When I audit a uniquely marked "user_create" event
    Then the syslog server should contain the marker within 10 seconds
    When I restart the syslog-ng process
    And I wait for syslog-ng to be ready
    And I audit a second uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the second marker within 15 seconds

  Scenario: Max retries exceeded returns error
    When I try to create a syslog output on "tcp" to "localhost:59999"
    Then the syslog construction should fail with an error containing "dial"

  # --- Syslog-specific metrics ---

  Scenario: Nil syslog metrics does not panic during delivery
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Syslog metrics configured during delivery does not panic
    Given mock syslog metrics are configured
    And an auditor with syslog output on "tcp" to "localhost:5514" with metrics and max retries 10
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  Scenario: Close is idempotent
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    And I close the auditor again
    Then the second close should return no error

  # --- Complete payload verification ---

  Scenario: All event fields present in syslog output
    Given an auditor with syslog output on "tcp" to "localhost:5514"
    When I audit event "user_create" with fields:
      | field     | value      |
      | outcome   | success    |
      | actor_id  | alice      |
      | marker    | syslog_all |
      | target_id | user-42    |
    And I close the auditor
    Then the syslog server should contain "syslog_all" within 10 seconds
    And the syslog line with "syslog_all" should contain "user_create"
    And the syslog line with "syslog_all" should contain "alice"

  # --- Batching (#599) ---
  #
  # The writeLoop accumulates events and flushes on count threshold,
  # byte threshold, timer timeout, or Close. Each batch triggers one
  # srslog call per entry so RFC 5425 octet-counting framing is
  # preserved per message. See docs/syslog-output.md "Batching".

  Scenario: Syslog batches events at batch_size threshold
    Given an auditor with syslog output on "tcp" to "localhost:5514" with batch size 10 and flush interval "10s"
    When I audit 10 uniquely marked events
    Then the syslog server should contain all 10 markers within 5 seconds

  Scenario: Syslog flushes on flush_interval timeout
    Given an auditor with syslog output on "tcp" to "localhost:5514" with batch size 1000 and flush interval "500ms"
    When I audit 3 uniquely marked events
    Then the syslog server should contain all 3 markers within 5 seconds

  Scenario: Syslog flushes partial batch on Close
    Given an auditor with syslog output on "tcp" to "localhost:5514" with batch size 1000 and flush interval "10s"
    When I audit 4 uniquely marked events
    And I close the auditor
    Then the syslog server should contain all 4 markers within 10 seconds

  Scenario: Syslog preserves RFC 5424 frame delimiters across batch
    Given an auditor with syslog output on "tcp" to "localhost:5514" with batch size 5 and flush interval "10s"
    When I audit 5 uniquely marked events
    Then the syslog server should contain all 5 markers within 5 seconds
    And each of the 5 delivered messages should be a distinct RFC 5424 frame

  Scenario: Syslog flushes oversized single event alone
    Given an auditor with syslog output on "tcp" to "localhost:5514" with batch size 100 and flush interval "10s" and max batch bytes 1024
    When I audit a uniquely marked event with a 2048-byte payload
    Then the syslog server should contain the marker within 5 seconds

  # --- Max event size (#688) ---
  #
  # Oversized events are rejected at Output.Write entry with
  # audit.ErrEventTooLarge. The auditor's drain goroutine swallows
  # the per-output error; from the consumer's view, Audit returns
  # nil but the event does not reach the receiver. Normal events
  # before and after the oversized one must continue to deliver.

  Scenario: Syslog rejects oversized event without stalling subsequent deliveries
    Given an auditor with syslog output on "tcp" to "localhost:5514" with max event bytes 1024
    When I audit a uniquely marked "user_create" event "sl_before"
    And I audit a uniquely marked event with a 4096-byte payload
    And I audit a uniquely marked "user_create" event "sl_after"
    And I close the auditor
    Then the syslog server should contain the "sl_before" marker within 10 seconds
    And the syslog server should contain the "sl_after" marker within 10 seconds

  Scenario: Syslog delivers event within max_event_bytes cap
    Given an auditor with syslog output on "tcp" to "localhost:5514" with max event bytes 1048576
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the marker within 10 seconds

  # --- Crash and replay (#553) ---
  #
  # The reconnect path must survive failure modes that exceed a
  # single clean restart:
  #
  #   - daemon killed mid-buffer, then comes back up before Close;
  #     every submitted event ends up either delivered or attributed
  #     to the OutputErrors counter (no silent loss).
  #
  #   - three rapid restarts in succession; reconnect backoff stays
  #     bounded — the recorded reconnect count does not climb into
  #     a storm.
  #
  #   - 1000 in-flight events when the daemon dies; on restart the
  #     auditor's drain catches up without leaking goroutines or
  #     hanging Close (TestMain goleak provides the leak gate).
  #
  # Accounting note: events still in flight when Close abandons the
  # drain (after ShutdownTimeout) may not yet have hit a terminal
  # counter. The "accounting holds" step checks that the submitted
  # count is fully accounted for OR that the delta is bounded by a
  # tolerance and the operator counters tell the same story
  # (delivered ≥ pre-stop events, OutputErrors ≥ post-stop events).

  Scenario: Syslog reconnects after kill mid-buffer and post-restart events deliver
    Given mock syslog metrics are configured
    And the auditor uses core metrics
    And an auditor with syslog output on "tcp" to "localhost:5514" with metrics and max retries 1
    When I audit 5 uniquely marked events
    And I restart the syslog-ng process
    And I wait for syslog-ng to be ready
    And I audit a second uniquely marked "user_create" event
    And I close the auditor
    Then the syslog server should contain the second marker within 15 seconds
    And the audit metrics submitted count should be 6

  Scenario: Three rapid syslog-ng restarts do not produce a reconnect storm
    Given mock syslog metrics are configured
    And the auditor uses core metrics
    And an auditor with syslog output on "tcp" to "localhost:5514" with metrics and max retries 2
    When I audit 5 uniquely marked events
    And I rapidly restart syslog-ng 3 times within 3 seconds
    And I audit a second uniquely marked "user_create" event
    And I close the auditor
    Then the syslog reconnect count should be at most 30
    And the audit metrics submitted count should be 6

  # --- TLS rejection (#552) ---
  #
  # The two scenarios below verify that the syslog output's TLS
  # client refuses to deliver to a receiver presenting a defective
  # certificate. The receiver lives in-process so the test does not
  # depend on Docker — bdd-syslog-ng-1 stays running on its valid
  # cert. The certificates are signed by a freshly-generated CA;
  # the audit client trusts that CA, so the rejection cause is
  # exactly the defect we install (expired NotAfter / wrong
  # DNSNames), not "unknown authority".

  Scenario: Syslog TLS rejects an expired server certificate
    Given bad TLS certs are generated
    And a syslog TLS receiver presenting an expired certificate
    When I try to send a syslog event over TLS to that receiver
    Then the TLS handshake should fail with "expired"

  Scenario: Syslog TLS rejects a wrong-CN server certificate
    Given bad TLS certs are generated
    And a syslog TLS receiver presenting a wrong-CN certificate
    When I try to send a syslog event over TLS to that receiver
    Then the TLS handshake should fail with "valid for"

  # Stalling-handshake variant: the TCP accept completes but the
  # server never participates in TLS hello. syslog.New must not
  # wedge — it must return an error within the configured
  # TLSHandshakeTimeout (#552 follow-up; #746).
  Scenario: Syslog New returns bounded under a stalled TLS handshake
    Given bad TLS certs are generated
    And a stalling TCP listener is started
    When I try to construct a syslog output to that stalling listener with TLSHandshakeTimeout 500ms within 2 seconds
    Then the syslog construction should fail with an error containing "tls handshake timeout"

  Scenario: 1000 in-flight events survive a syslog restart without leak
    Given mock syslog metrics are configured
    And the auditor uses core metrics
    And an auditor with syslog output on "tcp" to "localhost:5514" with metrics and max retries 1
    When I audit 1000 uniquely marked events
    And I restart the syslog-ng process
    And I wait for syslog-ng to be ready
    And I close the auditor
    Then the audit metrics submitted count should be 1000

  # --- Failure mode: DNS-unresolvable host (#562) ---
  #
  # The host is in the RFC 6761 reserved `.invalid` TLD; the OS
  # resolver returns NXDOMAIN deterministically without consulting
  # the network. The audit syslog client should not hang and the
  # construction should fail within a bounded window — operators
  # rely on this to surface misconfigured destinations quickly
  # rather than wedging a writer thread.
  Scenario: Syslog rejects a DNS-unresolvable destination promptly
    Given a DNS-unresolvable address is configured
    When I try to send a syslog event over TCP to the unresolvable address within 5 seconds
    Then the result should be a DNS-resolution failure

  # --- Startup connectivity check (#286) ---
  #
  # Syslog has always dialled at construction time; #286 exposes a
  # YAML-controllable opt-out (verify_on_startup) for consistency
  # with the new webhook/loki behaviour. The default (true) preserves
  # the historical fail-fast posture; setting it false defers the
  # dial to the runtime writeLoop, which uses the existing reconnect
  # machinery to retry against a destination that comes up later.

  Scenario: Syslog construction fails fast when the endpoint is unreachable (default)
    # Port 1 is privileged and typically refuses immediately on Linux.
    When I try to create a syslog output on "tcp" to "127.0.0.1:1"
    Then the syslog construction should fail with an error containing "startup verification failed"

  Scenario: Syslog construction with verify_on_startup false succeeds even when unreachable
    When I try to create a syslog output on "tcp" to "127.0.0.1:1" with verify_on_startup false
    Then the syslog construction should succeed
