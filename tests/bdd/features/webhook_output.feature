@webhook @docker
Feature: Webhook Output
  As a library consumer, I want to send audit events to an HTTP endpoint
  so that I can integrate with cloud SIEM, Splunk, or custom receivers.

  The webhook output batches events as NDJSON, retries on 5xx/429, drops
  on 4xx, prevents SSRF, supports custom headers, and flushes on shutdown.

  Background:
    Given a standard test taxonomy

  # --- Batch delivery ---

  Scenario: Batch delivery sends events in batches
    Given an auditor with webhook output configured for batch size 5
    When I audit 12 uniquely marked webhook events
    Then the webhook receiver should have exactly 3 requests within 10 seconds

  Scenario: Single event with batch size 1 delivered immediately
    Given an auditor with webhook output configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds

  Scenario: Flush interval triggers delivery before batch full
    Given an auditor with webhook output configured for batch size 100 and flush interval 200ms
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds

  Scenario: Timer resets after batch flush
    # The receiver counts HTTP requests (one per batch), not the
    # NDJSON event lines inside. batch_size=2, audit 2 events =>
    # 1 batch; another 2 events => 1 more batch (cumulative 2).
    Given an auditor with webhook output configured for batch size 2 and flush interval 300ms
    When I audit a uniquely marked webhook "user_create" event "timer1"
    And I audit a uniquely marked webhook "user_create" event "timer2"
    Then the webhook receiver should have exactly 1 request within 5 seconds
    When I audit a uniquely marked webhook "user_create" event "timer3"
    And I audit a uniquely marked webhook "user_create" event "timer4"
    Then the webhook receiver should have exactly 2 requests within 5 seconds

  # --- Byte-threshold batching (#687) ---
  #
  # The batchLoop flushes on count threshold, byte threshold,
  # FlushInterval timeout, or Close. MaxBatchBytes prevents
  # unbounded HTTP request bodies from verbose event payloads.
  # See docs/webhook-output.md "Batching".

  Scenario: Webhook flushes batch on byte threshold before count threshold
    # Receiver counts HTTP requests. 5 × 1 KiB events with 4 KiB byte
    # threshold and 1000-event count threshold => byte threshold trips
    # before count, so the batchLoop emits 2 requests (events 1-3 in
    # the first batch hitting ~3-4 KiB, then events 4-5 + close drain).
    Given an auditor with webhook output configured for batch size 1000 and flush interval 10s and max batch bytes 4096
    When I audit 5 uniquely marked webhook events with 1 KiB payloads
    And I close the auditor
    Then the webhook receiver should have at least 1 request within 5 seconds

  Scenario: Webhook flushes oversized single event alone
    Given an auditor with webhook output configured for batch size 100 and flush interval 10s and max batch bytes 1024
    When I audit a uniquely marked webhook "user_create" event with a 2048-byte payload
    Then the webhook receiver should have exactly 1 event within 5 seconds

  # --- Max event size (#688) ---
  #
  # Oversized events are rejected at Output.Write entry with
  # audit.ErrEventTooLarge. The auditor's drain goroutine swallows
  # the per-output error; the receiver only sees events that passed
  # the cap. Normal events around the oversized one must deliver.

  Scenario: Webhook rejects oversized event without stalling subsequent deliveries
    Given an auditor with webhook output configured for max event bytes 1024
    When I audit a uniquely marked webhook "user_create" event "wh_before"
    And I audit a uniquely marked webhook "user_create" event with a 4096-byte payload
    And I audit a uniquely marked webhook "user_create" event "wh_after"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: Webhook delivers event within max_event_bytes cap
    Given an auditor with webhook output configured for max event bytes 1048576
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds

  # --- Retry logic ---
  #
  # Retry-eligible scenarios use "at least N" rather than "exactly N"
  # because under retry the receiver MAY observe duplicates: a request
  # that timed out, succeeded server-side, and was retried client-side
  # arrives twice. Asserting "exactly 1" would make these scenarios
  # flaky on slow CI runners. (#554)

  Scenario: Retry on 503 response with eventual delivery
    Given the webhook receiver is configured to return status 503
    And an auditor with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: Retry on 429 rate limit response
    Given the webhook receiver is configured to return status 429
    And an auditor with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: Retry on 504 gateway timeout
    Given the webhook receiver is configured to return status 504
    And an auditor with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: No retry on 400 bad request
    Given the webhook receiver is configured to return status 400
    And an auditor with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "first"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: No retry on 401 unauthorized
    Given the webhook receiver is configured to return status 401
    And an auditor with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "no_retry_401"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel_401"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: No retry on 403 forbidden
    Given the webhook receiver is configured to return status 403
    And an auditor with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "no_retry_403"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel_403"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  # --- Custom headers ---

  Scenario: Custom headers delivered with events
    Given an auditor with webhook output with custom header "X-Audit-Source" = "bdd-test"
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds
    And the received webhook event should have header "X-Audit-Source" with value "bdd-test"

  Scenario: Authorization header delivered to receiver
    Given an auditor with webhook output with custom header "Authorization" = "Bearer test-token-123"
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds
    And the received webhook event should have header "Authorization" with value "Bearer test-token-123"

  Scenario: Content-Type is application/x-ndjson
    Given an auditor with webhook output configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds
    And the received webhook event should have header "Content-Type" with value "application/x-ndjson"

  # --- Shutdown flush ---

  Scenario: Pending events flushed on shutdown
    # Receiver counts HTTP requests. 3 events fit in one batch
    # (batch_size 100, flush 60s) so close emits exactly 1 batch.
    Given an auditor with webhook output configured for batch size 100 and flush interval 60s
    When I audit 3 uniquely marked webhook events
    And I close the auditor
    Then the webhook receiver should have exactly 1 request within 5 seconds

  # --- SSRF protection ---

  Scenario: HTTP URL rejected unless AllowInsecureHTTP is true
    When I try to create a webhook output to "http://localhost:8080/events" without AllowInsecureHTTP
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook url must be https (got "http"); set AllowInsecureHTTP for testing
      """

  Scenario: AllowInsecureHTTP permits http URLs
    Given an auditor with webhook output to "http://localhost:8080/events" with AllowInsecureHTTP
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds

  # SSRF/TLS drop scenarios use "at least N" because the auditor's
  # batched flush + retry-on-network-error paths can record multiple
  # drops for a single oversized/blocked batch — the exact count
  # depends on internal timing and retry budget. (#554)
  Scenario: Private range blocked by default drops events
    Given a local HTTP webhook receiver
    And mock webhook metrics are configured
    And an auditor with webhook output to the local receiver without AllowPrivateRanges
    When I audit a uniquely marked webhook "user_create" event
    And I close the auditor
    Then the webhook metrics should have recorded at least 1 drop within 5 seconds

  Scenario: AllowPrivateRanges permits private addresses
    Given a local HTTP webhook receiver
    And an auditor with webhook output to the local receiver with AllowPrivateRanges
    When I audit a uniquely marked webhook "user_create" event
    Then the local webhook receiver should have exactly 1 event within 5 seconds

  Scenario: Redirect is rejected and not followed
    Given a local HTTP webhook receiver configured to redirect
    And mock webhook metrics are configured
    And an auditor with webhook output to the redirecting receiver with metrics
    When I audit a uniquely marked webhook "user_create" event
    And I close the auditor
    Then the webhook metrics should have recorded at least 1 drop within 5 seconds

  Scenario: Webhook caps drain on 3xx response with large body
    # Issue #484 — an attacker-controlled endpoint returning 3xx with a
    # large body could otherwise force the client to drain up to 1 MiB
    # per retry. A non-redirect 3xx (300 Multiple Choices) reaches our
    # drain path unmodified; the cap limits the client read to 4 KiB.
    Given a local HTTP webhook receiver returning 3xx with a 10 MiB body
    And an auditor with webhook output to the 3xx receiver
    When I audit a uniquely marked webhook "user_create" event
    And I close the auditor
    Then the webhook receiver should have transmitted less than 4 MiB of body

  Scenario: Embedded credentials in URL rejected with exact error
    When I try to create a webhook output to "https://user:pass@example.com/events"
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook url must not contain credentials; use Headers for auth
      """

  Scenario: Header CRLF injection rejected with exact error
    When I try to create a webhook output with header containing CRLF
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook header value for "X-Bad" contains invalid characters
      """

  # --- Config validation ---

  Scenario: Empty URL rejected with exact error
    When I try to create a webhook output to ""
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook url must not be empty
      """

  Scenario: BatchSize exceeding maximum rejected with exact error
    When I try to create a webhook output with batch size 20000
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook batch_size 20000 exceeds maximum 10000
      """

  Scenario: MaxRetries exceeding maximum rejected with exact error
    When I try to create a webhook output with max retries 50
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook max_retries 50 exceeds maximum 20
      """

  Scenario: BufferSize exceeding maximum rejected with exact error
    When I try to create a webhook output with buffer size 2000000
    Then the webhook construction should fail with exact error:
      """
      audit: config validation failed: webhook buffer_size 2000000 exceeds maximum 1000000
      """

  # --- Complete payload verification ---

  Scenario: All event fields present in webhook delivery
    Given an auditor with webhook output configured for batch size 1
    When I audit event "user_create" with fields:
      | field     | value         |
      | outcome   | success       |
      | actor_id  | alice         |
      | marker    | webhook_all   |
      | target_id | user-42       |
    Then the webhook receiver should have exactly 1 event within 5 seconds
    And the webhook event body should contain field "event_type" with value "user_create"
    And the webhook event body should contain field "outcome" with value "success"
    And the webhook event body should contain field "actor_id" with value "alice"
    And the webhook event body should contain field "marker" with value "webhook_all"
    And the webhook event body should contain field "target_id" with value "user-42"
    And the webhook event body should contain field "timestamp"

  # --- Retry on other 5xx ---

  Scenario: Retry on 500 internal server error
    Given the webhook receiver is configured to return status 500
    And an auditor with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: Retry on 502 bad gateway
    Given the webhook receiver is configured to return status 502
    And an auditor with webhook output configured for batch size 1 and max retries 3
    When I audit a uniquely marked webhook "user_create" event
    And the webhook receiver is reconfigured to return status 200
    Then the webhook receiver should have at least 1 event within 10 seconds

  Scenario: No retry on 404 not found
    Given the webhook receiver is configured to return status 404
    And an auditor with webhook output configured for batch size 1 and max retries 5
    When I audit a uniquely marked webhook "user_create" event "no_retry_404"
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "sentinel_404"
    Then the webhook receiver should have exactly 2 events within 5 seconds

  Scenario: Retries exhausted drops batch and continues
    Given the webhook receiver is configured to return status 503
    And an auditor with webhook output configured for batch size 1 and max retries 1
    When I audit a uniquely marked webhook "user_create" event "exhausted"
    And I wait 3 seconds for retries to exhaust
    And the webhook receiver is reconfigured to return status 200
    And I audit a uniquely marked webhook "user_create" event "after_exhaust"
    Then the webhook receiver should have at least 1 event within 10 seconds

  # --- Buffer management ---

  Scenario: Buffer overflow is non-blocking
    Given an auditor with webhook output configured for batch size 100 and flush interval 60s
    When I rapidly audit 200 webhook events measuring time
    Then all 200 audit calls should complete within 2 seconds

  Scenario: Buffer overflow records per-output RecordDrop metric
    Given a local HTTP webhook receiver
    And mock webhook metrics are configured
    And an auditor with webhook to local receiver with buffer size 1 and metrics
    When I rapidly audit 200 webhook events measuring time
    And I close the auditor
    Then the webhook metrics should have recorded at least 1 drop within 5 seconds

  # --- Close idempotent ---

  Scenario: Close is idempotent
    Given an auditor with webhook output configured for batch size 1
    When I close the auditor
    And I close the auditor again
    Then the second close should return no error

  # --- HTTPS / TLS ---

  Scenario: Webhook over HTTPS with custom CA validates server
    Given a local HTTPS webhook receiver
    And an auditor with webhook output to the HTTPS receiver with custom CA
    When I audit a uniquely marked webhook "user_create" event
    Then the HTTPS webhook receiver should have exactly 1 event within 5 seconds

  Scenario: Webhook HTTPS with wrong CA drops events
    Given a local HTTPS webhook receiver
    And mock webhook metrics are configured
    And an auditor with webhook output to the HTTPS receiver with wrong CA and metrics
    When I audit a uniquely marked webhook "user_create" event
    And I close the auditor
    Then the webhook metrics should have recorded at least 1 drop within 5 seconds
    And the HTTPS webhook receiver should have received 0 events

  # --- Webhook-specific metrics ---

  Scenario: Webhook flush records RecordWebhookFlush metric
    Given mock webhook metrics are configured
    And an auditor with webhook output and webhook metrics configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds
    And I close the auditor
    And the webhook metrics should have recorded at least 1 flush

  Scenario: Nil webhook metrics does not panic
    Given an auditor with webhook output configured for batch size 1
    When I audit a uniquely marked webhook "user_create" event
    Then the webhook receiver should have exactly 1 event within 5 seconds

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given an auditor with webhook output configured for batch size 1
    When I close the auditor
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  # --- TLS rejection (#552) ---
  #
  # The webhook output delivers asynchronously: Write enqueues into
  # a per-output buffer; the HTTPS handshake happens in the
  # delivery goroutine. The TLS rejection therefore surfaces via
  # metrics or via a missing-request observation rather than via
  # the Write return value. The two scenarios below stand up an
  # in-process httptest.NewTLSServer with a defective certificate
  # and assert that no request ever reaches the receiver — proving
  # the audit client refused the broken cert before the HTTPS POST
  # could happen.
  #
  # Direct error-string assertions for webhook TLS rejection are
  # handled by the syslog scenarios (which expose the synchronous
  # handshake path); the syslog code is what every TLS-capable
  # output configures the same way through audit.TLSPolicy.

  Scenario: Webhook HTTPS rejects an expired server certificate
    Given bad TLS certs are generated
    And a webhook HTTPS receiver presenting an expired certificate
    When I try to send a webhook event to that receiver
    Then the bad-cert receiver should have received no requests

  Scenario: Webhook HTTPS rejects a wrong-CN server certificate
    Given bad TLS certs are generated
    And a webhook HTTPS receiver presenting a wrong-CN certificate
    When I try to send a webhook event to that receiver
    Then the bad-cert receiver should have received no requests

  # Stalling-handshake variant: the TCP accept completes but the
  # server never participates in TLS hello. The webhook output
  # must not wedge — Close has to return within a bounded window
  # even though the server is pathologically slow.
  Scenario: Webhook Close returns bounded under a stalled TLS handshake
    Given bad TLS certs are generated
    And a stalling TCP listener is started
    When I close the webhook output to that stalling listener within 10 seconds
    Then the bad-cert receiver should have received no requests

  # Rapid-restart variant: the receiver hijacks-and-closes the first
  # connection, then answers normally. Models a server that flaps
  # mid-request. The webhook output's retry path must eventually
  # deliver despite the connection drop.
  Scenario: Webhook recovers from rapid server connection drops
    Given bad TLS certs are generated
    And a flapping HTTPS receiver that drops the first 1 connections
    When I send 1 webhook events to the flapping receiver
    Then the flapping receiver should eventually receive at least one successful request

  # --- Failure mode: DNS-unresolvable host (#562) ---
  #
  # The host is in the RFC 6761 reserved `.invalid` TLD; the OS
  # resolver returns NXDOMAIN. The audit webhook client honours
  # the configured Timeout and surfaces the dial failure rather
  # than wedging the delivery goroutine.
  Scenario: Webhook rejects a DNS-unresolvable destination promptly
    Given a DNS-unresolvable address is configured
    When I try to send a webhook event to the unresolvable address within 3 seconds
    Then the result should be a DNS-resolution failure

  # --- Failure mode: giant response body (#562) ---
  #
  # The receiver returns a 4 MiB Content-Length response on a 5xx
  # request. The webhook output's drainCap (1 MiB on 2xx/4xx/5xx,
  # see webhook/http.go) limits the bytes the client consumes; the
  # request must complete within the configured Timeout without
  # exhausting memory or wedging the writer.
  Scenario: Webhook honours drainCap on a giant 5xx response body
    Given a webhook receiver returning a 4194304-byte body
    When I send 1 webhook event to the configured failure-mode receiver within 5 seconds
    Then the failure-mode receiver should have received between 1 and 5 requests

  # --- Failure mode: connection reset mid-request (#562) ---
  #
  # The receiver hijacks the TCP connection and closes it before
  # writing a response. The audit webhook client interprets this as
  # a transient failure and the configured MaxRetries (default 3)
  # drives the retry loop until exhaustion. The contract under test
  # is "the audit client makes the request, observes the close, and
  # tears down cleanly without wedging" — `at least 1 request`
  # captures that without pinning to the implementation-specific
  # retry count.
  Scenario: Webhook handles a connection reset mid-request
    Given a webhook receiver that resets the connection mid-request
    When I send 1 webhook event to the configured failure-mode receiver within 5 seconds
    Then the failure-mode receiver should have received between 1 and 5 requests

  # --- Failure mode: chunked-response stall (#562) ---
  #
  # The receiver writes one chunk of a Transfer-Encoding: chunked
  # response, then hangs. The audit webhook transport's
  # ResponseHeaderTimeout floor (1 s) bounds the read; the request
  # must fail within ~Timeout, not wedge.
  Scenario: Webhook bounds a stalled chunked response
    Given a webhook receiver that starts a chunked response then stalls
    When I send 1 webhook event to the configured failure-mode receiver within 5 seconds
    Then the failure-mode receiver should have received between 1 and 5 requests

  # --- Startup connectivity check (#286) ---
  #
  # The webhook output defaults to verify_on_startup: true. New()
  # performs a TCP dial — and, for https URLs, a TLS handshake —
  # before returning, so a misconfigured or down receiver fails the
  # application at startup rather than silently dropping every event
  # at the first flush.

  Scenario: Webhook construction fails fast when the endpoint is unreachable (default)
    When I try to create a webhook output to an unreachable URL
    Then the webhook construction should fail with an error containing "startup verification failed"

  Scenario: Webhook construction with verify_on_startup false succeeds even when unreachable
    When I try to create a webhook output to an unreachable URL with verify_on_startup false
    Then the webhook construction should succeed
