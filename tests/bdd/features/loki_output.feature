@loki @docker
Feature: Loki Output
  As a library consumer, I want to send audit events to Grafana Loki
  so that I can query audit trails using LogQL and integrate with
  Grafana dashboards.

  The Loki output batches events as JSON push requests, groups by
  stream labels, supports gzip compression, retries on 429/5xx,
  drops on 4xx, prevents SSRF, supports multi-tenancy via
  X-Scope-OrgID, and flushes on shutdown.

  Background:
    Given a standard test taxonomy

  # --- Basic delivery with complete payload verification ---

  Scenario: Single event delivered to Loki with complete payload
    Given an auditor with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Custom field values preserved in Loki log line
    Given an auditor with loki output
    When I audit a uniquely marked "user_create" event with field "actor_id" = "alice"
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | alice        |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Multiple events all delivered with complete payloads
    Given an auditor with loki output with batch size 5
    When I audit 10 loki events with a shared marker
    Then the loki server should have at least 10 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Stream labels with complete payload verification ---

  Scenario: All dynamic labels present on Loki stream with complete payload
    Given an auditor with loki output
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "event_type" with value "user_create"
    And the loki stream should have label "app_name" with value "bdd-audit"
    And the loki stream should have label "host" with value "bdd-host"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Static labels present on stream with complete payload
    Given an auditor with loki output with static label "environment" = "testing"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should have label "environment" with value "testing"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Excluded dynamic label absent from stream with payload intact
    Given an auditor with loki output excluding dynamic label "severity"
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki stream should not have label "severity"
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Different event types in separate streams with payload verification
    Given an auditor with loki output with batch size 10
    When I audit a uniquely marked "user_create" event
    And I audit a uniquely marked "auth_failure" event
    Then the loki server should have events in stream "user_create" within 15 seconds
    And the loki server should have events in stream "auth_failure" within 15 seconds

  # --- Batch delivery with complete payload verification ---

  Scenario: Batch flushes on count threshold with complete payload
    Given an auditor with loki output with batch size 5 and flush interval 60s
    When I audit 5 loki events with a shared marker
    Then the loki server should have at least 5 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Batch flushes on timer with complete payload
    Given an auditor with loki output with batch size 1000 and flush interval 500ms
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Shutdown flushes pending events with complete payload
    Given an auditor with loki output with batch size 1000 and flush interval 60s
    When I audit 3 loki events with a shared marker
    And I close the auditor
    Then the loki server should have at least 3 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Gzip compression with complete payload verification ---

  Scenario: Gzip-compressed events preserve complete payload in Loki
    Given an auditor with loki output with gzip enabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  Scenario: Uncompressed events preserve complete payload in Loki
    Given an auditor with loki output with gzip disabled
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Multi-tenancy with payload verification ---

  Scenario: Events delivered to specific tenant with complete payload
    Given an auditor with loki output to tenant "tenant-alpha"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-alpha" should contain the marker within 15 seconds

  Scenario: Tenant isolation prevents cross-tenant visibility
    Given an auditor with loki output to tenant "tenant-iso-a"
    When I audit a uniquely marked "user_create" event
    Then the loki server for tenant "tenant-iso-a" should contain the marker within 15 seconds
    And the loki server for tenant "tenant-iso-b" should not contain the marker within 5 seconds

  # --- Large batch delivery ---

  Scenario: All events from large batch delivered with complete payloads
    Given an auditor with loki output with batch size 10
    When I audit 10 loki events with a shared marker
    Then the loki server should have at least 10 events within 15 seconds
    And the loki event payload should contain:
      | field          | value        |
      | event_type     | user_create  |
      | outcome        | success      |
      | actor_id       | test-actor   |
      | app_name       | bdd-audit    |
      | host           | bdd-host     |
      | event_category | write        |

  # --- Lifecycle ---

  Scenario: Close is idempotent
    Given an auditor with loki output
    When I close the auditor
    And I close the auditor again
    Then no error should occur

  Scenario: Write after close returns error
    Given an auditor with loki output
    When I close the auditor
    And I try to audit a "user_create" event
    Then the audit call should return an error wrapping "ErrClosed"

  # --- Retry logic (httptest.Server, no Docker Loki) ---

  Scenario: Retry on 503 with eventual delivery
    Given a local Loki receiver returning status 503
    And mock loki metrics are configured
    And an auditor with loki output to the local receiver with max retries 3
    When I audit a uniquely marked "user_create" event
    And the local Loki receiver is reconfigured to return status 204
    Then the local Loki receiver should have at least 1 push within 10 seconds
    And the loki metrics should have recorded at least 1 flush

  Scenario: Retry on 429 rate limit with eventual delivery
    Given a local Loki receiver returning status 429
    And mock loki metrics are configured
    And an auditor with loki output to the local receiver with max retries 3
    When I audit a uniquely marked "user_create" event
    And the local Loki receiver is reconfigured to return status 204
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: No retry on 400 client error
    Given a local Loki receiver returning status 400
    And mock loki metrics are configured
    And an auditor with loki output to the local receiver with max retries 5
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds
    And the local Loki receiver should have received at most 1 push

  Scenario: No retry on 401 unauthorized
    Given a local Loki receiver returning status 401
    And mock loki metrics are configured
    And an auditor with loki output to the local receiver with max retries 5
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds
    And the local Loki receiver should have received at most 1 push

  Scenario: Retries exhausted drops batch
    Given a local Loki receiver returning status 503
    And mock loki metrics are configured
    And an auditor with loki output to the local receiver with max retries 1
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  # --- Loki unavailable ---

  Scenario: Loki unreachable drops events and records metrics
    Given mock loki metrics are configured
    And an auditor with loki output to unreachable server with metrics
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  # --- SSRF protection (httptest.Server, no Docker Loki) ---

  Scenario: Private range blocked by default drops events
    Given a local Loki receiver accepting pushes
    And mock loki metrics are configured
    And an auditor with loki output to the local Loki receiver without AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  Scenario: AllowPrivateRanges permits private addresses
    Given a local Loki receiver accepting pushes
    And an auditor with loki output to the local Loki receiver with AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: Redirect is rejected and not followed
    Given a local Loki receiver configured to redirect
    And mock loki metrics are configured
    And an auditor with loki output to the redirecting Loki receiver with metrics
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 drop within 5 seconds

  Scenario: Loki caps drain on 3xx response with large body
    # Issue #484 — an attacker-controlled endpoint returning 3xx with a
    # large body could otherwise force the client to drain up to 64 KiB
    # per retry. A non-redirect 3xx (300 Multiple Choices) reaches our
    # drain path unmodified; the cap limits the client read to 4 KiB.
    Given a local Loki receiver returning 3xx with a 10 MiB body
    And an auditor with loki output to the 3xx Loki receiver
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki receiver should have transmitted less than 4 MiB of body

  # --- Metrics (httptest.Server) ---

  Scenario: Successful delivery records flush metric
    Given a local Loki receiver accepting pushes
    And mock loki metrics are configured
    And an auditor with loki output to the local Loki receiver with metrics
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds
    And the loki metrics should have recorded at least 1 flush
    And the loki metrics should have recorded 0 drops

  Scenario: Nil loki metrics does not panic
    Given a local Loki receiver accepting pushes
    And an auditor with loki output to the local Loki receiver with AllowPrivateRanges
    When I audit a uniquely marked "user_create" event
    Then the local Loki receiver should have at least 1 push within 10 seconds

  Scenario: Delivery failure records RecordError metric
    Given a local Loki receiver returning status 400
    And mock loki metrics are configured
    And an auditor with loki output to the local Loki receiver with metrics and max retries 0
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the loki metrics should have recorded at least 1 error within 5 seconds

  # --- Max event size (#688) ---
  #
  # Oversized events are rejected at Output.Write entry with
  # audit.ErrEventTooLarge. The auditor's drain goroutine swallows
  # the per-output error; from the consumer's view, Audit returns
  # nil but the event does not reach the receiver. Normal events
  # before and after the oversized one must continue to deliver.

  Scenario: Loki rejects oversized event without stalling subsequent deliveries
    Given an auditor with loki output with max event bytes 1024
    When I audit a uniquely marked "user_create" event with a 4096-byte payload
    And I audit 2 loki events with a shared marker
    And I close the auditor
    Then the loki server should have at least 2 events within 10 seconds

  Scenario: Loki delivers event within max_event_bytes cap
    Given an auditor with loki output with max event bytes 1048576
    When I audit a uniquely marked "user_create" event
    Then the loki server should contain the marker within 15 seconds

  # --- TLS rejection (#552) ---
  #
  # See the matching block in webhook_output.feature for the
  # rationale: HTTPS delivery is async, so the TLS rejection is
  # observed by asserting the bad-cert receiver never sees the
  # request. Synchronous error-string coverage lives in the
  # syslog_output.feature TLS rejection scenarios, which exercise
  # the same audit.TLSPolicy primitive.

  Scenario: Loki HTTPS rejects an expired server certificate
    Given bad TLS certs are generated
    And a loki HTTPS receiver presenting an expired certificate
    When I try to send a loki event to that receiver
    Then the bad-cert receiver should have received no requests

  Scenario: Loki HTTPS rejects a wrong-CN server certificate
    Given bad TLS certs are generated
    And a loki HTTPS receiver presenting a wrong-CN certificate
    When I try to send a loki event to that receiver
    Then the bad-cert receiver should have received no requests

  # Stalling-handshake variant: the TCP accept completes but the
  # server never participates in TLS hello. The loki output must
  # not wedge — Close has to return within a bounded window even
  # though the server is pathologically slow.
  Scenario: Loki Close returns bounded under a stalled TLS handshake
    Given bad TLS certs are generated
    And a stalling TCP listener is started
    When I close the loki output to that stalling listener within 10 seconds
    Then the bad-cert receiver should have received no requests

  # Rapid-restart variant: the receiver hijacks-and-closes the first
  # connection, then answers normally. Models a server that flaps
  # mid-request. The loki output's retry path must eventually
  # deliver despite the connection drop.
  Scenario: Loki recovers from rapid server connection drops
    Given bad TLS certs are generated
    And a flapping HTTPS receiver that drops the first 1 connections
    When I send 1 loki events to the flapping receiver
    Then the flapping receiver should eventually receive at least one successful request

  # --- Failure mode: DNS-unresolvable host (#562) ---
  #
  # The host is in the RFC 6761 reserved `.invalid` TLD; the OS
  # resolver returns NXDOMAIN. The audit loki client honours the
  # configured Timeout and surfaces the dial failure rather than
  # wedging the delivery goroutine.
  Scenario: Loki rejects a DNS-unresolvable destination promptly
    Given a DNS-unresolvable address is configured
    When I try to send a loki event to the unresolvable address within 3 seconds
    Then the result should be a DNS-resolution failure

  # --- Failure mode: chunked-response stall (#562) ---
  #
  # The receiver writes one chunk of a Transfer-Encoding: chunked
  # response, then hangs. The audit loki transport's
  # ResponseHeaderTimeout floor (1 s) bounds the read; the request
  # must fail within ~Timeout, not wedge.
  Scenario: Loki bounds a stalled chunked response
    Given a loki receiver that starts a chunked response then stalls
    When I send 1 loki event with tenant "test-tenant" to the configured failure-mode receiver within 5 seconds
    Then the failure-mode receiver should have received between 1 and 5 requests

  # --- Failure mode: tenant-not-found (#562) ---
  #
  # The receiver returns 404 with a Loki-shaped error body. The
  # audit loki client records the failure as a non-retryable error
  # and does not retry. The X-Scope-OrgID header is what an
  # upstream Loki uses to decide tenant existence; we configure
  # TenantID so the client emits the header.
  Scenario: Loki handles tenant-not-found 404 without retry storms
    Given a loki receiver that returns 404 tenant-not-found
    When I send 1 loki event with tenant "nonexistent-tenant" to the configured failure-mode receiver within 3 seconds
    Then the failure-mode receiver should have received between 1 and 5 requests

  # --- Startup connectivity check (#286) ---
  #
  # The loki output defaults to verify_on_startup: true. New()
  # performs a TCP dial — and, for https URLs, a TLS handshake —
  # before returning, so a misconfigured or down Loki endpoint fails
  # the application at startup rather than silently dropping every
  # event at the first push.

  Scenario: Loki construction fails fast when the endpoint is unreachable (default)
    When I try to create a loki output to an unreachable URL
    Then the loki construction should fail with an error containing "startup verification failed"

  Scenario: Loki construction with verify_on_startup false succeeds even when unreachable
    When I try to create a loki output to an unreachable URL with verify_on_startup false
    Then the loki construction should succeed
