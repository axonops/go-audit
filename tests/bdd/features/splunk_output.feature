@splunk @docker
Feature: Splunk HEC Output
  As a library consumer, I want to send audit events to Splunk via HEC
  so that compliance evidence lands in our SIEM with full delivery
  guarantees and the established Splunk wire-format conventions.

  The Splunk output batches events into the /event JSON envelope or
  the /raw NDJSON format, gzips by default, retries 5xx/429 with
  exponential backoff, drops on 4xx with operator alerts on stop-
  codes (1/2/3/4/7/22), and never logs the HEC token.

  Background:
    Given a standard test taxonomy
    And a Splunk test container with HEC enabled

  # --- Envelope format and wire contract ---

  Scenario: The /event endpoint receives the JSON envelope
    Given an auditor with splunk output on the /event endpoint
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 envelope within 10 seconds
    And the received envelope should have field "sourcetype" = "axonops:audit"
    And the received envelope should have field "source" = "axonops-audit"

  Scenario: Concatenated JSON batch is parseable as a stream
    Given an auditor with splunk output configured for batch size 5
    When I audit 5 uniquely marked splunk "user_create" events
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request body should stream-decode to exactly 5 JSON objects

  Scenario: The /raw endpoint receives NDJSON
    Given an auditor with splunk output on the /raw endpoint
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request URL should contain query "sourcetype=axonops:audit"
    And the request URL should contain query "index="

  # --- Compression ---

  Scenario: gzip compression is on by default
    Given an auditor with splunk output and default gzip
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request header "Content-Encoding" should equal "gzip"

  # --- Authentication ---

  Scenario: The Splunk auth scheme is "Splunk" not "Bearer"
    Given an auditor with splunk output
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request header "Authorization" should start with "Splunk "

  Scenario: User-Agent header is mandatory for keep-alive
    Given an auditor with splunk output
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request header "User-Agent" should start with "audit-splunk/"

  # --- HEC error-code semantics ---

  Scenario Outline: HEC retryable code <code> retries with backoff
    Given an auditor with splunk output where the HEC will return code <code> twice then succeed
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 3 requests within 15 seconds
    And the elapsed time should be at least 500 ms

    Examples:
      | code |
      | 9    |
      | 8    |

  Scenario Outline: HEC stop-and-alert code <code> stops the output
    Given an auditor with splunk output where the HEC will return code <code>
    When I audit a uniquely marked splunk "user_create" event
    And I wait up to 3 seconds for the output to enter the stop state
    Then the next write should return ErrOutputClosed

    Examples:
      | code |
      | 4    |
      | 7    |

  Scenario: HEC code 24 surfaces as a capacity-warning metric, not an error
    Given an auditor with splunk output where the HEC will return code 24
    When I audit a uniquely marked splunk "user_create" event
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the output's capacity-warning metric should be at least 1
    And the output's drop metric should be 0

  # --- Payload limits ---

  Scenario: HTTP 413 drops the batch and increments the drop metric
    Given an auditor with splunk output where the HEC will return HTTP 413
    When I audit a uniquely marked splunk "user_create" event
    Then the output's drop metric should be at least 1
    And the splunk receiver should have received exactly 1 request within 10 seconds

  Scenario: A single event over MaxEventBytes is dropped with a metric
    Given an auditor with splunk output and MaxEventBytes 1024
    When I audit an oversized splunk "user_create" event of 2048 bytes
    Then the Write call should return ErrEventTooLarge
    And the splunk receiver should have received exactly 0 requests within 2 seconds

  # --- Network safety ---

  Scenario: HTTPS is required unless AllowInsecureHTTP is true
    When I construct a splunk output with URL "http://splunk.test:8088" and AllowInsecureHTTP false
    Then construction should fail with ErrConfigInvalid

  Scenario: Token is never logged or surfaced in errors
    Given an auditor with splunk output and token "super-secret-token-abc"
    When I audit a uniquely marked splunk "user_create" event
    And I read the diagnostic log buffer
    Then the diagnostic log should not contain "super-secret-token-abc"
    And the diagnostic log should contain the string "audit/splunk"

  Scenario: Close flushes the remaining batch before returning
    Given an auditor with splunk output configured for batch size 100 and flush interval 30s
    When I audit 5 uniquely marked splunk "user_create" events
    And I close the auditor
    Then the splunk receiver should have received exactly 1 request within 10 seconds
    And the request body should stream-decode to exactly 5 JSON objects

  # --- Splunk-Cloud-stack rejection (PR 1 only — PR 2 enables it) ---

  Scenario: splunkcloud:// URL scheme rejected in PR 1
    When I construct a splunk output with URL "splunkcloud://acme-prod"
    Then construction should fail with ErrPR1NotImplemented
