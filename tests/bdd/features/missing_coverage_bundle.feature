@core @missing-coverage
Feature: Missing BDD Coverage Bundle (#561)
  Bundles BDD scenarios for documented behaviours that previously had
  zero or insufficient BDD coverage. Each scenario block below pins
  one of the eight master-tracker items F-21 through F-28.

  Background:
    Given a standard test taxonomy

  # ---------------------------------------------------------------
  # F-21 — EventHandle.AuditEvent (event.go:365)
  # ---------------------------------------------------------------

  Scenario: EventHandle.AuditEvent delivers an event using the handle's bound auditor
    Given an auditor with synchronous delivery and a recording mock output
    And I get a handle for event type "user_create"
    When I call EventHandle.AuditEvent with a NewEvent for "user_create"
    Then the audit call should return no error
    And the recording output should have received exactly 1 events

  Scenario: EventHandle.AuditEvent on a closed auditor returns ErrClosed
    Given an auditor with synchronous delivery and a recording mock output
    And I get a handle for event type "user_create"
    When I close the auditor
    And I call EventHandle.AuditEvent with a NewEvent for "user_create"
    Then the audit call should return an error wrapping "ErrClosed"
    And the recording output should have received exactly 0 events

  # ---------------------------------------------------------------
  # F-22 — audittest.WithSync, WithVerbose, RequireEvents
  # ---------------------------------------------------------------

  Scenario: audittest WithSync delivers events synchronously without WaitForN
    Given an audittest auditor created with WithSync
    When I audit event "user_create" with required fields via the audittest auditor
    Then the audittest recorder should contain exactly 1 "user_create" event with no Close call

  Scenario: audittest RequireEvents returns recorded events when count matches
    Given an audittest auditor created via NewQuick with a standard taxonomy
    When I audit event "user_create" with required fields via the audittest auditor
    And I audit event "user_create" with required fields via the audittest auditor
    Then RequireEvents 2 returns the recorded events

  Scenario: audittest RequireEvents fails the test bench when count mismatches
    Given an audittest auditor created via NewQuick with a standard taxonomy
    When I audit event "user_create" with required fields via the audittest auditor
    And I call RequireEvents with n=5 expecting failure
    Then the audittest test bench should have been failed

  Scenario: audittest WithVerbose enables diagnostic logging output
    Given an audittest auditor created with WithVerbose and a captured logger
    When I close the audittest auditor
    Then the captured diagnostic log should contain "audit:" lifecycle messages

  # ---------------------------------------------------------------
  # F-23 — Webhook/Loki buffer_size YAML
  # ---------------------------------------------------------------

  Scenario: Webhook output accepts buffer_size in YAML
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        wh:
          type: webhook
          webhook:
            url: http://example.invalid/audit
            allow_insecure_http: true
            verify_on_startup: false
            buffer_size: 250
      """
    When I load the outputs config
    Then the config should load successfully

  Scenario: Webhook output buffer_size defaults when omitted
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        wh:
          type: webhook
          webhook:
            url: http://example.invalid/audit
            allow_insecure_http: true
            verify_on_startup: false
      """
    When I load the outputs config
    Then the config should load successfully

  Scenario: Webhook output buffer_size exceeding maximum is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        wh:
          type: webhook
          webhook:
            url: http://example.invalid/audit
            allow_insecure_http: true
            verify_on_startup: false
            buffer_size: 2000000
      """
    When I load the outputs config
    Then the config load should fail with an error containing "buffer_size"

  Scenario: Loki output accepts buffer_size in YAML
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        lk:
          type: loki
          loki:
            url: http://example.invalid/loki/api/v1/push
            allow_insecure_http: true
            verify_on_startup: false
            buffer_size: 500
      """
    When I load the outputs config
    Then the config should load successfully

  Scenario: Loki output buffer_size defaults when omitted
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        lk:
          type: loki
          loki:
            url: http://example.invalid/loki/api/v1/push
            allow_insecure_http: true
            verify_on_startup: false
      """
    When I load the outputs config
    Then the config should load successfully

  Scenario: Loki output buffer_size exceeding maximum is rejected
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      outputs:
        lk:
          type: loki
          loki:
            url: http://example.invalid/loki/api/v1/push
            allow_insecure_http: true
            verify_on_startup: false
            buffer_size: 2000000
      """
    When I load the outputs config
    Then the config load should fail with an error containing "buffer_size"

  # ---------------------------------------------------------------
  # F-24 — drain_timeout deprecation error (outputconfig/auditor_config.go)
  # ---------------------------------------------------------------

  Scenario: Deprecated auditor.drain_timeout field is rejected with a rename hint
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      auditor:
        drain_timeout: 5s
      outputs:
        wh:
          type: webhook
          webhook:
            url: http://example.invalid/audit
            allow_insecure_http: true
            verify_on_startup: false
      """
    When I load the outputs config
    Then the config load should fail with an error containing "drain_timeout"
    And the config load error should also contain "shutdown_timeout"

  Scenario: shutdown_timeout (replacement for drain_timeout) is accepted
    Given the following outputs YAML:
      """
      version: 1
      app_name: test-app
      host: test-host
      auditor:
        shutdown_timeout: 5s
      outputs:
        wh:
          type: webhook
          webhook:
            url: http://example.invalid/audit
            allow_insecure_http: true
            verify_on_startup: false
      """
    When I load the outputs config
    Then the config should load successfully

  # ---------------------------------------------------------------
  # F-25 — ValidationMode warn delivers (vs strict rejects)
  # ---------------------------------------------------------------

  Scenario: ValidationMode warn delivers an event with an unknown field
    Given an auditor with synchronous delivery, a recording output, and ValidationMode warn
    When I audit event "user_create" with required fields and an unknown field "extra_field"
    Then the audit call should return no error
    And the recording output should have received exactly 1 events

  Scenario: ValidationMode strict rejects an event with an unknown field
    Given an auditor with synchronous delivery, a recording output, and ValidationMode strict
    When I try to audit event "user_create" with required fields and an unknown field "extra_field"
    Then the audit call should return an error wrapping "ErrValidation"
    And the recording output should have received exactly 0 events

  Scenario: ValidationMode warn still rejects events missing a required field
    Given an auditor with synchronous delivery, a recording output, and ValidationMode warn
    When I try to audit event "user_create" with empty fields
    Then the audit call should return an error wrapping "ErrValidation"
    And the recording output should have received exactly 0 events

  # ---------------------------------------------------------------
  # F-26 — CEF formatter OmitEmpty (parity with JSON)
  # ---------------------------------------------------------------

  Scenario: CEF formatter with OmitEmpty true skips empty-string fields
    Given an auditor with file output and a CEF formatter with OmitEmpty true
    When I audit event "user_create" with an empty optional field "reason"
    And I close the auditor
    Then the file should not contain CEF extension key "reason"

  Scenario: CEF formatter with OmitEmpty false includes empty-string fields
    Given an auditor with file output and a CEF formatter with OmitEmpty false
    When I audit event "user_create" with an empty optional field "reason"
    And I close the auditor
    Then the file should contain CEF extension key "reason"

  # ---------------------------------------------------------------
  # F-27 — DestinationKey duplicate detection (cross-type and same-type)
  # ---------------------------------------------------------------

  Scenario: Two outputs returning the same DestinationKey are rejected at construction
    Given two outputs with destination keys "https://example.invalid/audit" and "https://example.invalid/audit"
    When I construct an auditor with those two outputs via WithNamedOutput
    Then the construction should fail with an error wrapping "ErrDuplicateDestination"

  Scenario: Two outputs with empty DestinationKey opt out of duplicate detection
    Given two outputs with destination keys "" and ""
    When I construct an auditor with those two outputs via WithNamedOutput
    Then the construction should succeed

  Scenario: Two outputs with distinct DestinationKey values are accepted
    Given two outputs with destination keys "https://a.example.invalid/audit" and "https://b.example.invalid/audit"
    When I construct an auditor with those two outputs via WithNamedOutput
    Then the construction should succeed

  # ---------------------------------------------------------------
  # F-28 — Output.Name() empty-string policy (rejected at construction)
  # ---------------------------------------------------------------

  Scenario: WithNamedOutput rejects an output whose Name returns the empty string
    Given an output whose Name returns the empty string
    When I construct an auditor with that output via WithNamedOutput
    Then the construction should fail with a message containing "Name() must not return an empty string"

  Scenario: WithOutputs rejects an output whose Name returns the empty string
    Given an output whose Name returns the empty string
    When I construct an auditor with that output via WithOutputs
    Then the construction should fail with a message containing "Name() must not return an empty string"
