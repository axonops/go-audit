@core @config
Feature: YAML Output Configuration
  As a library consumer, I want to configure audit outputs via a YAML
  file so that I can wire outputs without writing Go code.

  Scenario: Load minimal stdout-only config from YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        console:
          type: stdout
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I close the auditor
    Then the audit call should have succeeded
    And the captured output should contain "user_create"
    And the captured output should contain "alice"
    And the loaded auditor metadata should have app_name "test"

  Scenario: Load file output with routing from YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        all_events:
          type: file
          file:
            path: "${AUDIT_BDD_DIR}/all.log"
        write_only:
          type: file
          file:
            path: "${AUDIT_BDD_DIR}/writes.log"
          route:
            include_categories:
              write: {}
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    And I audit event "auth_failure" with fields:
      | field   | value   |
      | outcome | failure |
    And I close the auditor
    Then the file "all.log" should contain "user_create"
    And the file "all.log" should contain "auth_failure"
    And the file "writes.log" should contain "user_create"
    And the file "writes.log" should not contain "auth_failure"

  Scenario: Unknown output type returns helpful error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        broken:
          type: kafka
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "unknown output type"
    And the config load error should contain "add import"

  Scenario: Missing environment variable returns clear error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        bad:
          type: file
          file:
            path: "${TOTALLY_UNDEFINED_BDD_VAR}/audit.log"
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "TOTALLY_UNDEFINED_BDD_VAR"

  Scenario: envsubst preserves string semantics for YAML magic values
    # #487 — env-var expanded values must flow to factories as the
    # exact string literal the env var contained. A plain yaml.Marshal
    # of the post-expansion map would emit ".inf", ".NaN", and (under
    # YAML 1.1 parsers) "on"/"off" unquoted, and the downstream parser
    # would re-read them as float / bool — silently turning a string
    # config value into the wrong Go type. The safeMarshal helper in
    # outputconfig/safe_marshal.go defends against this.
    Given a test taxonomy
    And the environment variable "BDD_MAGIC_ON" is set to "on"
    And the environment variable "BDD_MAGIC_OFF" is set to "off"
    And the environment variable "BDD_MAGIC_YES" is set to "yes"
    And the environment variable "BDD_MAGIC_NO" is set to "no"
    And the environment variable "BDD_MAGIC_TRUE" is set to "true"
    And the environment variable "BDD_MAGIC_FALSE" is set to "false"
    And the environment variable "BDD_MAGIC_NULL" is set to "null"
    And the environment variable "BDD_MAGIC_TILDE" is set to "~"
    And the environment variable "BDD_MAGIC_INF" is set to ".inf"
    And the environment variable "BDD_MAGIC_NAN" is set to ".NaN"
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        hook:
          type: webhook
          webhook:
            url: "https://example.com/e"
            allow_private_ranges: true
            headers:
              X-Magic-On: ${BDD_MAGIC_ON}
              X-Magic-Off: ${BDD_MAGIC_OFF}
              X-Magic-Yes: ${BDD_MAGIC_YES}
              X-Magic-No: ${BDD_MAGIC_NO}
              X-Magic-True: ${BDD_MAGIC_TRUE}
              X-Magic-False: ${BDD_MAGIC_FALSE}
              X-Magic-Null: ${BDD_MAGIC_NULL}
              X-Magic-Tilde: ${BDD_MAGIC_TILDE}
              X-Magic-Inf: ${BDD_MAGIC_INF}
              X-Magic-Nan: ${BDD_MAGIC_NAN}
              X-Magic-Empty: "${UNSET_BDD_MAGIC:-}"
      """
    When I create an auditor from the YAML config
    And I close the auditor
    Then the config load should succeed
    And the captured webhook raw config should have header "X-Magic-On" with value "on"
    And the captured webhook raw config should have header "X-Magic-Off" with value "off"
    And the captured webhook raw config should have header "X-Magic-Yes" with value "yes"
    And the captured webhook raw config should have header "X-Magic-No" with value "no"
    And the captured webhook raw config should have header "X-Magic-True" with value "true"
    And the captured webhook raw config should have header "X-Magic-False" with value "false"
    And the captured webhook raw config should have header "X-Magic-Null" with value "null"
    And the captured webhook raw config should have header "X-Magic-Tilde" with value "~"
    And the captured webhook raw config should have header "X-Magic-Inf" with value ".inf"
    And the captured webhook raw config should have header "X-Magic-Nan" with value ".NaN"
    And the captured webhook raw config should have header "X-Magic-Empty" with value ""

  # --- Framework fields in output config (#237) ---

  Scenario: Missing app_name in output config YAML is rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      host: test
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "app_name is required"

  Scenario: Missing host in output config YAML is rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "host is required"

  Scenario: timezone optional in output config YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        console:
          type: stdout
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded
    And the loaded auditor metadata should have timezone ""

  Scenario: timezone present in output config YAML
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      timezone: UTC
      outputs:
        console:
          type: stdout
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded
    And the loaded auditor metadata should have timezone "UTC"

  # --- standard_fields in output config (#237) ---

  Scenario: standard_fields with valid reserved field accepted
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        source_ip: "10.0.0.1"
      outputs:
        console:
          type: stdout
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded
    And the captured output should contain "10.0.0.1"
    And the captured output should contain "source_ip"

  Scenario: standard_fields with unknown field rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        bogus_field: "value"
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "unknown field"

  Scenario: standard_fields with empty value rejected
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      standard_fields:
        source_ip: ""
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "non-empty"

  # --- Loki formatter validation (#304) ---

  Scenario: Loki output rejects CEF formatter
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        loki_out:
          type: loki
          formatter:
            type: cef
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "loki does not support custom formatters"

  Scenario: Loki output rejects CloudEvents formatter
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        loki_out:
          type: loki
          formatter:
            type: cloudevents
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "loki does not support custom formatters"

  Scenario: Loki output accepts explicit JSON formatter
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      outputs:
        loki_out:
          type: loki
          formatter:
            type: json
      """
    When I try to create an auditor from the YAML config
    Then the config load should succeed
    And the loki output formatter should be JSON

  Scenario: default_formatter key rejected with error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      default_formatter:
        type: cef
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "default_formatter has been removed"
    And the config load error should contain "set formatter on each output individually"

  # --- Root-level tls_policy removed (#476) ---

  Scenario: Root-level tls_policy rejected with migration hint
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      tls_policy:
        allow_tls12: true
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "tls_policy is no longer a top-level key"
    And the config load error should contain "syslog, webhook, loki"
    And the config load error should contain "vault, openbao"
    And the config load error should contain "#476"

  # --- YAML shape errors (#541) ---

  Scenario: auditor declared as scalar rather than mapping returns helpful error
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: test
      host: test
      auditor: "not a mapping"
      outputs:
        console:
          type: stdout
      """
    When I try to create an auditor from the YAML config
    Then the config load should fail with an error containing "auditor"
    And the config load error should contain "expected YAML mapping"
    And the config load error should contain "got string"
    And the config load error should contain "queue_size"

  # --- Syslog app_name injection (#237) ---

  Scenario: Global app_name injected into syslog output config
    Given a test taxonomy
    And the following output configuration YAML:
      """
      version: 1
      app_name: injected-app
      host: test
      outputs:
        console:
          type: stdout
      """
    When I create an auditor from the YAML config
    And I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
    Then the audit call should have succeeded
    And the loaded auditor metadata should have app_name "injected-app"
    And the captured output should contain "injected-app"

