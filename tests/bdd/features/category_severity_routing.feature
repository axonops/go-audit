@core @category-severity-routing
Feature: Per-category severity thresholds in event routes (#193)
  As a library consumer, I want each included category to carry its
  own severity bound, so that I can express "all read events AND
  only critical security events" in a single route without splitting
  it across multiple outputs.

  A per-category SeverityRange is authoritative for category matches.
  Route-level MinSeverity/MaxSeverity apply only to IncludeEventTypes
  matches and to the severity-only catch-all (the PagerDuty pattern).

  Background:
    Given a severity routing taxonomy

  # ---------------------------------------------------------------------------
  # Mode A — category-only (nil filter, all severities)
  # ---------------------------------------------------------------------------

  Scenario: Category-only filter delivers all severities for that category
    Given an auditor with stdout output routed to include only "security"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Mode B — per-category severity (the new capability)
  # ---------------------------------------------------------------------------

  Scenario: Per-category min_severity rejects events below the threshold
    Given an auditor with stdout output routed to include only "security" with min_severity 9
    When I audit event "auth_failure" with fields:
      | field    | value         |
      | outcome  | failure       |
      | actor_id | unknown       |
      | marker   | below_per_cat |
    Then the output should contain exactly 0 events

  Scenario: Per-category min_severity delivers events at or above the threshold
    Given an auditor with stdout output routed to include only "security" with min_severity 7
    When I audit event "auth_failure" with fields:
      | field    | value      |
      | outcome  | failure    |
      | actor_id | unknown    |
      | marker   | at_per_cat |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Mode C — severity-only catch-all (route-level applies)
  # ---------------------------------------------------------------------------

  Scenario: Severity-only catch-all without include_categories
    Given an auditor with stdout output routed with min_severity 9
    When I audit event "auth_failure" with fields:
      | field    | value     |
      | outcome  | failure   |
      | actor_id | unknown   |
      | marker   | not_crit  |
    And I audit event "system_breach" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | attacker |
      | marker   | crit     |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "system_breach"

  # ---------------------------------------------------------------------------
  # Severity precedence — route-level does NOT apply to category matches
  # ---------------------------------------------------------------------------

  # auth_failure resolves to severity 8 in the severity routing taxonomy.
  # The route includes category "security" with NIL filter, so all
  # severities for security must pass — even though route-level
  # min_severity=9 would normally reject sev=8.
  Scenario: Route-level severity does not gate category matches with nil filter
    Given a per-category route including "security" with no severity AND route-level min_severity 9
    When I audit event "auth_failure" with fields:
      | field    | value     |
      | outcome  | failure   |
      | actor_id | unknown   |
      | marker   | cat_match |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Validation errors (per-category bounds)
  # ---------------------------------------------------------------------------

  Scenario: Per-category min_severity above 10 is rejected
    When I try to create an auditor with per-category route for "security" min_severity 11
    Then the auditor creation should fail with error containing "min_severity 11 out of range 0-10"
    And the auditor creation should fail with error containing "EventRoute category"

  Scenario: Per-category min_severity exceeding per-category max_severity is rejected
    When I try to create an auditor with per-category route for "security" min_severity 8 and max_severity 3
    Then the auditor creation should fail with error containing "exceeds max_severity"
    And the auditor creation should fail with error containing "EventRoute category"

  Scenario: Per-category max_severity above 10 is rejected
    When I try to create an auditor with per-category route for "security" min_severity 0 and max_severity 11
    Then the auditor creation should fail with error containing "max_severity 11 out of range 0-10"
    And the auditor creation should fail with error containing "EventRoute category"

  Scenario: Unknown category in per-category route is rejected
    When I try to create an auditor with per-category route for "nonexistent_category" min_severity 5
    Then the auditor creation should fail with error containing "nonexistent_category"

  # ---------------------------------------------------------------------------
  # Runtime SetOutputRoute with per-category severity
  # ---------------------------------------------------------------------------

  Scenario: SetOutputRoute can switch from category-only to per-category severity
    Given an auditor with named stdout output "alerts" receiving all events
    When I audit event "auth_failure" with fields:
      | field    | value         |
      | outcome  | failure       |
      | actor_id | unknown       |
      | marker   | before_change |
    And I set output "alerts" route to per-category "security" with min_severity 9
    And I audit event "auth_failure" with fields:
      | field    | value        |
      | outcome  | failure      |
      | actor_id | unknown      |
      | marker   | rejected_now |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "auth_failure"
