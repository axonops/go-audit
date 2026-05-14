@core @severity-routing
Feature: Severity-based event routing
  As a library consumer, I want to route audit events to different
  outputs based on their severity level, so that high-severity events
  (like authentication failures) trigger alerts via PagerDuty while
  low-severity events go to a debug log.

  Severity precedence (#193): for category matches in
  include_categories, the per-category SeverityRange is authoritative
  and route-level MinSeverity/MaxSeverity is NOT applied. Route-level
  severity applies to include_event_types matches, exclude-mode
  routes, and the severity-only catch-all (the PagerDuty pattern).

  Background:
    Given a severity routing taxonomy

  # ---------------------------------------------------------------------------
  # MinSeverity filtering
  # ---------------------------------------------------------------------------

  Scenario: MinSeverity filters out events below threshold
    Given an auditor with stdout output routed with min_severity 7
    When I audit event "user_create" with fields:
      | field    | value   |
      | outcome  | success |
      | actor_id | alice   |
      | marker   | low_sev |
    And I audit event "auth_failure" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | unknown  |
      | marker   | high_sev |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "auth_failure"

  Scenario: MinSeverity equal to event severity delivers the event
    Given an auditor with stdout output routed with min_severity 8
    When I audit event "auth_failure" with fields:
      | field    | value       |
      | outcome  | failure     |
      | actor_id | unknown     |
      | marker   | exact_match |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # MaxSeverity filtering
  # ---------------------------------------------------------------------------

  Scenario: MaxSeverity filters out events above threshold
    Given an auditor with stdout output routed with max_severity 5
    When I audit event "user_create" with fields:
      | field    | value     |
      | outcome  | success   |
      | actor_id | alice     |
      | marker   | below_max |
    And I audit event "auth_failure" with fields:
      | field    | value     |
      | outcome  | failure   |
      | actor_id | unknown   |
      | marker   | above_max |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "user_create"

  Scenario: MaxSeverity equal to event severity delivers the event
    Given an auditor with stdout output routed with max_severity 4
    When I audit event "user_create" with fields:
      | field    | value     |
      | outcome  | success   |
      | actor_id | alice     |
      | marker   | exact_max |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Severity range (MinSeverity + MaxSeverity)
  # ---------------------------------------------------------------------------

  Scenario: Severity range delivers only events within the band
    Given an auditor with stdout output routed with min_severity 3 and max_severity 7
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
      | marker  | too_low |
    And I audit event "user_create" with fields:
      | field    | value    |
      | outcome  | success  |
      | actor_id | alice    |
      | marker   | in_range |
    And I audit event "auth_failure" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | unknown  |
      | marker   | too_high |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "user_create"

  # ---------------------------------------------------------------------------
  # Severity-only route (PagerDuty use case)
  # ---------------------------------------------------------------------------

  Scenario: Severity-only route with no category or event type filters
    Given an auditor with stdout output routed with min_severity 9
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
      | marker  | info    |
    And I audit event "user_create" with fields:
      | field    | value |
      | outcome  | success |
      | actor_id | alice |
      | marker   | write |
    And I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
      | marker   | security |
    And I audit event "system_breach" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | attacker |
      | marker   | critical |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "system_breach"

  # ---------------------------------------------------------------------------
  # Per-category severity (#193) — the step builds a per-category
  # SeverityRange; route-level MinSeverity is NOT used for these
  # scenarios.
  # ---------------------------------------------------------------------------

  Scenario: Category include with per-category min_severity rejects below threshold
    Given an auditor with stdout output routed to include only "security" with min_severity 9
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
      | marker   | sec_low |
    Then the output should contain exactly 0 events

  Scenario: Category include with per-category min_severity at threshold delivers
    Given an auditor with stdout output routed to include only "security" with min_severity 7
    When I audit event "auth_failure" with fields:
      | field    | value      |
      | outcome  | failure    |
      | actor_id | unknown    |
      | marker   | both_match |
    Then the output should contain exactly 1 event

  Scenario: Category exclude with severity filter
    Given an auditor with stdout output routed to exclude "read" with min_severity 3
    When I audit event "user_get" with fields:
      | field   | value   |
      | outcome | success |
      | marker  | excluded_cat |
    And I audit event "user_create" with fields:
      | field    | value      |
      | outcome  | success    |
      | actor_id | alice      |
      | marker   | pass_both  |
    And I audit event "health_check" with fields:
      | field   | value     |
      | outcome | success   |
      | marker  | below_min |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "user_create"

  # ---------------------------------------------------------------------------
  # Boundary values
  # ---------------------------------------------------------------------------

  Scenario: MinSeverity 0 acts as no-op floor — all events pass
    Given an auditor with stdout output routed with min_severity 0
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 1 event

  Scenario: MaxSeverity 0 filters everything except severity 0
    Given an auditor with stdout output routed with max_severity 0
    When I audit event "health_check" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 0 events

  Scenario: MinSeverity 10 delivers only severity 10 events
    Given an auditor with stdout output routed with min_severity 10
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
    And I audit event "system_breach" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | attacker |
    Then the output should contain exactly 1 event
    And all delivered events should have event_type "system_breach"

  Scenario: MaxSeverity 10 acts as no-op ceiling — all events pass
    Given an auditor with stdout output routed with max_severity 10
    When I audit event "system_breach" with fields:
      | field    | value    |
      | outcome  | failure  |
      | actor_id | attacker |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Backward compatibility
  # ---------------------------------------------------------------------------

  Scenario: Nil severity filters deliver all events unchanged
    Given an auditor with stdout output routed to include only "security"
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
    Then the output should contain exactly 1 event

  # ---------------------------------------------------------------------------
  # Uncategorised events
  # ---------------------------------------------------------------------------

  # custom_event has event-level severity 6 in the taxonomy (below min 7).
  Scenario: Severity filter applies to uncategorised events
    Given an auditor with stdout output routed with min_severity 7
    When I audit event "custom_event" with fields:
      | field   | value   |
      | outcome | success |
    Then the output should contain exactly 0 events

  # ---------------------------------------------------------------------------
  # Runtime SetOutputRoute with severity
  # ---------------------------------------------------------------------------

  Scenario: SetOutputRoute changes severity threshold at runtime
    Given an auditor with named stdout output "alerts" receiving all events
    When I audit event "user_create" with fields:
      | field    | value         |
      | outcome  | success       |
      | actor_id | alice         |
      | marker   | before_change |
    And I set output "alerts" route to min_severity 7
    And I audit event "user_create" with fields:
      | field    | value        |
      | outcome  | success      |
      | actor_id | alice        |
      | marker   | after_change |
    And I audit event "auth_failure" with fields:
      | field    | value        |
      | outcome  | failure      |
      | actor_id | unknown      |
      | marker   | passes_after |
    Then the output should contain exactly 2 events

  # ---------------------------------------------------------------------------
  # Validation errors
  # ---------------------------------------------------------------------------

  Scenario: MinSeverity out of range is rejected
    When I try to create an auditor with route min_severity 11
    Then the auditor creation should fail with error containing "min_severity 11 out of range 0-10"

  Scenario: MaxSeverity out of range is rejected
    When I try to create an auditor with route max_severity -1
    Then the auditor creation should fail with error containing "max_severity -1 out of range 0-10"

  Scenario: MinSeverity greater than MaxSeverity is rejected
    When I try to create an auditor with route min_severity 8 and max_severity 3
    Then the auditor creation should fail with error containing "min_severity 8 exceeds max_severity 3"

  Scenario: MinSeverity 0 is valid and accepted
    Given an auditor with stdout output routed with min_severity 0
    Then the auditor should be created successfully

  # ---------------------------------------------------------------------------
  # Multi-category interaction
  # ---------------------------------------------------------------------------

  # The multi-category severity taxonomy has auth_failure in compliance
  # (severity 3) and security (severity 8). The resolved severity is 3
  # (compliance wins alphabetically). With min_severity 5, severity 3 < 5
  # → rejected on ALL category passes.
  Scenario: Multi-category event uses single resolved severity for routing
    Given a multi-category severity taxonomy
    And an auditor with stdout output routed with min_severity 5
    When I audit event "auth_failure" with fields:
      | field    | value   |
      | outcome  | failure |
      | actor_id | unknown |
    Then the output should contain exactly 0 events
