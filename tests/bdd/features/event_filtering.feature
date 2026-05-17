@core @filtering
Feature: Event Filtering
  As a library consumer, I want to enable and disable event categories
  at runtime so that I can control which events are recorded without
  restarting the application.

  Event filtering operates at two levels: category-level (enable/disable
  all events in a category) and per-event overrides (enable/disable a
  specific event type regardless of its category state). Per-event
  overrides always take precedence over category state.

  Background:
    Given a taxonomy with categories "write" and "security"
    And an auditor with stdout output

  # --- Category-level filtering ---

  Scenario: All categories are enabled by default
    When I audit event "user_create" with required fields
    Then the event should be delivered successfully
    And the output should contain an event matching:
      | field      | value       |
      | event_type | user_create |
      | outcome    | success     |
      | actor_id   | test-actor  |
      | marker     |             |

  Scenario: Events in disabled categories are silently discarded
    Given I disable category "security"
    When I audit event "auth_failure" with required fields
    Then the audit call should return no error
    And no events should be delivered

  Scenario: Re-enabling a disabled category starts delivery
    Given I disable category "security"
    And I enable category "security"
    When I audit event "auth_failure" with required fields
    Then the event should be delivered successfully
    And the output should contain an event matching:
      | field      | value        |
      | event_type | auth_failure |
      | outcome    | success      |
      | actor_id   | test-actor   |
      | marker     |              |

  Scenario: Disabling an enabled category stops delivery
    Given I disable category "write"
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And no events should be delivered

  # --- Per-event overrides ---

  Scenario: EnableEvent overrides disabled category
    Given I disable category "security"
    And I enable event "auth_failure"
    When I audit event "auth_failure" with required fields
    Then the event should be delivered successfully

  Scenario: DisableEvent overrides enabled category
    Given I disable event "user_create"
    When I audit event "user_create" with required fields
    Then the audit call should return no error
    And no events should be delivered

  Scenario: Per-event override takes precedence over category state
    Given I disable category "write"
    And I enable event "user_create"
    When I audit event "user_create" with required fields
    Then the event should be delivered successfully

  # --- Error handling ---

  # Each Enable/Disable error wraps a sentinel (#467) so consumers can
  # discriminate via errors.Is: ErrConfigInvalid for unknown categories,
  # ErrHandleNotFound for unknown event types. The rendered string
  # preserves the original "audit: unknown X %q" prefix for diagnostic
  # tooling and appends the wrapped sentinel's message.

  Scenario: Enabling unknown category returns exact error
    When I try to enable category "nonexistent"
    Then the operation should return an error matching:
      """
      audit: unknown category "nonexistent": audit: config validation failed
      """

  Scenario: Disabling unknown category returns exact error
    When I try to disable category "nonexistent"
    Then the operation should return an error matching:
      """
      audit: unknown category "nonexistent": audit: config validation failed
      """

  Scenario: Enabling unknown event type returns exact error
    When I try to enable event "nonexistent_event"
    Then the operation should return an error matching:
      """
      audit: unknown event type "nonexistent_event": audit: event type not found
      """

  Scenario: Disabling unknown event type returns exact error
    When I try to disable event "nonexistent_event"
    Then the operation should return an error matching:
      """
      audit: unknown event type "nonexistent_event": audit: event type not found
      """

  # Sentinel wrapping (#467): proves consumers can discriminate
  # operation errors via errors.Is without string matching, per the
  # CLAUDE.md error-discrimination convention.

  Scenario: Enabling unknown category wraps ErrConfigInvalid
    When I try to enable category "nonexistent"
    Then the operation should return an error wrapping "ErrConfigInvalid"

  Scenario: Enabling unknown event type wraps ErrHandleNotFound
    When I try to enable event "nonexistent_event"
    Then the operation should return an error wrapping "ErrHandleNotFound"
