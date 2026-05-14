@core @webhook-batching
Feature: Webhook batched payload structure for JSON and CEF (#463)
  As a library consumer, I want the webhook output to produce a
  wire body whose structure matches its declared Content-Type:
  newline-delimited JSON for the JSON formatter, newline-delimited
  CEF lines for the CEF formatter. The receiver should be able to
  parse the batch back without guessing the format.

  Background:
    Given a standard test taxonomy

  # ---------------------------------------------------------------------------
  # JSON formatter — NDJSON wire structure
  # ---------------------------------------------------------------------------

  Scenario: Multi-event NDJSON batch has exactly N parseable JSON lines
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver, batch size 3
    When I audit 3 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request body should have exactly 3 NDJSON lines
    And the most recent body-capture request body should end with a newline

  Scenario: NDJSON line order preserves submission order
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver, batch size 3
    When I audit 3 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And line 1 of the body-capture body should contain marker "m1"
    And line 2 of the body-capture body should contain marker "m2"
    And line 3 of the body-capture body should contain marker "m3"

  Scenario: Default formatter sends application/x-ndjson Content-Type
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver, batch size 1
    When I audit 1 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request Content-Type should be "application/x-ndjson"

  # ---------------------------------------------------------------------------
  # CEF formatter — text/plain wire structure (#463)
  # ---------------------------------------------------------------------------

  Scenario: Single-event CEF body has one CEF line
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver using CEF formatter, batch size 1
    When I audit 1 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request body should have exactly 1 CEF lines
    And the most recent body-capture request body should end with a newline

  Scenario: Multi-event CEF batch has exactly N CEF lines
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver using CEF formatter, batch size 3
    When I audit 3 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request body should have exactly 3 CEF lines
    And the most recent body-capture request body should end with a newline

  Scenario: CEF formatter sends text/plain Content-Type
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver using CEF formatter, batch size 1
    When I audit 1 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request Content-Type should be "text/plain"

  Scenario: CEF formatter does not send application/x-ndjson Content-Type
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver using CEF formatter, batch size 1
    When I audit 1 uniquely marked batching events
    And I close the batching auditor
    Then the body-capture receiver should have at least 1 request within 5 seconds
    And the most recent body-capture request Content-Type should not be "application/x-ndjson"

  # ---------------------------------------------------------------------------
  # Lifecycle edge cases
  # ---------------------------------------------------------------------------

  Scenario: Close with no audited events sends no request
    Given a local body-capturing webhook receiver
    And an auditor with webhook output to the body-capture receiver, batch size 10
    When I close the batching auditor
    Then the body-capture receiver should have exactly 0 requests

  # ---------------------------------------------------------------------------
  # Multi-output Content-Type isolation
  # ---------------------------------------------------------------------------

  Scenario: JSON and CEF webhook outputs send distinct Content-Types
    Given two local body-capturing webhook receivers
    And an auditor with two webhook outputs: receiver A using JSON, receiver B using CEF, batch size 1
    When I audit 1 uniquely marked batching events
    And I close the batching auditor
    Then receiver A should have at least 1 request within 5 seconds
    And receiver B should have at least 1 request within 5 seconds
    And the most recent receiver A request Content-Type should be "application/x-ndjson"
    And the most recent receiver B request Content-Type should be "text/plain"
