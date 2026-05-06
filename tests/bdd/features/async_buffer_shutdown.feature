@core @shutdown
Feature: Async Buffer Shutdown
  As a library consumer, I want Close to drain all per-output async
  buffers before returning so that no audit data is silently lost
  during application shutdown.

  Each async output (file, syslog, webhook, loki) has an internal
  buffered channel. Close signals the background writeLoop to drain
  remaining events, then waits for completion with a timeout.

  Background:
    Given a standard test taxonomy

  Scenario: File output drains all buffered events on close
    Given an auditor with file output at a temporary path
    When I audit 50 events rapidly
    And I close the auditor
    Then the file should contain exactly 50 events

  Scenario: Close with async file output is idempotent
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor
    And I close the auditor again
    Then the second close should return no error
    And the file should contain exactly 1 event

  Scenario: Concurrent close and audit does not panic
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor from 5 goroutines concurrently
    Then no panic should have occurred

  Scenario: Close with error output does not block file drain
    Given an auditor with file output and an error-returning output
    When I audit a uniquely marked "user_create" event
    And I close the auditor
    Then the file should contain the marker

  Scenario: Shutdown completes within timeout when output Write blocks
    Given an auditor with a blocking output and drain timeout 1s
    When I audit event "user_create" with required fields
    Then closing the auditor should complete within 5 seconds

  # #564 P0 BDD coverage for async-delivery edge cases. These scenarios
  # pin documented contracts that were previously only covered by unit
  # tests:
  #
  #   1. Synchronous AuditEvent on a closed auditor returns ErrClosed
  #      synchronously (not after a drain wait).
  #   2. Synchronous delivery isolates a panicking output — other
  #      outputs still receive the event.
  #   3. buffer_size: 0 on a per-output config silently coerces to the
  #      per-output default capacity.
  #   4. Delivery accounting:
  #      submitted = delivered + filtered + dropped
  #                + validation_errors + serialization_errors
  #      holds under a mixed workload.

  Scenario: Synchronous AuditEvent returns ErrClosed after auditor is closed
    Given an auditor with synchronous delivery and a recording mock output
    When I close the auditor
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"
    And the recording output should have received exactly 0 events

  Scenario: Synchronous delivery isolates a panicking output from a healthy output
    Given an auditor with synchronous delivery, file output, and a panicking output
    When I audit a uniquely marked "user_create" event
    Then the audit call should return no error
    And the file should contain the marker

  Scenario: File output with buffer_size 0 coerces to default capacity
    Given a file output with buffer_size 0 and mock output metrics
    Given an auditor with that file output and queue_size 1
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the file should contain exactly 1 event
    And the effective output buffer capacity should be 10000

  Scenario: Delivery accounting invariant holds under a mixed workload
    Given an auditor with a recording output, pipeline metrics, and synchronous delivery
    When I audit event "user_create" with required fields
    And I audit event "user_create" with required fields
    And I try to audit event "unknown_event_type" with required fields
    And I disable category "write"
    And I audit event "user_create" with required fields
    And I close the auditor
    Then RecordSubmitted should have been called 4 times
    And the delivery accounting invariant should hold

  # Per-counter coverage of the delivery accounting invariant
  # (#722). The mixed-workload scenario above exercises Successes,
  # ValidationErrors, and Filtered; the three scenarios below force
  # OutputErrors, SerializationErrors, and BufferDrops respectively
  # so every counter in the invariant equation is non-zero in at
  # least one scenario. Together they kill the tautology risk where
  # a regression in RecordOutputError, RecordSerializationError, or
  # RecordBufferDrop would not be caught by the mixed-workload
  # scenario alone.

  Scenario: Delivery accounting invariant holds when an output Write returns an error
    Given an auditor with an error output, pipeline metrics, and synchronous delivery
    When I audit event "user_create" with required fields
    And I close the auditor
    Then RecordSubmitted should have been called 1 time
    And the OutputErrors counter should equal 1
    And the delivery accounting invariant should hold

  Scenario: Delivery accounting invariant holds when the formatter returns an error
    Given an auditor with an error-returning formatter, a recording output, pipeline metrics, and synchronous delivery
    When I audit event "user_create" with required fields
    And I close the auditor
    Then RecordSubmitted should have been called 1 time
    And the SerializationErrors counter should equal 1
    And the delivery accounting invariant should hold

  # Async delivery is the only mode that exposes BufferDrops; sync
  # delivery has no buffer, hence no overflow path. The default
  # behaviour when the queue is full is non-blocking — AuditEvent
  # returns audit.ErrQueueFull and RecordBufferDrop is incremented
  # (audit.go:320 doc block). This scenario pins that contract.
  Scenario: Delivery accounting invariant holds when the async queue overflows
    Given an auditor with a slow output, pipeline metrics, and async delivery with queue_size 1
    When I audit 200 events with required fields
    And I close the auditor
    Then RecordSubmitted should have been called 200 times
    And the BufferDrops counter should be at least 1
    And Successes plus BufferDrops should equal 200
    And the delivery accounting invariant should hold
