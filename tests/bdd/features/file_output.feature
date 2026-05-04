@file
Feature: File Output
  As a library consumer, I want to write audit events to a log file
  so that I have a persistent local record of all audit activity.

  The file output supports automatic rotation by size, backup retention,
  gzip compression, and configurable permissions. Symlinks are rejected
  for security.

  Background:
    Given a standard test taxonomy

  # --- Write & format ---

  Scenario: Write JSON event to file with complete field verification
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with fields:
      | field       | value      |
      | outcome     | success    |
      | actor_id    | alice      |
      | marker      | file_test  |
      | target_id   | user-42    |
    And I close the auditor
    Then every event in the file should be valid JSON
    And the file should contain an event matching:
      | field       | value       |
      | event_type  | user_create |
      | outcome     | success     |
      | actor_id    | alice       |
      | marker      | file_test   |
      | target_id   | user-42     |
      | duration_ms |             |

  Scenario: Multiple writes produce one event per line
    Given an auditor with file output at a temporary path
    When I audit 5 events rapidly
    And I close the auditor
    Then the file should contain exactly 5 events
    And every event in the file should be valid JSON

  Scenario: Concurrent writes do not interleave lines
    Given an auditor with file output at a temporary path
    When I audit 100 events from 10 concurrent goroutines
    And I close the auditor
    Then the file should contain exactly 100 events
    And every event in the file should be valid JSON

  # --- Permissions ---

  Scenario: Default file permissions are 0600
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the file should have permissions "0600"

  Scenario: Group-readable file output uses 0640
    Given an auditor with file output that is group-readable
    When I audit event "user_create" with required fields
    And I close the auditor
    Then the file should have permissions "0640"

  Scenario: Existing audit log with broader permissions is rejected
    Given an existing audit log file with permissions 0644 at the configured path
    When I try to construct a file output at that path
    Then the file output construction should fail with an error
    And the error should wrap audit.ErrConfigInvalid
    And the error message should contain "broader than required"

  Scenario: Existing audit log with narrower permissions is accepted
    Given an existing audit log file with permissions 0600 at the configured path
    When I construct a group-readable file output at that path
    Then the file output construction should succeed

  Scenario: Symlink path is rejected on write — symlink target stays empty
    When I write a single event to a file output configured with a symlink path
    Then the symlink target file should remain empty

  # --- Rotation ---

  Scenario: File rotates when MaxSizeMB exceeded
    Given an auditor with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then more than one file should exist in the output directory

  Scenario: Rotated backup has timestamp in filename
    Given an auditor with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then a backup file with a timestamp pattern should exist in the output directory

  Scenario: Compressed backups have .gz extension
    Given an auditor with file output configured for 1 MB max size with compression
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then a .gz backup file should exist in the output directory

  Scenario: Compression disabled preserves plain backup
    Given an auditor with file output configured for 1 MB max size without compression
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then no .gz files should exist in the output directory

  # --- Config validation ---

  Scenario: Empty path is rejected with exact error
    When I try to create a file output with empty path
    Then the file output construction should fail with error:
      """
      audit/file: output path must not be empty
      """

  Scenario: MaxSizeMB exceeding limit is rejected
    When I try to create a file output with MaxSizeMB 20000
    Then the file output construction should fail with an error

  Scenario: Non-existent parent directory is rejected
    When I try to create a file output at "/nonexistent/dir/audit.log"
    Then the file output construction should fail with an error

  Scenario: MaxBackups exceeding limit is rejected
    When I try to create a file output with MaxBackups 200
    Then the file output construction should fail with an error

  # --- Lifecycle ---

  Scenario: Write after close returns error
    Given an auditor with file output at a temporary path
    When I close the auditor
    And I try to audit event "user_create" with required fields
    Then the audit call should return an error wrapping "ErrClosed"

  Scenario: Close is idempotent
    Given an auditor with file output at a temporary path
    When I audit event "user_create" with required fields
    And I close the auditor
    And I close the auditor again
    Then the second close should return no error

  # --- File-specific metrics ---

  Scenario: Rotation triggers RecordFileRotation callback
    Given mock file metrics are configured
    And an auditor with file output configured for 1 MB max size with file metrics
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then the file metrics should have recorded at least 1 rotation

  Scenario: MaxBackups enforced — excess deleted
    Given an auditor with file output configured for 1 MB max size and max backups 2
    When I write enough events to exceed 4 MB
    And I close the auditor
    Then at most 3 files should exist in the output directory

  Scenario: Multiple rotations trigger multiple metric callbacks
    Given mock file metrics are configured
    And an auditor with file output configured for 1 MB max size with file metrics
    When I write enough events to exceed 3 MB
    And I close the auditor
    Then the file metrics should have recorded at least 2 rotations

  Scenario: Nil file metrics does not panic on rotation
    Given an auditor with file output configured for 1 MB max size
    When I write enough events to exceed 1 MB
    And I close the auditor
    Then the file should contain events

  # --- OS-level failure modes (#748) ---
  #
  # Each scenario asserts the file output's writeLoop calls
  # om.RecordError when the underlying filesystem returns the
  # mapped errno. The MockFileMetrics extension (#748) captures
  # these calls via an ErrorCount() accessor.

  Scenario: File output records RecordError when target directory becomes read-only
    Given mock file metrics are configured
    And an auditor with file output configured for 1 MB max size with file metrics
    When I write enough events to exceed 1 MB
    And I wait for at least 1 file rotation(s)
    And the audit log directory is made read-only
    And I write enough events to exceed 1 MB
    Then the file output should record at least 1 error(s)

  @linux
  Scenario: File output records RecordError when fd limit is exhausted on rotation
    When I run the file-emfile subprocess

  @linux @docker
  Scenario: File output records RecordError on ENOSPC
    Given the file-os tmpfs container is up
    When I run the ENOSPC test inside the file-os container
