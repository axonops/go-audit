// Copyright 2026 AxonOps Limited.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

// Control-plane methods on [Auditor]: runtime enable/disable of
// taxonomy categories and event types. Split out of audit.go (#540).
//
// Accepted trade-off (#509, master-tracker C-23): EnableCategory,
// DisableCategory, EnableEvent, and DisableEvent all use fmt.Errorf
// on the validation-miss path, which allocates. These are admin /
// control-plane operations invoked during startup and occasional
// runtime reconfiguration — not the hot path. The allocation rate
// is negligible compared to Audit() and optimising it would obscure
// the error-message semantics. Hot-path filter state reads
// (filterState.isEnabled) are separately optimised and do not
// allocate; see filter.go.

import "fmt"

// EnableCategory enables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Auditor.DisableEvent] take precedence over category state.
func (a *Auditor) EnableCategory(category string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot enable category on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	a.filter.enabledCategories.Store(category, true)
	a.logger.Load().Info("audit: category enabled", "category", category)
	return nil
}

// DisableCategory disables all events in the named category. The
// category MUST exist in the registered taxonomy. Per-event overrides
// via [Auditor.EnableEvent] take precedence over category state.
func (a *Auditor) DisableCategory(category string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot disable category on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Categories[category]; !ok {
		return fmt.Errorf("audit: unknown category %q", category)
	}
	a.filter.enabledCategories.Store(category, false)
	a.logger.Load().Info("audit: category disabled", "category", category)
	return nil
}

// EnableEvent enables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (a *Auditor) EnableEvent(eventType string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot enable event on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	a.filter.eventOverrides.Store(eventType, true)
	a.filter.hasEventOverrides.Store(true)
	a.logger.Load().Info("audit: event enabled", "event_type", eventType)
	return nil
}

// DisableEvent disables a specific event type regardless of its
// category's state. The event type MUST exist in the registered
// taxonomy. Per-event overrides take precedence over category state.
func (a *Auditor) DisableEvent(eventType string) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot disable event on disabled auditor: %w", ErrDisabled)
	}
	// taxonomy is immutable after construction; safe to read without lock.
	if _, ok := a.taxonomy.Events[eventType]; !ok {
		return fmt.Errorf("audit: unknown event type %q", eventType)
	}
	a.filter.eventOverrides.Store(eventType, false)
	a.filter.hasEventOverrides.Store(true)
	a.logger.Load().Info("audit: event disabled", "event_type", eventType)
	return nil
}
