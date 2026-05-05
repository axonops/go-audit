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

// Per-output route validation and management methods on [Auditor].
// Split out of audit.go (#540).

import "fmt"

// validateOutputRoutes checks all per-output event routes and
// sensitivity exclusion labels against the taxonomy.
func (a *Auditor) validateOutputRoutes() error {
	for _, oe := range a.entries {
		route := oe.route.Load()
		if route != nil {
			if err := ValidateEventRoute(route, a.taxonomy); err != nil {
				return fmt.Errorf("audit: output %q: %w", oe.output.Name(), err)
			}
		}
		if err := a.validateExcludeLabels(oe); err != nil {
			return err
		}
	}
	return nil
}

// validateExcludeLabels checks that all exclude_labels on an output
// reference labels defined in the taxonomy's sensitivity config.
func (a *Auditor) validateExcludeLabels(oe *outputEntry) error {
	if len(oe.excludedLabels) == 0 {
		return nil
	}
	if a.taxonomy == nil || a.taxonomy.Sensitivity == nil {
		return fmt.Errorf("audit: output %q has exclude_labels but taxonomy has no sensitivity config",
			oe.output.Name())
	}
	for label := range oe.excludedLabels {
		if _, ok := a.taxonomy.Sensitivity.Labels[label]; !ok {
			return fmt.Errorf("audit: output %q exclude_labels references undefined sensitivity label %q",
				oe.output.Name(), label)
		}
	}
	return nil
}

// SetOutputRoute sets the per-output event route for the named output.
// The route is validated against the taxonomy; unknown categories or
// event types return an error. Mixed include/exclude routes return an
// error. An unknown output name returns an error.
//
// SetOutputRoute is safe for concurrent use with event delivery.
func (a *Auditor) SetOutputRoute(outputName string, route *EventRoute) error {
	if a.disabled {
		return fmt.Errorf("audit: cannot set output route on disabled auditor: %w", ErrDisabled)
	}
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	if err := ValidateEventRoute(route, a.taxonomy); err != nil {
		return err
	}
	oe.setRoute(route)
	a.logger.Load().Info("audit: output route set", "output", outputName)
	return nil
}

// ClearOutputRoute removes the per-output event route for the named
// output, causing it to receive all globally-enabled events.
//
// ClearOutputRoute is safe for concurrent use with event delivery.
func (a *Auditor) ClearOutputRoute(outputName string) error {
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return fmt.Errorf("audit: unknown output %q", outputName)
	}
	oe.setRoute(&EventRoute{})
	a.logger.Load().Info("audit: output route cleared", "output", outputName)
	return nil
}

// OutputRoute returns a copy of the current per-output event route
// for the named output. An unknown output name returns an error.
func (a *Auditor) OutputRoute(outputName string) (EventRoute, error) {
	oe, ok := a.outputsByName[outputName]
	if !ok {
		return EventRoute{}, fmt.Errorf("audit: unknown output %q", outputName)
	}
	return oe.getRoute(), nil
}
