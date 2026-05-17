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

// Per-output configuration options. WithOutputs and WithNamedOutput
// register output destinations on the auditor; the OutputOption
// helpers (WithRoute, WithOutputFormatter, WithExcludeLabels,
// WithHMAC) tune per-output behaviour. Split out of options.go (#540)
// to keep top-level auditor options separate from per-output knobs.
//
// The shared helpers buildLabelSet and checkDestinationDup live in
// options.go because they are also used by core construction paths.

import "fmt"

// WithOutputs sets the output destinations for the auditor. Events are
// fanned out to all provided outputs. Each output receives every
// globally-enabled event with no per-output filtering.
//
// Use this when every output should receive every enabled event —
// the simplest case (a single uniform fan-out). Switch to
// [WithNamedOutput] when you need per-output event routing,
// per-output formatters, sensitivity-label stripping, or per-output
// HMAC configuration. The two options MUST NOT be mixed in the same
// [New] call; mixing returns an error wrapping [ErrConfigInvalid].
//
// Duplicate output destinations are detected: if two outputs
// implement [DestinationKeyer] and return the same key, WithOutputs
// returns [ErrDuplicateDestination]. If no outputs are configured,
// events are validated and filtered but silently discarded.
func WithOutputs(outputs ...Output) Option {
	return func(a *Auditor) error {
		if len(a.entries) > 0 {
			return fmt.Errorf("audit: WithOutputs cannot be used with WithNamedOutput: %w", ErrConfigInvalid)
		}
		byName := make(map[string]*outputEntry, len(outputs))
		byDest := make(map[string]string) // destination key → output name
		entries := make([]*outputEntry, len(outputs))
		for i, o := range outputs {
			name := o.Name()
			if name == "" {
				return fmt.Errorf("audit: output Name() must not return an empty string: %w", ErrConfigInvalid)
			}
			if _, dup := byName[name]; dup {
				return fmt.Errorf("audit: duplicate output name %q: %w", name, ErrConfigInvalid)
			}
			if err := checkDestinationDup(o, name, byDest); err != nil {
				return err
			}
			oe := &outputEntry{output: o}
			entries[i] = oe
			byName[name] = oe
		}
		a.entries = entries
		a.outputsByName = byName
		a.usedWithOutputs = true
		return nil
	}
}

// OutputOption configures a single output registered via
// [WithNamedOutput]. Use [WithRoute], [WithOutputFormatter],
// [WithExcludeLabels], and [WithHMAC] to customise per-output
// behaviour.
type OutputOption func(*outputEntryBuilder)

// outputEntryBuilder accumulates per-output configuration before
// the output entry is registered on the auditor.
type outputEntryBuilder struct {
	formatter     Formatter
	route         *EventRoute
	hmacConfig    *HMACConfig
	excludeLabels []string
}

// WithRoute sets the per-output event route. The route restricts
// which events are delivered to this output. Nil means all
// globally-enabled events are delivered.
func WithRoute(r *EventRoute) OutputOption {
	return func(b *outputEntryBuilder) {
		b.route = r
	}
}

// WithOutputFormatter overrides the auditor's default formatter for
// this output. Nil means the auditor's default formatter is used.
//
// The "Output" prefix disambiguates from the auditor-level
// [WithFormatter] option; the two options set different defaults
// (auditor-wide vs per-output).
func WithOutputFormatter(f Formatter) OutputOption {
	return func(b *outputEntryBuilder) {
		b.formatter = f
	}
}

// WithExcludeLabels specifies sensitivity labels whose fields should
// be stripped from events before delivery to this output. When
// non-empty, the taxonomy MUST define a [SensitivityConfig] and every
// label MUST be defined within it; [New] returns an error if
// either condition is violated. An empty call means no field stripping.
// Framework fields are never stripped.
func WithExcludeLabels(labels ...string) OutputOption {
	return func(b *outputEntryBuilder) {
		b.excludeLabels = labels
	}
}

// WithHMAC configures per-output HMAC integrity. The config is
// validated eagerly during [New] option application — invalid
// configs (short salt, unknown algorithm) cause [New] to return
// an error. Nil means no HMAC for this output.
func WithHMAC(cfg *HMACConfig) OutputOption {
	return func(b *outputEntryBuilder) {
		b.hmacConfig = cfg
	}
}

// WithNamedOutput adds a single named output with optional per-output
// configuration. Use [WithRoute], [WithOutputFormatter],
// [WithExcludeLabels], and [WithHMAC] to customise behaviour.
//
// Use this for any production setup with multiple outputs, or when
// even a single output needs routing, a per-output formatter,
// sensitivity-label stripping, or HMAC. [WithOutputs] is a shortcut
// for the simplest case (single uniform fan-out, no per-output config).
//
// WithNamedOutput MUST NOT be combined with [WithOutputs]; if
// [WithOutputs] was already applied, WithNamedOutput returns an
// error wrapping [ErrConfigInvalid].
//
// Output names MUST be unique across all outputs; duplicate names
// cause [New] to return an error. Duplicate destinations are
// also detected via [DestinationKeyer]. Routes are validated against
// the taxonomy after all options have been applied.
func WithNamedOutput(output Output, opts ...OutputOption) Option {
	return func(a *Auditor) error {
		if a.usedWithOutputs {
			return fmt.Errorf("audit: WithNamedOutput cannot be used with WithOutputs: %w", ErrConfigInvalid)
		}
		var b outputEntryBuilder
		for _, opt := range opts {
			opt(&b)
		}
		if b.hmacConfig != nil {
			if err := ValidateHMACConfig(b.hmacConfig); err != nil {
				return err
			}
		}
		return a.addNamedOutput(output, &b)
	}
}

// addNamedOutput registers a named output with dedup checking and
// optional route/formatter/exclude-label/HMAC configuration.
func (a *Auditor) addNamedOutput(output Output, b *outputEntryBuilder) error {
	name := output.Name()
	if name == "" {
		return fmt.Errorf("audit: output Name() must not return an empty string: %w", ErrConfigInvalid)
	}
	if a.outputsByName == nil {
		a.outputsByName = make(map[string]*outputEntry)
	}
	if a.destKeys == nil {
		a.destKeys = make(map[string]string)
	}
	if _, dup := a.outputsByName[name]; dup {
		return fmt.Errorf("audit: duplicate output name %q: %w", name, ErrConfigInvalid)
	}
	if err := checkDestinationDup(output, name, a.destKeys); err != nil {
		return err
	}
	oe := &outputEntry{
		output:    output,
		formatter: b.formatter,
	}
	if b.route != nil {
		oe.setRoute(b.route)
	}
	if len(b.excludeLabels) > 0 {
		oe.excludedLabels = buildLabelSet(b.excludeLabels)
	}
	if b.hmacConfig != nil {
		oe.hmacConfig = b.hmacConfig
	}
	a.entries = append(a.entries, oe)
	a.outputsByName[name] = oe
	return nil
}
