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

// IsFrameworkField is exported for testing only.
var IsFrameworkField = isFrameworkField

// IsZeroValueForTest is exported for testing only. Direct coverage
// of the float32 / uint / uint64 branches in isZeroValue, which are
// no longer reachable through AuditEvent (#595 B-43 coerces those
// types to string upstream of OmitEmpty in non-strict modes).
var IsZeroValueForTest = isZeroValue

// BuildRouteForTest exposes buildRouteSets so external (audit_test)
// benchmarks and tests can opt routes into the same inline fast
// path that production uses via Auditor.SetOutputRoute. Production
// callers go through the auditor; consumers never need to build
// routes themselves. The export_test.go naming ensures this symbol
// is NOT part of the public audit package surface — it lives only
// in the test binary. (#867 PR-2.)
func BuildRouteForTest(r *EventRoute) {
	buildRouteSets(r)
}

// InlineCatCountForTest exposes the unexported inlineCatCount
// field so white-box tests can assert which path MatchesRoute
// dispatches through after BuildRouteForTest is called.
func InlineCatCountForTest(r *EventRoute) int8 { return r.inlineCatCount }

// KindForTest exposes the unexported route kind discriminator so
// white-box tests can assert the routeMode classification. Values
// match the unexported routeMode constants: 0=empty, 1=include,
// 2=exclude, 3=severity-only.
func KindForTest(r *EventRoute) uint8 { return uint8(r.kind) }
