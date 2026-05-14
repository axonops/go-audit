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

package webhook

// ValidateConfigForTest exposes the internal config-validator to
// black-box test packages. Production callers MUST use New, which
// runs the same validator before constructing the output.
var ValidateConfigForTest = validateWebhookConfig

// ParseRetryAfter exposes the internal Retry-After parser to
// black-box test packages so the table-driven boundary cases (cap
// clamping, malformed values, non-positive values) can be asserted
// without going through the retry-loop integration path.
var ParseRetryAfter = parseRetryAfter

// MaxRetryAfter exposes the Retry-After cap so cap-clamping tests
// can reference the documented limit without hardcoding the value.
const MaxRetryAfter = maxRetryAfter
