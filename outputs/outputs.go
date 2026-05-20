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

package outputs

import (
	"github.com/axonops/audit"

	_ "github.com/axonops/audit/file"    // register "file" output type
	_ "github.com/axonops/audit/loki"    // register "loki" output type
	_ "github.com/axonops/audit/syslog"  // register "syslog" output type
	_ "github.com/axonops/audit/webhook" // register "webhook" output type
	// "splunk" is registered explicitly by consumers via
	// `import _ "github.com/axonops/audit/splunk"` until the splunk
	// module is published (#55).
)

// init registers the "stdout" output factory. The core audit package
// used to register it automatically via its own init(); that was
// dropped in #578 to eliminate hidden global mutation at import time.
// Now consumers who blank-import this convenience package get the
// stdout factory registered alongside file/loki/syslog/webhook,
// preserving the pre-#578 behaviour of `import _ ".../audit/outputs"`.
// Consumers who do not blank-import this package and want the YAML
// `type: stdout` form MUST call
// [audit.RegisterOutputFactory] themselves:
//
//	audit.MustRegisterOutputFactory("stdout", audit.StdoutFactory())
func init() {
	audit.MustRegisterOutputFactory("stdout", audit.StdoutFactory())
}
