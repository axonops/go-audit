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

package file_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/axonops/audit/file"
)

func ExampleNew() {
	// Create a file output with rotation for production use.
	dir, err := os.MkdirTemp("", "audit-example-*")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	out, err := file.New(&file.Config{
		Path:       filepath.Join(dir, "audit.log"),
		MaxSizeMB:  100,
		MaxBackups: 5,
		MaxAgeDays: 30,
		// GroupReadable defaults to false (mode 0o600).
	})
	if err != nil {
		fmt.Println("create error:", err)
		return
	}
	defer func() { _ = out.Close() }()

	fmt.Println("file output created")
	// Output: file output created
}
