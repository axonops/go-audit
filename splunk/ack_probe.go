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

package splunk

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// ackFeatureProbe sends a single synthetic event to /event with the
// channel header (via the just-wired tracker). Returns nil when HEC
// responds with a non-nil ackID. Returns ErrAckDisabled (wrapped)
// when HEC responds with code 14 ("ACK is disabled"); returns any
// underlying error otherwise.
//
// The synthetic event is a `{"event":"audit-splunk channel probe",
// "_ack_probe":1}` envelope. It is intentionally a real event so an
// operator browsing the Splunk index can see one row per process
// start — the marker field `_ack_probe:1` filters them out of normal
// dashboards.
//
// Called from New() AFTER the /health probe has succeeded and AFTER
// the tracker has been wired (so applyRequestHeaders attaches the
// channel header).
func (o *Output) ackFeatureProbe(ctx context.Context) error {
	if o.tracker == nil {
		return errors.New("audit/splunk: ackFeatureProbe called with nil tracker (internal error)")
	}

	probeEvent := []byte(`{"event_type":"_ack_probe","timestamp":"` + time.Now().UTC().Format(time.RFC3339Nano) + `","_ack_probe":1}`)

	// Wrap into the /event envelope (the probe always uses /event,
	// even when the consumer configured /raw — the /raw endpoint
	// doesn't support ACK feature detection because the response
	// envelope is different).
	o.batchBufs.envelope.Reset()
	if _, err := wrapEvent(&o.batchBufs.envelope, o.cfg, probeEvent, time.Now()); err != nil {
		return fmt.Errorf("audit/splunk: ack probe wrap: %w", err)
	}
	payload := o.batchBufs.envelope.Bytes()

	action, status, hecCode, ackID, postErr := o.doPost(ctx, payload, false, o.batchBufs)
	o.batchBufs.retryHint = 0
	if action == actionAckDisabled || hecCode == 14 {
		return fmt.Errorf("%w (HTTP %d, HEC code %d)", ErrAckDisabled, status, hecCode)
	}
	if postErr != nil {
		return fmt.Errorf("audit/splunk: ack probe: %w", postErr)
	}
	if ackID == nil {
		// HEC responded with 200 but no ackID — token must have ACK
		// silently disabled on the channel.
		return fmt.Errorf("%w (HEC returned no ackId)", ErrAckDisabled)
	}
	// Register the probe so the poll loop confirms it; the synthetic
	// event is treated like any other in-flight batch.
	o.tracker.register(*ackID, nil)
	return nil
}
