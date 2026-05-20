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
	"fmt"
	"io"
	"net/http"

	"github.com/axonops/audit"
)

// ssrfOptsFromConfig builds the [audit.SSRFOption] slice from the
// config. Mirrors loki/probe.go:146-152 and webhook/probe.go: an
// `AllowPrivateRanges` config knob (false by default) opts into the
// permissive mode for tests and dev networks.
func ssrfOptsFromConfig(cfg *Config) []audit.SSRFOption {
	var opts []audit.SSRFOption
	if cfg.AllowPrivateRanges {
		opts = append(opts, audit.AllowPrivateRanges())
	}
	return opts
}

// probeEndpoint performs the startup health check against the HEC
// `/services/collector/health` endpoint. Returns nil on HTTP 200 with
// the documented `{"text":"HEC is healthy","code":17}` body shape;
// returns a wrapped [ErrHealthCheckFailed] otherwise.
//
// **The health endpoint does NOT validate the token.** It confirms
// reachability and overall HEC service health only. Token validity
// is verified by the first real send via the HEC error code on the
// response.
func (o *Output) probeEndpoint(ctx context.Context) error {
	healthURL, err := joinHealthURL(o.cfg.URL)
	if err != nil {
		return fmt.Errorf("%w: build health URL: %v", ErrHealthCheckFailed, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
	if err != nil {
		return fmt.Errorf("%w: build request: %v", ErrHealthCheckFailed, err)
	}
	req.Header.Set("User-Agent", o.cfg.UserAgent)
	resp, err := o.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %s: %v",
			ErrHealthCheckFailed,
			sanitizeURLForLog(o.cfg.URL),
			err,
		)
	}
	defer drainAndClose(resp, maxResponseDrainHealth)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseDrainHealth))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: %s returned HTTP %d: %s",
			ErrHealthCheckFailed,
			sanitizeURLForLog(o.cfg.URL),
			resp.StatusCode,
			sanitizeText(string(body)),
		)
	}
	// Defence-in-depth: reject HTTP 200 from an endpoint that doesn't
	// look like HEC (e.g. a misconfigured reverse proxy returning an
	// HTML 200). The documented healthy body carries HEC code 17;
	// older versions return code 0. Anything else means the URL is
	// not pointing at HEC.
	hecCode, _ := parseHECCode(body)
	if hecCode != 0 && hecCode != 17 {
		return fmt.Errorf("%w: %s returned HTTP 200 with unexpected HEC code %d (body: %s) — verify URL points at /services/collector/health",
			ErrHealthCheckFailed,
			sanitizeURLForLog(o.cfg.URL),
			hecCode,
			sanitizeText(string(body)),
		)
	}
	return nil
}
