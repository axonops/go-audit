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

import (
	"bytes"
	"context"
	"runtime"
	"time"
)

func (a *Auditor) drainLoop(ctx context.Context) {
	defer close(a.drainDone)
	defer a.logger.Load().Debug("audit: drain loop exiting")
	a.logger.Load().Debug("audit: drain loop started")
	for {
		select {
		case entry := <-a.ch:
			if entry != nil {
				a.processEntry(entry)
			}
		case <-ctx.Done():
			a.drainRemaining()
			return
		}
	}
}

// drainRemaining flushes any events left in the channel after the
// context is cancelled.
func (a *Auditor) drainRemaining() {
	for {
		select {
		case entry := <-a.ch:
			if entry != nil {
				a.processEntry(entry)
			}
		default:
			return
		}
	}
}

// processEntry fans out an audit entry to all matching outputs. Events
// are serialised once per unique Formatter; per-output routes are
// checked before delivery. Output failures are isolated.
func (a *Auditor) processEntry(entry *auditEntry) { //nolint:gocognit,gocyclo,cyclop // queue depth sampling adds 1 to baseline complexity
	// Sample queue depth every 64 events for metrics gauges.
	a.drainCount++
	if a.metrics != nil && a.drainCount%64 == 0 {
		a.metrics.RecordQueueDepth(len(a.ch), cap(a.ch))
	}

	// Format cache scoped to this processEntry call. Holds pool
	// leases for buffered formatters and a per-event post-field
	// scratch buffer. release() returns every lease to its pool;
	// declared above the pool-return defer so defers run LIFO with
	// release happening BEFORE auditEntry pool-put (#497).
	var fc formatCache

	// Defers execute LIFO. The pool return must happen after the
	// panic recovery, so it is declared first (executes last).
	defer func() {
		// Pool-return is suppressed for donated fields (#497): the
		// map belongs to the [FieldsDonor] caller, not the auditor's
		// fieldsPool. Returning a borrowed map would corrupt the
		// donor's view and risk double-Put on the same map.
		if !entry.donated {
			returnFieldsToPool(entry.fields)
		}
		entry.eventType = ""
		entry.fields = nil
		entry.donated = false
		auditEntryPool.Put(entry)
	}()
	// release() returns format-cache buffer leases and the post-field
	// scratch buffer. Runs after panic recovery and before
	// auditEntry pool-put.
	defer fc.release()
	defer func() {
		if r := recover(); r != nil {
			a.logger.Load().Error("audit: panic in processEntry",
				"event_type", entry.eventType,
				"panic", r)
			if a.metrics != nil {
				a.metrics.RecordSerializationError(entry.eventType)
			}
		}
	}()

	ts := time.Now()
	def := a.taxonomy.Events[entry.eventType]

	if len(def.Categories) == 0 {
		// Uncategorised event: single pass, no category context.
		a.deliverToOutputs(entry, "", ts, def, &fc)
		return
	}

	// Categorised event: deliver once per enabled category.
	// If EnableEvent was called, iterate ALL categories.
	// The atomic flag guards the sync.Map lookup on the hot path.
	eventForceEnabled := false
	if a.filter.hasEventOverrides.Load() {
		if override, ok := a.filter.eventOverrides.Load(entry.eventType); ok && override {
			eventForceEnabled = true
		}
	}

	// Format cache (fc above) is shared across category passes — the
	// formatted output is identical because ResolvedSeverity is a
	// single value per event, not per category.

	for _, category := range def.Categories {
		if !eventForceEnabled && !a.filter.isCategoryEnabled(category) {
			continue
		}
		a.deliverToOutputs(entry, category, ts, def, &fc)
	}
}

// deliverToOutputs fans out a single event to all matching outputs
// for a given category. An empty category means the event is
// uncategorised.
func (a *Auditor) deliverToOutputs(entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache) {
	severity := def.ResolvedSeverity()
	meta := EventMetadata{
		EventType: entry.eventType,
		Severity:  severity,
		Category:  category,
		Timestamp: ts,
	}

	for _, oe := range a.entries {
		a.deliverToOutput(oe, entry, category, ts, def, fc, meta)
	}
}

// deliverToOutput handles delivery to a single output with per-output
// panic recovery. A panic in one output's Write (or format/HMAC path)
// does not prevent delivery to subsequent outputs. This is critical
// for the fan-out guarantee: a buggy output must not take down the
// entire delivery pipeline.
func (a *Auditor) deliverToOutput(oe *outputEntry, entry *auditEntry, category string, ts time.Time, def *EventDef, fc *formatCache, meta EventMetadata) { //nolint:gocyclo,gocognit,cyclop // per-output delivery with panic recovery
	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			a.logger.Load().Error("audit: panic in output write",
				"output", oe.output.Name(),
				"event_type", entry.eventType,
				"panic", r,
				"stack", string(buf[:n]))
			// Always record the panic in core metrics, even for
			// DeliveryReporter outputs — the output clearly did not
			// self-report if it panicked.
			if a.metrics != nil {
				a.metrics.RecordOutputError(oe.output.Name())
			}
		}
	}()

	if !oe.matchesEvent(entry.eventType, category, meta.Severity) {
		if a.metrics != nil {
			a.metrics.RecordOutputFiltered(oe.output.Name())
		}
		return
	}

	var data []byte
	if oe.formatOpts != nil && def.FieldLabels != nil {
		// Per-output sensitivity-label exclusion: bypasses the format
		// cache entirely (each output produces unique bytes) and does
		// not flow through the leased-buffer fast path. Stays on the
		// public Format path with defensive copy — see security review
		// of #497.
		data = a.formatWithExclusion(oe, entry, ts, def)
	} else {
		data = a.formatCached(oe, entry, ts, def, fc)
	}
	if data == nil {
		return
	}

	fmtr := oe.effectiveFormatter(a.formatter)
	needsCategory := category != "" && !a.taxonomy.SuppressEventCategory
	needsHMAC := oe.hmac != nil

	// HMAC ordering invariant: the HMAC tag (_hmac) is the LAST field
	// on the wire and is computed over every byte that precedes it,
	// including event_category and _hmac_version. Any future post-field
	// MUST be appended before computeHMACFast; appending after _hmac
	// would leave the new field outside the authenticated region —
	// same class of bug as issue #473. The buffer holding `data` MUST
	// NOT be returned to any pool until output.Write(data) has
	// returned; this is enforced by formatCache.release() running in
	// processEntry's defer chain only AFTER deliverToOutputs has
	// returned for every output and category pass (#497).
	if needsCategory || needsHMAC {
		data = a.assemblePostFields(fc, data, fmtr, category, oe, needsCategory, needsHMAC)
	}

	var writeErr error
	if oe.metadataWriter != nil {
		writeErr = oe.metadataWriter.WriteWithMetadata(data, meta)
	} else {
		writeErr = oe.output.Write(data)
	}
	a.recordWrite(oe.output.Name(), entry.eventType, oe.selfReports, writeErr)
}

// assemblePostFields builds the per-output wire bytes from the cached
// formatter output plus event_category and HMAC fields, using the
// per-event post-field scratch buffer owned by [formatCache]. The
// returned slice aliases the scratch buffer and is valid only until
// the next assemblePostFields call on the same fc.
//
// # Append ordering and the HMAC authenticated region
//
// The HMAC tag (_hmac) is the LAST field on the wire and MUST NOT
// cover itself. Every other post-field — currently event_category
// and _hmac_version (JSON) / _hmacVersion (CEF) — MUST be inside the
// authenticated region so an
// attacker cannot swap a salt version or inject a category label
// without invalidating the HMAC. See issue #473 for the regression
// class this invariant defends against.
//
// Concretely:
//
//  1. Collect every "inside the authenticated region" post-field
//     into preHMAC (currently event_category and _hmac_version;
//     order within the batch matches the intended wire order).
//  2. Append them in ONE batch call ([appendPostFieldsInto] for
//     n == 2, [appendPostFieldInto] for n == 1) — saves one
//     terminator rewind / restore cycle vs two sequential calls.
//  3. Compute the HMAC over everything written so far
//     (oe.hmac.computeHMACFast(data)).
//  4. Append _hmac as a SEPARATE [appendPostFieldInto] call. This
//     call runs AFTER computeHMACFast and the value it writes is
//     outside the authenticated region, as required.
//
// Any future post-field that must be authenticated MUST be added
// to the preHMAC batch in step 1. Appending it after step 3 would
// leave it outside the authenticated region — the same regression
// class as #473.
func (a *Auditor) assemblePostFields(fc *formatCache, base []byte, fmtr Formatter, category string, oe *outputEntry, needsCategory, needsHMAC bool) []byte {
	pb := fc.borrowPostBuf()
	pb.Write(base)
	data := pb.Bytes()

	// preHMAC holds every post-field that must fall inside the
	// authenticated region. Stack-allocated: no per-event alloc.
	// See #508 for the consolidation rationale and #473 for the
	// ordering invariant this batch enforces.
	var preHMAC [2]PostField
	n := 0
	if needsCategory {
		preHMAC[n] = PostField{JSONKey: "event_category", CEFKey: "cat", Value: category}
		n++
	}
	if needsHMAC {
		preHMAC[n] = PostField{JSONKey: "_hmac_version", CEFKey: "_hmacVersion", Value: oe.hmacConfig.Salt.Version}
		n++
	}
	switch n {
	case 1:
		data = appendPostFieldInto(pb, fmtr, preHMAC[0])
	case 2:
		data = appendPostFieldsInto(pb, fmtr, preHMAC[:2])
	}

	if needsHMAC {
		hmacHex := oe.hmac.computeHMACFast(data)
		data = appendPostFieldInto(pb, fmtr, PostField{
			JSONKey: "_hmac", CEFKey: "_hmac", Value: string(hmacHex),
		})
	}
	return data
}

// prepareOutputEntries caches interface assertions and pre-constructs
// per-output state (MetadataWriter, DeliveryReporter, FormatOptions,
// HMAC). Called once at construction time after all options are applied.
func (a *Auditor) prepareOutputEntries() {
	for _, oe := range a.entries {
		if mw, ok := oe.output.(MetadataWriter); ok {
			oe.metadataWriter = mw
		}
		if dr, ok := oe.output.(DeliveryReporter); ok {
			oe.selfReports = dr.ReportsDelivery()
		}
		if oe.excludedLabels != nil {
			oe.formatOpts = &FormatOptions{
				ExcludedLabels: oe.excludedLabels,
			}
		}
		if oe.hmacConfig != nil && oe.hmacConfig.Enabled {
			oe.hmac = newHMACState(oe.hmacConfig)
		}
	}
}

// propagateFrameworkFields propagates auditor-wide framework
// metadata to all formatters that implement [FrameworkFieldSetter].
// Outputs receive framework fields at construction via
// [FrameworkContext]; this propagation only covers formatters.
func (a *Auditor) propagateFrameworkFields() {
	set := func(f Formatter) {
		if setter, ok := f.(FrameworkFieldSetter); ok {
			setter.SetFrameworkFields(a.appName, a.host, a.timezone, a.pid)
		}
	}
	set(a.formatter)
	for _, oe := range a.entries {
		if oe.formatter != nil {
			set(oe.formatter)
		}
	}
}

// propagateContentTypes informs each output that implements
// [ContentTypeSetter] of the MIME type of the bytes its effective
// formatter emits. Called once at auditor construction, after
// [propagateFrameworkFields], before any event is dispatched.
//
// HTTP-based outputs (notably [webhook.Output]) use the value to
// populate the request Content-Type header so receivers can
// correctly parse CEF text vs. JSON streams. Outputs that don't
// care (file, stdout, syslog, Loki) simply omit the interface and
// are skipped.
//
// The webhook's batchLoop may already be running when this
// propagation fires; implementations MUST use atomic/synchronised
// storage for the field per the contract on [ContentTypeSetter].
func (a *Auditor) propagateContentTypes() {
	for _, oe := range a.entries {
		setter, ok := oe.output.(ContentTypeSetter)
		if !ok {
			continue
		}
		f := oe.effectiveFormatter(a.formatter)
		if f == nil {
			continue
		}
		setter.SetContentType(f.ContentType())
	}
}

// formatWithExclusion serialises an event with sensitivity-labelled
// fields excluded. It bypasses the format cache because different
// outputs may exclude different label sets.
func (a *Auditor) formatWithExclusion(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef) []byte {
	// Safe: drain loop is single-goroutine. FieldLabels is read-only
	// after taxonomy registration; we assign the pointer per-event
	// to avoid allocating a new FormatOptions on every call.
	oe.formatOpts.FieldLabels = def.FieldLabels
	f := oe.effectiveFormatter(a.formatter)
	data, err := f.Format(ts, entry.eventType, entry.fields, def, oe.formatOpts)
	if err != nil {
		a.logger.Load().Error("audit: format error (filtered)", "event", entry.eventType, "output", oe.output.Name(), "error", err)
		if a.metrics != nil {
			a.metrics.RecordSerializationError(entry.eventType)
		}
		return nil
	}
	return data
}

// formatCacheSize is the number of unique formatters cached in the
// fixed-size array on the [formatCache] stack frame before the
// overflow map is allocated.
//
// 8 covers realistic deployments: one distinct formatter per output,
// with typical fan-out of 4-8 outputs (stdout + file + syslog +
// webhook + loki + secondary file + archive + stderr). Each entry is
// ~48 bytes, so the array is 384 bytes at this size — comfortably
// within the per-function stack budget. Escape analysis keeps `var
// fc formatCache` stack-allocated (verified before/after the bump
// via `go build -gcflags='-m=2'`).
//
// Beyond 8 formatters the linear scan in [formatCache.get] is still
// cheaper than a map lookup (8 pointer-equality compares span ~6
// cache lines; a map lookup hashes the interface header and walks a
// bucket chain). The overflow map remains as a correctness safety
// net at higher cardinality, not as the performance-optimal path.
//
// See #499 for the rationale behind the specific bound and the
// benchmark evidence (BenchmarkAudit_FanOut_5DistinctFormatters and
// BenchmarkAudit_FanOut_8DistinctFormatters — both 0 allocs/op).
const formatCacheSize = 8

// formatCacheEntry pairs a formatter with its serialised output and,
// for [bufferedFormatter] fast-path entries, the leased buffer that
// backs the data slice. owned is non-nil only when data aliases the
// leased buffer's bytes — releaseFormatBuf MUST be called on it
// before the buffer goes back to its pool (#497).
type formatCacheEntry struct { //nolint:govet // fieldalignment: readability over packing for a 3-field hot-path value
	f     Formatter
	data  []byte
	owned *bytes.Buffer // pool lease; nil for non-buffered formatters or cache misses
}

// formatCache caches serialised output per unique formatter for the
// duration of a single [Auditor.processEntry] call. For deployments
// with <= 8 unique formatters (see [formatCacheSize]; the vast
// majority), the array is stack-allocated. Falls back to a heap map
// for larger counts.
//
// The cache also owns the per-event "post-field scratch" buffer
// (postBuf). When an output requires post-fields (event_category +
// HMAC), the drain assembles the final wire bytes into postBuf rather
// than mutating the cached format buffer (which is shared across
// outputs and across category passes). postBuf is reset between
// outputs so its backing array is amortised across the whole event.
//
// release returns every leased buffer to its pool. It is called from
// [Auditor.processEntry]'s defer, after every [Output.Write] for the
// event has returned.
type formatCache struct {
	m       map[Formatter]formatCacheEntry // overflow; nil until needed
	postBuf *bytes.Buffer                  // per-event post-field scratch; nil until first use
	arr     [formatCacheSize]formatCacheEntry
	n       int
}

func (c *formatCache) get(f Formatter) ([]byte, bool) {
	for i := range c.n {
		if c.arr[i].f == f {
			return c.arr[i].data, true
		}
	}
	if c.m != nil {
		e, ok := c.m[f]
		return e.data, ok
	}
	return nil, false
}

func (c *formatCache) put(f Formatter, data []byte, owned *bytes.Buffer) {
	if c.n < formatCacheSize {
		c.arr[c.n] = formatCacheEntry{f: f, data: data, owned: owned}
		c.n++
		return
	}
	if c.m == nil {
		c.m = make(map[Formatter]formatCacheEntry)
	}
	c.m[f] = formatCacheEntry{f: f, data: data, owned: owned}
}

// release returns every leased buffer (format-cache entries plus
// postBuf) to its formatter's pool. Must be called from
// [Auditor.processEntry]'s defer chain after every Output.Write has
// returned for the event.
func (c *formatCache) release() {
	for i := 0; i < c.n; i++ {
		releaseFormatCacheEntry(c.arr[i])
		c.arr[i] = formatCacheEntry{}
	}
	c.n = 0
	for f, e := range c.m {
		releaseFormatCacheEntry(formatCacheEntry{f: f, owned: e.owned})
	}
	c.m = nil
	if c.postBuf != nil {
		putJSONBuf(c.postBuf)
		c.postBuf = nil
	}
}

// releaseFormatCacheEntry returns the entry's leased buffer (if any)
// to its formatter's pool.
func releaseFormatCacheEntry(e formatCacheEntry) {
	if e.owned == nil {
		return
	}
	if bf, ok := e.f.(bufferedFormatter); ok {
		bf.releaseFormatBuf(e.owned)
	}
}

// borrowPostBuf returns the per-event post-field scratch buffer,
// resetting it for the caller. The buffer is leased on first use and
// reused across subsequent outputs in the same processEntry call;
// formatCache.release returns it to the pool.
func (c *formatCache) borrowPostBuf() *bytes.Buffer {
	if c.postBuf == nil {
		buf, ok := jsonBufPool.Get().(*bytes.Buffer)
		if !ok {
			buf = new(bytes.Buffer)
		}
		c.postBuf = buf
	}
	c.postBuf.Reset()
	return c.postBuf
}

// formatCached returns the serialised bytes for the output's formatter,
// using the cache to avoid redundant serialisation. When the formatter
// implements [bufferedFormatter], the cached bytes alias the leased
// buffer and the cache.release defer returns it to the pool. Returns
// nil if serialisation failed.
func (a *Auditor) formatCached(oe *outputEntry, entry *auditEntry, ts time.Time, def *EventDef, cache *formatCache) []byte {
	f := oe.effectiveFormatter(a.formatter)
	if data, ok := cache.get(f); ok {
		return data // may be nil if serialisation failed
	}
	if bf, ok := f.(bufferedFormatter); ok {
		buf, err := bf.formatBuf(ts, entry.eventType, entry.fields, def, nil)
		if err != nil {
			a.logger.Load().Error("audit: serialisation failed",
				"event_type", entry.eventType,
				"error", err)
			if a.metrics != nil {
				a.metrics.RecordSerializationError(entry.eventType)
			}
			cache.put(f, nil, nil)
			return nil
		}
		cache.put(f, buf.Bytes(), buf)
		return buf.Bytes()
	}
	// Third-party formatter — public Format path with defensive copy.
	data, err := f.Format(ts, entry.eventType, entry.fields, def, nil)
	if err != nil {
		a.logger.Load().Error("audit: serialisation failed",
			"event_type", entry.eventType,
			"error", err)
		if a.metrics != nil {
			a.metrics.RecordSerializationError(entry.eventType)
		}
		cache.put(f, nil, nil)
		return nil
	}
	cache.put(f, data, nil)
	return data
}

// recordWrite handles post-write metrics and error logging for both
// the plain Write and MetadataWriter paths. Called once per output per
// event with the result of the write call. No closures, no interface
// dispatch — all parameters are concrete values.
func (a *Auditor) recordWrite(outputName, eventType string, selfReports bool, writeErr error) {
	if writeErr != nil {
		a.logger.Load().Error("audit: output write failed",
			"output", outputName,
			"event_type", eventType,
			"error", writeErr)
		if a.metrics != nil && !selfReports {
			a.metrics.RecordOutputError(outputName)
			a.metrics.RecordDelivery(outputName, EventError)
		}
		return
	}
	if a.metrics != nil && !selfReports {
		a.metrics.RecordDelivery(outputName, EventSuccess)
	}
}
