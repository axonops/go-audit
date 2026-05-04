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

package file

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/axonops/audit"
	"github.com/axonops/audit/file/internal/rotate"
)

// Compile-time assertions.
var (
	_ audit.Output           = (*Output)(nil)
	_ audit.DestinationKeyer = (*Output)(nil)
	_ audit.DeliveryReporter = (*Output)(nil)
)

const (
	// MaxSizeMB is the maximum allowed value for [Config.MaxSizeMB].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxSizeMB = 10_240 // 10 GB

	// MaxBackups is the maximum allowed value for [Config.MaxBackups].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxBackups = 100

	// MaxAgeDays is the maximum allowed value for [Config.MaxAgeDays].
	// Values above this limit cause [New] to return an error
	// wrapping [audit.ErrConfigInvalid].
	MaxAgeDays = 365

	// DefaultBufferSize is the default async buffer capacity for the
	// file output. Matches the default for webhook and loki outputs
	// to provide consistent behaviour across all async outputs.
	DefaultBufferSize = 10_000

	// MaxOutputBufferSize is the maximum allowed per-output async
	// buffer capacity. Values above this limit cause [New] to return
	// an error wrapping [audit.ErrConfigInvalid].
	MaxOutputBufferSize = 100_000
)

// RotationRecorder is an OPTIONAL extension interface for file-output
// rotation telemetry. A consumer's [audit.OutputMetrics] implementation
// MAY also implement RotationRecorder. When the file output receives
// per-output metrics via [WithOutputMetrics] (or factory wiring via
// outputconfig.WithOutputMetricsFactory), it type-asserts for
// RotationRecorder and invokes RecordRotation on every log-file
// rotation. Precedent: [net/http.Flusher] as an optional extension
// on [http.ResponseWriter].
//
// Consumers who do not care about rotation telemetry need not
// implement this interface — the base [audit.OutputMetrics] contract
// is sufficient.
type RotationRecorder interface {
	// RecordRotation records that the file output rotated its active
	// log file. path is the absolute filesystem path of the file that
	// was rotated. Implementations SHOULD NOT use path as an unbounded
	// metric label — it may expose infrastructure topology and cause
	// cardinality explosion.
	RecordRotation(path string)
}

// Config holds configuration for [Output].
//
//nolint:govet // field order: logical grouping (required, then optional, then pointer)
type Config struct {
	// Path is the filesystem path for the audit log file. REQUIRED.
	// Relative paths are resolved to absolute at construction time.
	// The parent directory must exist when [New] is called.
	Path string

	// GroupReadable, when false (the default), creates files readable
	// only by the owning user (mode 0o600) — the recommended setting
	// for audit logs. Set true to also allow read access by the file's
	// group (mode 0o640), used when a SIEM forwarder (Filebeat,
	// Promtail, Fluentd) runs as a separate user in the file's group.
	//
	// No other modes are supported. World-readable or group-writable
	// audit logs are a security defect: audit data may contain PII,
	// credentials, or operational details, and the trail must be
	// append-only from a single writer to preserve tamper-detection.
	// SOX, HIPAA, and GDPR all require this constraint. Operators
	// needing finer-grained access should use ACLs at the OS level,
	// not relax the library's mode.
	//
	// At construction, if an existing audit log file's permissions are
	// broader than the configured target, [New] wraps
	// [audit.ErrConfigInvalid]; setuid/setgid/sticky bits or a
	// hardlink count above 1 are also rejected as tamper indicators.
	GroupReadable bool

	// MaxSizeMB is the maximum size in megabytes of a single log file
	// before rotation. Zero defaults to 100. Values above [MaxSizeMB]
	// (10,240 = 10 GB) cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	MaxSizeMB int

	// MaxBackups is the maximum number of rotated backup files to
	// retain. Zero defaults to 5. Values above [MaxBackups] (100)
	// cause [New] to return an error wrapping [audit.ErrConfigInvalid].
	MaxBackups int

	// MaxAgeDays is the maximum age in days of rotated backup files
	// before deletion. Zero defaults to 30. Values above [MaxAgeDays]
	// (365) cause [New] to return an error wrapping
	// [audit.ErrConfigInvalid].
	MaxAgeDays int

	// Compress enables gzip compression of rotated backup files.
	// When nil, defaults to true.
	Compress *bool

	// BufferSize is the internal async buffer capacity. When full,
	// new events are dropped and [audit.OutputMetrics.RecordDrop] is
	// called. Zero defaults to [DefaultBufferSize] (10,000). Values
	// above [MaxOutputBufferSize] (100,000) cause [New] to return an
	// error wrapping [audit.ErrConfigInvalid].
	BufferSize int
}

// dropWarnInterval is the minimum interval between slog.Warn calls
// for buffer-full drop events.
const dropWarnInterval = 10 * time.Second

// Output writes serialised audit events to a file with automatic
// size-based rotation. It supports backup retention, age-based cleanup,
// and optional gzip compression.
//
// Write enqueues events into an internal buffered channel and returns
// immediately. A background goroutine reads from the channel and
// performs the actual file I/O. If the channel is full, the event is
// dropped and metrics are recorded.
//
// Output is safe for concurrent use, including concurrent calls
// to [Output.Write] and [Output.Close].
type Output struct {
	writer           *rotate.Writer
	logger           *slog.Logger        // diagnostic logger; immutable after New (#696)
	outputMetrics    audit.OutputMetrics // immutable after New (#696)
	rotationRecorder RotationRecorder    // optional; nil when outputMetrics does not implement it
	ch               chan []byte
	closeCh          chan struct{}
	done             chan struct{}
	name             string
	path             string
	writeCount       uint64
	// lastDeliveryNanos is the wall-clock UnixNano of the most recent
	// successful flush from writeLoop (#753). Async output: Write
	// just enqueues; this timestamp tracks actual disk writes so
	// [audit.Auditor.LastDeliveryAge] surfaces silently-failing
	// outputs whose channel keeps draining via drops.
	lastDeliveryNanos atomic.Int64
	drops             dropLimiter
	closed            atomic.Bool
	mu                sync.Mutex
}

// resolvePath normalises the path to an absolute form, resolving
// symlinks in the parent directory when possible. Falls back to
// filepath.Abs if symlink resolution fails (e.g. parent doesn't exist).
func resolvePath(path string) (string, error) {
	resolved, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err == nil {
		return filepath.Join(resolved, filepath.Base(path)), nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("audit/file: output path: %w", err)
	}
	return abs, nil
}

// New creates a new [Output] from the given config. It validates the
// path, permissions, and parent directory existence, then starts a
// background goroutine for async event delivery.
//
// Per-output metrics may be supplied at construction via
// [WithOutputMetrics]. When omitted, telemetry calls become no-ops.
//
// Callers MUST NOT mutate cfg.Compress via the pointer after New
// returns — the defensive copy is shallow, so caller and Output share
// the same *bool. Mutating other fields after New is safe; they are
// copied by value.
func New(cfg *Config, opts ...Option) (*Output, error) { //nolint:gocyclo,cyclop // constructor with validation
	if cfg == nil {
		return nil, fmt.Errorf("audit/file: config must not be nil")
	}
	// Copy config so validation/defaults don't mutate the caller's struct.
	cfgCopy := *cfg
	cfg = &cfgCopy

	o := resolveOptions(opts)
	logger := o.logger

	if cfg.Path == "" {
		return nil, fmt.Errorf("audit/file: output path must not be empty")
	}
	var err error
	cfg.Path, err = resolvePath(cfg.Path)
	if err != nil {
		return nil, err
	}

	// Check parent directory exists early to provide a clear "audit:" error
	// message. rotate.New performs the same check but with a "rotate:" prefix.
	parentDir := filepath.Dir(cfg.Path)
	if _, statErr := os.Lstat(parentDir); statErr != nil {
		return nil, fmt.Errorf("audit/file: output parent directory %q: %w", parentDir, statErr)
	}

	perm := targetMode(cfg.GroupReadable)

	// Reject existing audit log files whose permissions, special
	// bits, or hardlink count signal tampering. Skipped on non-Unix
	// platforms (see existing_perms_check_*.go) because os.FileMode
	// semantics there don't map to the POSIX bits we enforce.
	if validErr := validateExistingFilePerms(cfg.Path, perm); validErr != nil {
		return nil, validErr
	}

	applyFileDefaults(cfg)
	if validErr := validateFileLimits(cfg); validErr != nil {
		return nil, validErr
	}

	compress := true
	if cfg.Compress != nil {
		compress = *cfg.Compress
	}

	out := &Output{
		path:          cfg.Path,
		name:          "file:" + cfg.Path,
		ch:            make(chan []byte, cfg.BufferSize),
		closeCh:       make(chan struct{}),
		done:          make(chan struct{}),
		logger:        logger,
		outputMetrics: o.outputMetrics,
	}
	// Detect optional RotationRecorder via structural typing.
	if rr, ok := o.outputMetrics.(RotationRecorder); ok {
		out.rotationRecorder = rr
	}

	logPath := cfg.Path // capture for closure
	rotCfg := rotate.Config{
		MaxSize:    int64(cfg.MaxSizeMB) * 1024 * 1024,
		MaxAge:     time.Duration(cfg.MaxAgeDays) * 24 * time.Hour,
		Mode:       perm,
		MaxBackups: cfg.MaxBackups,
		Compress:   compress,
		OnError: func(err error) {
			out.logger.Warn("audit/file: output background error",
				"path", logPath, "error", err)
		},
	}
	// Install OnRotate when a recorder is wired at construction.
	if out.rotationRecorder != nil {
		rr := out.rotationRecorder
		rotCfg.OnRotate = func(path string) { rr.RecordRotation(path) }
	}
	rw, err := rotate.New(cfg.Path, rotCfg)
	if err != nil {
		return nil, fmt.Errorf("audit/file: output: %w", err)
	}
	out.writer = rw

	go out.writeLoop()
	return out, nil
}

// Write enqueues a serialised audit event for async delivery to the
// file. The data is copied before enqueuing — the caller may reuse
// the backing array after Write returns. If the internal buffer is
// full, the event is dropped and [audit.OutputMetrics.RecordDrop] is
// called. Write never blocks the caller.
func (f *Output) Write(data []byte) error {
	if f.closed.Load() {
		return audit.ErrOutputClosed
	}

	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case f.ch <- cp:
		return nil
	default:
		f.drops.record(dropWarnInterval, func(dropped int64) {
			f.logger.Warn("audit: output file: event dropped (buffer full)",
				"dropped", dropped,
				"buffer_size", cap(f.ch))
		})
		f.outputMetrics.RecordDrop()
		return nil // non-blocking — do not return error to drain goroutine
	}
}

// Close signals the background goroutine to drain the buffer and
// flush remaining events, then closes the underlying file writer.
// Close is idempotent and safe for concurrent use with [Output.Write].
func (f *Output) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Signal writeLoop to drain remaining events and exit.
	close(f.closeCh)

	// Wait for writeLoop to finish draining.
	shutdownTimeout := 10 * time.Second
	timer := time.NewTimer(shutdownTimeout)
	defer timer.Stop()

	select {
	case <-f.done:
	case <-timer.C:
		remaining := len(f.ch)
		f.logger.Error("audit: output file: shutdown timeout, events lost",
			"timeout", shutdownTimeout,
			"events_lost", remaining)
	}

	// Close the rotate.Writer AFTER the writeLoop exits to ensure all
	// drained events are written before the file is closed.
	if err := f.writer.Close(); err != nil {
		return fmt.Errorf("audit/file: output close: %w", err)
	}
	return nil
}

// ReportsDelivery returns true, indicating that Output reports its
// own delivery metrics from the background writeLoop after actual
// file I/O, not from the Write enqueue path.
func (f *Output) ReportsDelivery() bool { return true }

// maxBatch is the upper bound on events coalesced into a single
// Writev call. Sized to 256 per the #510 performance review: 1024
// is UIO_MAXIOV on Linux but most audit events are 200-500 bytes
// so 256 × 500 = 128 KiB per batch is generous without pinning
// the writeLoop inside the kernel for too long.
const maxBatch = 256

// writeLoop is the background goroutine that reads events from the
// channel and writes them to the rotate.Writer. It runs until closeCh
// is closed, then drains remaining events before returning.
//
// The loop coalesces events opportunistically: it blocks for the
// first event, then non-blockingly drains up to maxBatch-1 more,
// submitting them all as a single vectored write. No artificial
// latency — if only one event is pending, a single-iovec batch
// is submitted immediately.
func (f *Output) writeLoop() {
	defer close(f.done)

	batch := make([][]byte, 0, maxBatch)
	for {
		// Blocking pull for the first event.
		select {
		case data := <-f.ch:
			batch = append(batch[:0], data)
		case <-f.closeCh:
			f.drainRemaining()
			return
		}

		// Opportunistic non-blocking drain.
	drain:
		for len(batch) < maxBatch {
			select {
			case data := <-f.ch:
				batch = append(batch, data)
			default:
				break drain
			}
		}

		f.writeBatch(batch)
	}
}

// writeBatch writes a batch of events to the rotate.Writer as a
// single vectored write, with panic recovery and metrics
// recording. The whole batch shares one defer/recover — cheaper
// than per-event recovery — because a panic in writev is either
// per-batch (unlikely) or per-process (worse than unlikely).
func (f *Output) writeBatch(batch [][]byte) {
	logger := f.logger
	om := f.outputMetrics

	defer func() {
		if r := recover(); r != nil {
			buf := make([]byte, 4096)
			n := runtime.Stack(buf, false)
			logger.Error("audit: output file: panic recovered",
				"panic", r,
				"stack", string(buf[:n]))
			om.RecordError()
		}
	}()

	// Sample queue depth every batch. Since batching naturally
	// amortises metric calls (N events = 1 sample), there is no
	// need to sub-sample further — the per-batch cost is one
	// atomic increment plus one metric call.
	f.writeCount++
	om.RecordQueueDepth(len(f.ch), cap(f.ch))

	start := time.Now()
	if _, err := f.writer.Writev(batch); err != nil {
		logger.Error("audit: output file: delivery failed",
			"error", err, "batch_size", len(batch))
		om.RecordError()
		return
	}
	// Successful flush: record the delivery timestamp for #753
	// LastDeliveryReporter. Updated AFTER Writev returns nil so a
	// failing flush leaves the timestamp frozen.
	f.lastDeliveryNanos.Store(time.Now().UnixNano())
	om.RecordFlush(len(batch), time.Since(start))
}

// LastDeliveryNanos returns the wall-clock UnixNano of the most
// recent successful disk flush, or 0 if no flush has yet succeeded.
// Implements [audit.LastDeliveryReporter] (#753).
func (f *Output) LastDeliveryNanos() int64 {
	return f.lastDeliveryNanos.Load()
}

// drainRemaining reads all remaining events from the channel after
// closeCh fires and writes them to the file. Uses the same
// batch-coalescing shape as the steady-state writeLoop so shutdown
// amortises syscall cost too.
func (f *Output) drainRemaining() {
	batch := make([][]byte, 0, maxBatch)
	for {
		batch = batch[:0]
	fill:
		for len(batch) < maxBatch {
			select {
			case data := <-f.ch:
				batch = append(batch, data)
			default:
				break fill
			}
		}
		if len(batch) == 0 {
			return
		}
		f.writeBatch(batch)
	}
}

// Name returns the human-readable identifier for this output.
func (f *Output) Name() string {
	return f.name
}

// DestinationKey returns the absolute filesystem path,
// enabling duplicate destination detection via [audit.DestinationKeyer].
func (f *Output) DestinationKey() string {
	return f.path
}

// targetMode returns the file mode for an audit log output. The two
// supported modes are 0o600 (default; owner read/write only) and
// 0o640 (owner read/write, group read) — see [Config.GroupReadable].
func targetMode(groupReadable bool) os.FileMode {
	if groupReadable {
		return 0o640
	}
	return 0o600
}

// applyFileDefaults fills zero-valued rotation and buffer fields with defaults.
func applyFileDefaults(cfg *Config) {
	if cfg.MaxSizeMB <= 0 {
		cfg.MaxSizeMB = 100
	}
	if cfg.MaxBackups <= 0 {
		cfg.MaxBackups = 5
	}
	if cfg.MaxAgeDays <= 0 {
		cfg.MaxAgeDays = 30
	}
	if cfg.BufferSize <= 0 {
		cfg.BufferSize = DefaultBufferSize
	}
}

// validateFileLimits checks that rotation and buffer fields do not
// exceed their upper bounds.
func validateFileLimits(cfg *Config) error {
	if cfg.MaxSizeMB > MaxSizeMB {
		return fmt.Errorf("%w: max_size_mb %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxSizeMB, MaxSizeMB)
	}
	if cfg.MaxBackups > MaxBackups {
		return fmt.Errorf("%w: max_backups %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxBackups, MaxBackups)
	}
	if cfg.MaxAgeDays > MaxAgeDays {
		return fmt.Errorf("%w: max_age_days %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.MaxAgeDays, MaxAgeDays)
	}
	if cfg.BufferSize > MaxOutputBufferSize {
		return fmt.Errorf("%w: buffer_size %d exceeds maximum %d",
			audit.ErrConfigInvalid, cfg.BufferSize, MaxOutputBufferSize)
	}
	return nil
}
