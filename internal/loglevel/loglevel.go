package loglevel

import (
	"context"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Level int32

const (
	Debug Level = iota
	Info
	Warning
)

const (
	escalateFor    = 5 * time.Minute
	summaryEvery   = 10 * time.Minute
	summaryMaxTags = 12
)

var (
	mode atomic.Int32

	mu         sync.Mutex
	escalated  = map[string]time.Time{}
	suppressed = map[string]int{}
	lastValue  = map[string]string{}
	now        = time.Now
)

const modeAuto int32 = -1

func init() {
	mode.Store(modeAuto)
}

func Set(name string) error {
	switch name {
	case "", "auto":
		mode.Store(modeAuto)
	case "debug":
		mode.Store(int32(Debug))
	case "info":
		mode.Store(int32(Info))
	case "warning":
		mode.Store(int32(Warning))
	default:
		return fmt.Errorf("log_level: invalid value %q (must be auto, debug, info, or warning)", name)
	}
	return nil
}

func Current() string {
	switch m := mode.Load(); {
	case m == modeAuto:
		return "auto"
	case Level(m) == Debug:
		return "debug"
	case Level(m) == Info:
		return "info"
	default:
		return "warning"
	}
}

func Debugf(format string, args ...any) {
	logf(Debug, format, args...)
}

func Infof(format string, args ...any) {
	logf(Info, format, args...)
}

func Warnf(format string, args ...any) {
	logf(Warning, format, args...)
}

// Stepf logs at info when ok, and at warning otherwise.
func Stepf(ok bool, format string, args ...any) {
	if ok {
		Infof(format, args...)
		return
	}
	Warnf(format, args...)
}

// InfoOnChange logs at info when value differs from the last value seen for key, and at debug otherwise.
func InfoOnChange(key, value, format string, args ...any) {
	mu.Lock()
	changed := lastValue[key] != value
	lastValue[key] = value
	mu.Unlock()
	if changed {
		Infof(format, args...)
		return
	}
	Debugf(format, args...)
}

func logf(level Level, format string, args ...any) {
	m := mode.Load()
	if m != modeAuto {
		if level >= Level(m) {
			log.Printf(format, args...)
		}
		return
	}
	tag := tagOf(format)
	switch {
	case level == Warning:
		escalate(subsystem(tag))
		log.Printf(format, args...)
	case level == Info || isEscalated(subsystem(tag)):
		log.Printf(format, args...)
	default:
		count(tag)
	}
}

// tagOf returns the bracketed tag of a format string, e.g. "AGENT:TOKEN_ACQ" for "[AGENT:TOKEN_ACQ] ...".
func tagOf(format string) string {
	if !strings.HasPrefix(format, "[") {
		return ""
	}
	end := strings.IndexByte(format, ']')
	if end < 2 {
		return ""
	}
	return format[1:end]
}

func subsystem(tag string) string {
	sub, _, _ := strings.Cut(tag, ":")
	return sub
}

func escalate(tag string) {
	mu.Lock()
	escalated[tag] = now().Add(escalateFor)
	mu.Unlock()
}

func isEscalated(tag string) bool {
	mu.Lock()
	defer mu.Unlock()
	until, ok := escalated[tag]
	return ok && now().Before(until)
}

func count(tag string) {
	mu.Lock()
	suppressed[tag]++
	mu.Unlock()
}

// Summarize logs one line per summaryEvery listing suppressed routine messages. It runs only in auto mode.
func Summarize(ctx context.Context) {
	t := time.NewTicker(summaryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			flushSummary()
		}
	}
}

func flushSummary() {
	if mode.Load() != modeAuto {
		return
	}
	mu.Lock()
	counts := suppressed
	suppressed = map[string]int{}
	mu.Unlock()
	if len(counts) == 0 {
		return
	}
	tags := make([]string, 0, len(counts))
	for tag := range counts {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	var parts []string
	for i, tag := range tags {
		if i == summaryMaxTags {
			parts = append(parts, fmt.Sprintf("+%d more", len(tags)-summaryMaxTags))
			break
		}
		parts = append(parts, fmt.Sprintf("%s x%d", tag, counts[tag]))
	}
	log.Printf("[LOG:SUMMARY] routine messages in the last %s, not logged at auto: %s", summaryEvery, strings.Join(parts, ", "))
}
