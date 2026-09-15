// Package procs implements the framework guide's §11 performance
// requirement: "GOMAXPROCS: set explicitly to match the container's CPU
// quota (use go.uber.org/automaxprocs so it respects cgroup limits
// automatically)".
//
// Deviation from the framework guide: go.uber.org/automaxprocs is not
// fetchable in this build environment. This is a small, hand-rolled
// equivalent covering the common case — a single CPU quota read from
// either cgroup v1 (two files) or cgroup v2 (one file) — not the full
// package's edge-case handling (cgroup namespaces, multiple controller
// mount points, container runtimes that expose cgroups unusually).
//
// Verification note: CGroupCPULimit's "no limit imposed" path was
// checked against this project's own build sandbox, which genuinely
// runs under cgroup v1 with cpu.cfs_quota_us == -1 (unlimited) — a real
// cgroup filesystem, not a simulated one. The "a positive quota is
// actually set" path (the case that matters most, e.g. a Kubernetes pod
// with CPU limits configured) was verified against synthetic files
// matching the real kernel documentation's format, since this sandbox's
// own cgroup has no quota applied. Both cgroup v1 and v2 branches were
// checked this way before this file was written, not after.
package procs

import (
	"context"
	"log/slog"
	"math"
	"os"
	"runtime"
	"strconv"
	"strings"
)

const (
	cgroupV2CPUMaxPath = "/sys/fs/cgroup/cpu.max"
	cgroupV1QuotaPath  = "/sys/fs/cgroup/cpu/cpu.cfs_quota_us"
	cgroupV1PeriodPath = "/sys/fs/cgroup/cpu/cpu.cfs_period_us"
)

// CGroupCPULimit returns the number of CPUs this process's cgroup is
// allowed to use, or ok=false if no limit is imposed — an unlimited
// quota (-1 under v1, "max" under v2) is reported as ok=false, not as
// some sentinel limit, so callers unconditionally fall back to
// runtime.NumCPU() in that case rather than needing to special-case it
// themselves.
func CGroupCPULimit() (limit float64, ok bool) {
	if data, err := os.ReadFile(cgroupV2CPUMaxPath); err == nil {
		return parseCGroupV2(string(data))
	}
	return parseCGroupV1()
}

func parseCGroupV2(data string) (float64, bool) {
	fields := strings.Fields(strings.TrimSpace(data))
	if len(fields) != 2 || fields[0] == "max" {
		return 0, false
	}
	quota, err1 := strconv.ParseFloat(fields[0], 64)
	period, err2 := strconv.ParseFloat(fields[1], 64)
	if err1 != nil || err2 != nil || period <= 0 || quota <= 0 {
		return 0, false
	}
	return quota / period, true
}

func parseCGroupV1() (float64, bool) {
	quotaData, err1 := os.ReadFile(cgroupV1QuotaPath)
	periodData, err2 := os.ReadFile(cgroupV1PeriodPath)
	if err1 != nil || err2 != nil {
		return 0, false
	}
	quota, err1 := strconv.ParseFloat(strings.TrimSpace(string(quotaData)), 64)
	period, err2 := strconv.ParseFloat(strings.TrimSpace(string(periodData)), 64)
	if err1 != nil || err2 != nil || quota <= 0 || period <= 0 {
		return 0, false // quota == -1 is cgroup v1's "unlimited"
	}
	return quota / period, true
}

// SetGOMAXPROCS sets runtime.GOMAXPROCS to the cgroup CPU limit
// (rounded up, minimum 1) if one is imposed; otherwise it leaves the
// runtime's own default (NumCPU()) untouched. Returns whatever
// GOMAXPROCS ends up being, purely so the caller can log it. Call this
// once, early in process startup (framework guide §11).
func SetGOMAXPROCS(logger *slog.Logger) int {
	limit, ok := CGroupCPULimit()
	if !ok {
		n := runtime.GOMAXPROCS(0)
		logger.LogAttrs(context.Background(), slog.LevelInfo, "gomaxprocs: no cgroup CPU limit detected, using runtime default",
			slog.Int("gomaxprocs", n))
		return n
	}

	n := int(math.Ceil(limit))
	if n < 1 {
		n = 1
	}
	runtime.GOMAXPROCS(n)
	logger.LogAttrs(context.Background(), slog.LevelInfo, "gomaxprocs: set from cgroup CPU limit",
		slog.Float64("cpu_limit", limit), slog.Int("gomaxprocs", n))
	return n
}
