// Copyright 2025 CompliK Authors
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

// Package processor provides functionality for analyzing system processes,
// detecting suspicious behavior based on configurable rules, and identifying
// container relationships for Kubernetes workloads.
package processor

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bearslyricattack/CompliK/procscan/internal/container"
	procscanrules "github.com/bearslyricattack/CompliK/procscan/internal/rules"
	legacy "github.com/bearslyricattack/CompliK/procscan/pkg/logger/legacy"
	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	"github.com/sirupsen/logrus"
)

type Processor struct {
	ProcPath string
	matcher  *procscanrules.Matcher
	revision uint64
	mu       sync.RWMutex
}

// NewProcessor creates a new processor instance with the given configuration
func NewProcessor(config *models.Config) *Processor {
	p := &Processor{ProcPath: config.Scanner.ProcPath}
	p.UpdateConfig(config)
	return p
}

// UpdateConfig updates the processor's detection rules from the new configuration
func (p *Processor) UpdateConfig(config *models.Config) error {
	var matcher *procscanrules.Matcher
	if config.ProcscanRules.RulesetRevision > 0 {
		compiled, err := procscanrules.Compile(config.ProcscanRules)
		if err != nil {
			return fmt.Errorf("compile procscan rules: %w", err)
		}
		matcher = compiled
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	p.matcher = matcher
	p.revision = config.ProcscanRules.RulesetRevision
	return nil
}

func (p *Processor) Ready() bool {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.matcher != nil && p.revision > 0
}

func (p *Processor) RulesetRevision() uint64 {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.revision
}

// GetAllProcesses returns a list of all process IDs from the proc filesystem
func (p *Processor) GetAllProcesses() ([]int, error) {
	procDirs, err := os.ReadDir(p.ProcPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s directory: %w", p.ProcPath, err)
	}

	pids := make([]int, 0, len(procDirs))
	for _, dir := range procDirs {
		if !dir.IsDir() {
			continue
		}

		pid, err := strconv.Atoi(dir.Name())
		if err != nil {
			continue
		}

		pids = append(pids, pid)
	}

	return pids, nil
}

// AnalyzeProcess returns process info for structured rule hits after exemption checks.
func (p *Processor) AnalyzeProcess(pid int) (*models.ProcessInfo, error) {
	procDir := filepath.Join(p.ProcPath, strconv.Itoa(pid))
	cmdlineFile := filepath.Join(procDir, "cmdline")

	cmdlineData, err := os.ReadFile(cmdlineFile)
	if err != nil {
		return nil, nil
	}

	cmdline := strings.ReplaceAll(string(cmdlineData), "\x00", " ")

	cmdline = strings.TrimSpace(cmdline)
	if cmdline == "" {
		return nil, nil
	}

	processName := p.getProcessName(cmdline)

	procLogger := legacy.L.WithFields(logrus.Fields{
		"pid":            pid,
		"process_name":   processName,
		"cmdline":        cmdline,
		"proc_dir":       procDir,
		"cmdline_length": len(cmdline),
	})
	procLogger.Debug("Starting process analysis,Process Info:")

	matchResult, revision, structured := p.matchStructured(procscanrules.Sample{
		ProcessName: processName,
		Command:     cmdline,
	})
	if !structured || matchResult == nil {
		if structured {
			procLogger.Debug("Process did not match an enabled rule or was exempted")
		}
		return nil, nil
	}
	message := fmt.Sprintf("process matched rule %q", matchResult.PrimaryRule.ID)

	procLogger.WithField("reason", message).Info("Process matched detection rule")

	// Step 3: Identify container main process
	mainProcessPID := pid

	processStatus, err := ReadProcessStatus(p.ProcPath, pid)
	if err != nil {
		procLogger.WithError(err).Debug("Failed to read process status, using current PID")
	} else {
		if IsContainerMainProcess(processStatus) {
			procLogger.WithField("main_process_pid", mainProcessPID).
				Info("Detected malicious process is container main process")
		} else {
			// Trace back to find container main process
			mainPID, err := FindContainerMainProcess(p.ProcPath, pid)
			if err != nil {
				procLogger.WithError(err).
					Debug("Failed to find container main process, continuing with current PID")
			} else {
				mainProcessPID = mainPID
				procLogger.WithFields(logrus.Fields{
					"malicious_pid":    pid,
					"main_process_pid": mainProcessPID,
				}).Info("Traced malicious process to container main process")
			}
		}
	}

	// Step 4: Get container ID
	containerID := p.getContainerIDFromPID(mainProcessPID)

	// Step 5: Query container info on-demand when container metadata is available.
	var podName, namespace, podUID string
	attributionStatus := "resolved"
	attributionReason := ""
	if containerID == "" {
		attributionStatus = "unresolved"
		attributionReason = "container_id_missing"
		procLogger.WithFields(logrus.Fields{
			"container_metadata_degraded": true,
			"container_metadata_reason":   "container_id_missing",
			"main_process_pid":            mainProcessPID,
		}).Warn("Unable to determine container ID, continue alerting without container metadata")
	} else {
		podName, namespace, podUID, err = container.GetContainerInfo(containerID)
		if err != nil {
			attributionStatus = "unresolved"
			attributionReason = "cri_lookup_failed"
			procLogger.WithFields(logrus.Fields{
				"containerID":                 containerID,
				"container_metadata_degraded": true,
				"container_metadata_reason":   "cri_container_info_failed",
				"container_metadata_error":    err.Error(),
				"main_process_pid":            mainProcessPID,
			}).Warn("Failed to get container info, continue alerting without pod/namespace")

			podName = ""
			namespace = ""
		} else if strings.TrimSpace(namespace) == "" {
			attributionStatus = "unresolved"
			attributionReason = "namespace_missing"
		}
	}

	matchResult, revision, _ = p.matchStructured(procscanrules.Sample{
		ProcessName: processName,
		Command:     cmdline,
		Namespace:   namespace,
		PodName:     podName,
	})
	if matchResult == nil {
		procLogger.Info("Process or infrastructure matched an exemption")
		return nil, nil
	}
	message = fmt.Sprintf("process matched rule %q", matchResult.PrimaryRule.ID)

	processInfo := &models.ProcessInfo{
		PID:               pid,
		ProcessName:       processName,
		Command:           cmdline,
		Timestamp:         time.Now().Format(time.RFC3339),
		ProcessStartTime:  p.getProcessStartTime(pid),
		ContainerID:       containerID,
		Message:           message,
		PodName:           podName,
		PodUID:            podUID,
		Namespace:         namespace,
		IsIllegal:         true,
		RulesetRevision:   revision,
		AttributionStatus: attributionStatus,
		AttributionReason: attributionReason,
	}
	if matchResult != nil {
		processInfo.PrimaryRuleID = matchResult.PrimaryRule.ID
		processInfo.MatchedRuleIDs = append([]string{}, matchResult.MatchedRuleIDs...)
		processInfo.MatchType = matchResult.PrimaryRule.MatchType
		processInfo.MatchRule = matchResult.PrimaryRule.Pattern
		processInfo.Severity = matchResult.PrimaryRule.Severity
		processInfo.RuleAction = matchResult.PrimaryRule.Action
	}

	// Step 7: Confirmed as suspicious process
	procLogger.WithFields(logrus.Fields{
		"namespace":        processInfo.Namespace,
		"pod":              processInfo.PodName,
		"containerID":      processInfo.ContainerID,
		"malicious_pid":    pid,
		"main_process_pid": mainProcessPID,
	}).Warn("Confirmed malicious process detected")

	return processInfo, nil
}

func (p *Processor) getProcessStartTime(pid int) string {
	statPath := filepath.Join(p.ProcPath, strconv.Itoa(pid), "stat")
	data, err := os.ReadFile(statPath)
	if err != nil {
		return ""
	}

	content := string(data)
	closeParen := strings.LastIndexByte(content, ')')
	if closeParen < 0 || closeParen+2 >= len(content) {
		return ""
	}

	// After the command name, fields start at /proc stat field 3.
	fields := strings.Fields(content[closeParen+2:])
	if len(fields) <= 19 {
		return ""
	}

	return fields[19]
}

func (p *Processor) matchStructured(sample procscanrules.Sample) (*procscanrules.MatchResult, uint64, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.matcher == nil {
		return nil, 0, false
	}
	return p.matcher.Match(sample), p.revision, true
}

// getProcessName extracts the process name from command line
func (p *Processor) getProcessName(cmdline string) string {
	parts := strings.Fields(cmdline)
	if len(parts) == 0 {
		return ""
	}

	return filepath.Base(parts[0])
}

// getContainerIDFromPID extracts container ID from process cgroup information
func (p *Processor) getContainerIDFromPID(pid int) string {
	cgroupPath := filepath.Join(p.ProcPath, strconv.Itoa(pid), "cgroup")

	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		return ""
	}

	lines := strings.SplitSeq(string(content), "\n")
	for line := range lines {
		if strings.Contains(line, "containerd") || strings.Contains(line, "docker") ||
			strings.Contains(line, "kubepods") {
			parts := strings.SplitSeq(line, "/")
			for part := range parts {
				if strings.HasPrefix(part, "cri-containerd-") && strings.HasSuffix(part, ".scope") {
					containerID := strings.TrimPrefix(part, "cri-containerd-")

					containerID = strings.TrimSuffix(containerID, ".scope")
					if len(containerID) == 64 && isHexString(containerID) {
						return containerID
					}
				}
			}
		}
	}

	return ""
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}

	return true
}

func displayValueOrUnknown(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}
