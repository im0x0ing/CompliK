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

package processor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bearslyricattack/CompliK/procscan/pkg/models"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestProcessor(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Processor Suite")
}

func minerRuleSet(revision uint64) models.ProcscanRuleSet {
	return models.ProcscanRuleSet{
		SchemaVersion:   2,
		RulesetRevision: revision,
		Rules: []models.ProcscanRule{{
			ID: "miner", Name: "miner", Enabled: true,
			MatchType: "process_name", Pattern: "^xmrig$",
			Severity: "critical", Action: "ban",
		}},
	}
}

func TestGetProcessStartTime(t *testing.T) {
	tmpDir := t.TempDir()
	pidDir := filepath.Join(tmpDir, "1234")
	if err := os.MkdirAll(pidDir, 0o700); err != nil {
		t.Fatalf("mkdir pid dir: %v", err)
	}

	// The substring after the final ')' starts at /proc stat field 3.
	stat := "1234 (process name with ) paren) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20"
	if err := os.WriteFile(filepath.Join(pidDir, "stat"), []byte(stat), 0o600); err != nil {
		t.Fatalf("write stat: %v", err)
	}

	processor := NewProcessor(&models.Config{Scanner: models.ScannerConfig{ProcPath: tmpDir}})
	if got := processor.getProcessStartTime(1234); got != "19" {
		t.Fatalf("getProcessStartTime() = %q, want %q", got, "19")
	}
}

var _ = Describe("Processor", func() {
	Describe("NewProcessor", func() {
		It("should create a new processor with structured rules", func() {
			config := &models.Config{
				Scanner:       models.ScannerConfig{ProcPath: "/proc"},
				ProcscanRules: minerRuleSet(1),
			}

			processor := NewProcessor(config)
			Expect(processor).NotTo(BeNil())
			Expect(processor.ProcPath).To(Equal("/proc"))
			Expect(processor.Ready()).To(BeTrue())
			Expect(processor.RulesetRevision()).To(Equal(uint64(1)))
		})
	})

	Describe("UpdateConfig", func() {
		It("should compile structured rules from new config", func() {
			processor := NewProcessor(&models.Config{
				Scanner: models.ScannerConfig{ProcPath: "/proc"},
			})
			Expect(processor.Ready()).To(BeFalse())

			err := processor.UpdateConfig(&models.Config{ProcscanRules: minerRuleSet(3)})
			Expect(err).NotTo(HaveOccurred())
			Expect(processor.Ready()).To(BeTrue())
			Expect(processor.RulesetRevision()).To(Equal(uint64(3)))
		})
	})

	Describe("getProcessName", func() {
		var processor *Processor

		BeforeEach(func() {
			processor = NewProcessor(&models.Config{
				Scanner: models.ScannerConfig{ProcPath: "/proc"},
			})
		})

		It("should extract process name from simple command", func() {
			Expect(processor.getProcessName("/usr/bin/python3 script.py")).To(Equal("python3"))
		})

		It("should extract process name from complex path", func() {
			Expect(processor.getProcessName("/usr/local/bin/some-app --flag=value")).To(Equal("some-app"))
		})

		It("should handle command with no arguments", func() {
			Expect(processor.getProcessName("nginx")).To(Equal("nginx"))
		})

		It("should handle empty command", func() {
			Expect(processor.getProcessName("")).To(BeEmpty())
		})
	})

	Describe("isHexString", func() {
		It("should validate valid hex strings", func() {
			Expect(isHexString("0123456789abcdef")).To(BeTrue())
			Expect(isHexString("ABCDEF0123456789")).To(BeTrue())
			Expect(
				isHexString("aabbccddee112233445566778899aabbccddee112233445566778899aabbccdd"),
			).To(BeTrue())
		})

		It("should reject non-hex strings", func() {
			Expect(isHexString("xyz123")).To(BeFalse())
			Expect(isHexString("12345g")).To(BeFalse())
			Expect(isHexString("hello-world")).To(BeFalse())
		})

		It("should handle empty string", func() {
			Expect(isHexString("")).To(BeTrue())
		})
	})

	Describe("GetAllProcesses", func() {
		var (
			processor *Processor
			tmpDir    string
		)

		BeforeEach(func() {
			var err error
			tmpDir, err = os.MkdirTemp("", "proc-test-*")
			Expect(err).NotTo(HaveOccurred())
			processor = NewProcessor(&models.Config{
				Scanner: models.ScannerConfig{ProcPath: tmpDir},
			})
		})

		AfterEach(func() {
			os.RemoveAll(tmpDir)
		})

		It("should return list of PIDs from proc directory", func() {
			mustMkdir(filepath.Join(tmpDir, "1234"))
			mustMkdir(filepath.Join(tmpDir, "5678"))
			mustMkdir(filepath.Join(tmpDir, "9999"))
			mustMkdir(filepath.Join(tmpDir, "self"))

			pids, err := processor.GetAllProcesses()
			Expect(err).NotTo(HaveOccurred())
			Expect(pids).To(HaveLen(3))
			Expect(pids).To(ContainElement(1234))
			Expect(pids).To(ContainElement(5678))
			Expect(pids).To(ContainElement(9999))
		})

		It("should handle empty proc directory", func() {
			pids, err := processor.GetAllProcesses()
			Expect(err).NotTo(HaveOccurred())
			Expect(pids).To(BeEmpty())
		})

		It("should return error when proc path doesn't exist", func() {
			processor.ProcPath = "/non/existent/path"
			_, err := processor.GetAllProcesses()
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("failed to read"))
		})
	})

	Describe("getContainerIDFromPID", func() {
		var (
			processor *Processor
			tmpDir    string
		)

		BeforeEach(func() {
			var err error
			tmpDir, err = os.MkdirTemp("", "proc-test-*")
			Expect(err).NotTo(HaveOccurred())
			processor = NewProcessor(&models.Config{
				Scanner: models.ScannerConfig{ProcPath: tmpDir},
			})
		})

		AfterEach(func() {
			os.RemoveAll(tmpDir)
		})

		It("should extract container ID from cgroup with containerd", func() {
			pidDir := filepath.Join(tmpDir, "1234")
			mustMkdir(pidDir)

			cgroupContent := `12:memory:/kubepods/besteffort/pod123/cri-containerd-aabbccddee112233445566778899aabbccddee112233445566778899aabbccdd.scope
11:cpu:/kubepods/besteffort/pod123/cri-containerd-aabbccddee112233445566778899aabbccddee112233445566778899aabbccdd.scope`
			err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroupContent), 0o600)
			Expect(err).NotTo(HaveOccurred())

			containerID := processor.getContainerIDFromPID(1234)
			Expect(containerID).To(Equal(
				"aabbccddee112233445566778899aabbccddee112233445566778899aabbccdd",
			))
			Expect(isHexString(containerID)).To(BeTrue())
		})

		It("should return empty string when cgroup file doesn't exist", func() {
			Expect(processor.getContainerIDFromPID(99999)).To(BeEmpty())
		})

		It("should return empty string for non-container process", func() {
			mustMkdir(filepath.Join(tmpDir, "5678"))
			Expect(processor.getContainerIDFromPID(5678)).To(BeEmpty())
		})
	})
})
