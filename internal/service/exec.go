package service

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
	"time"

	"new_radar/internal/model"
)

// ExecService handles async network tool execution.
type ExecService struct {
	store   *TaskStore
	timeout time.Duration
}

func NewExecService(store *TaskStore, timeout time.Duration) *ExecService {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &ExecService{store: store, timeout: timeout}
}

// PingRequest is the input for a ping task.
type PingRequest struct {
	Host   string `json:"host"`
	Count  int    `json:"count"`
	UnitID string `json:"unit_id"`
}

// TracerouteRequest is the input for a traceroute task.
type TracerouteRequest struct {
	Host    string `json:"host"`
	MaxHops int    `json:"max_hops"`
	UnitID  string `json:"unit_id"`
}

// ArpingRequest is the input for an arping task.
type ArpingRequest struct {
	Host      string `json:"host"`
	Interface string `json:"interface,omitempty"`
	Count     int    `json:"count"`
	UnitID    string `json:"unit_id"`
}

// DADCheckRequest is the input for a Duplicate Address Detection task.
type DADCheckRequest struct {
	IP        string `json:"ip"`
	Interface string `json:"interface,omitempty"`
	UnitID    string `json:"unit_id"`
}

// Ping starts an async ping task.
func (s *ExecService) Ping(req *PingRequest) *model.Task {
	count := req.Count
	if count <= 0 {
		count = 4
	}

	task := s.store.Create(req.UnitID, "ping")
	go s.runCommand(task.ID, "ping", "-c", fmt.Sprintf("%d", count), req.Host)
	return task
}

// Traceroute starts an async traceroute task.
func (s *ExecService) Traceroute(req *TracerouteRequest) *model.Task {
	maxHops := req.MaxHops
	if maxHops <= 0 {
		maxHops = 30
	}

	task := s.store.Create(req.UnitID, "traceroute")
	go s.runCommand(task.ID, "traceroute", "-m", fmt.Sprintf("%d", maxHops), req.Host)
	return task
}

// Arping starts an async arping task.
func (s *ExecService) Arping(req *ArpingRequest) *model.Task {
	count := req.Count
	if count <= 0 {
		count = 3
	}

	task := s.store.Create(req.UnitID, "arping")

	args := []string{"-c", fmt.Sprintf("%d", count)}
	if req.Interface != "" {
		args = append(args, "-I", req.Interface)
	}
	args = append(args, req.Host)

	go s.runCommand(task.ID, "arping", args...)
	return task
}

// DADCheck starts an async Duplicate Address Detection task.
// Uses arping -D to detect if an IP is already in use.
func (s *ExecService) DADCheck(req *DADCheckRequest) *model.Task {
	task := s.store.Create(req.UnitID, "dad_check")

	args := []string{"-D", "-c", "3"}
	if req.Interface != "" {
		args = append(args, "-I", req.Interface)
	}
	args = append(args, req.IP)

	go s.runDADCheck(task.ID, args)
	return task
}

// GetTask returns a task by ID.
func (s *ExecService) GetTask(taskID string) (*model.Task, bool) {
	return s.store.Get(taskID)
}

// runCommand executes an OS command and stores the result.
func (s *ExecService) runCommand(taskID string, name string, args ...string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	slog.Info("exec task started", "task_id", taskID, "command", name, "args", strings.Join(args, " "))

	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.store.Fail(taskID, "command timed out")
		} else {
			// Include output even on error (e.g. ping with partial results)
			result := string(output)
			if result == "" {
				result = err.Error()
			}
			s.store.Complete(taskID, result)
		}
		return
	}

	s.store.Complete(taskID, string(output))
	slog.Info("exec task completed", "task_id", taskID)
}

// runDADCheck runs arping -D and interprets the result.
// arping -D exit code: 0 = address is free, 1 = address is in use
func (s *ExecService) runDADCheck(taskID string, args []string) {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	slog.Info("dad_check started", "task_id", taskID)

	cmd := exec.CommandContext(ctx, "arping", args...)
	output, err := cmd.CombinedOutput()

	result := string(output)
	if ctx.Err() == context.DeadlineExceeded {
		s.store.Fail(taskID, "DAD check timed out")
		return
	}

	if err != nil {
		// Exit code 1 means duplicate detected
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			result = result + "\nRESULT: DUPLICATE ADDRESS DETECTED"
		} else {
			result = result + "\nERROR: " + err.Error()
		}
	} else {
		result = result + "\nRESULT: ADDRESS IS FREE"
	}

	s.store.Complete(taskID, result)
	slog.Info("dad_check completed", "task_id", taskID)
}
