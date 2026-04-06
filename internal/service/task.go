package service

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"new_radar/internal/model"
)

// TaskStore is an in-memory store for async task results.
type TaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*model.Task
}

func NewTaskStore() *TaskStore {
	return &TaskStore{
		tasks: make(map[string]*model.Task),
	}
}

// Create registers a new task and returns it.
func (s *TaskStore) Create(unitID, taskType string) *model.Task {
	t := &model.Task{
		ID:        uuid.New().String(),
		UnitID:    unitID,
		Type:      taskType,
		Status:    model.TaskRunning,
		CreatedAt: time.Now(),
	}
	s.mu.Lock()
	s.tasks[t.ID] = t
	s.mu.Unlock()
	return t
}

// Get returns a task by ID.
func (s *TaskStore) Get(taskID string) (*model.Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tasks[taskID]
	return t, ok
}

// Complete marks a task as finished with output.
func (s *TaskStore) Complete(taskID, output string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[taskID]; ok {
		t.Status = model.TaskFinished
		t.Output = output
	}
}

// Fail marks a task as finished with error output.
func (s *TaskStore) Fail(taskID, errMsg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t, ok := s.tasks[taskID]; ok {
		t.Status = model.TaskFinished
		t.Output = "ERROR: " + errMsg
	}
}

// Cleanup removes tasks older than maxAge.
func (s *TaskStore) Cleanup(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for id, t := range s.tasks {
		if t.CreatedAt.Before(cutoff) {
			delete(s.tasks, id)
			removed++
		}
	}
	return removed
}

// StartCleanupLoop runs periodic cleanup in a goroutine.
func (s *TaskStore) StartCleanupLoop(interval, maxAge time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.Cleanup(maxAge)
		}
	}()
}
