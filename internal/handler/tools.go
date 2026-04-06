package handler

import (
	"net/http"

	"new_radar/internal/service"

	"github.com/go-chi/chi/v5"
)

type ToolsHandler struct {
	execSvc *service.ExecService
}

func NewToolsHandler(execSvc *service.ExecService) *ToolsHandler {
	return &ToolsHandler{execSvc: execSvc}
}

// POST /api/v2/tools/ping
func (h *ToolsHandler) Ping(w http.ResponseWriter, r *http.Request) {
	var req service.PingRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" {
		Error(w, http.StatusBadRequest, "host is required")
		return
	}

	task := h.execSvc.Ping(&req)
	JSON(w, http.StatusAccepted, map[string]string{"task_id": task.ID})
}

// POST /api/v2/tools/traceroute
func (h *ToolsHandler) Traceroute(w http.ResponseWriter, r *http.Request) {
	var req service.TracerouteRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" {
		Error(w, http.StatusBadRequest, "host is required")
		return
	}

	task := h.execSvc.Traceroute(&req)
	JSON(w, http.StatusAccepted, map[string]string{"task_id": task.ID})
}

// POST /api/v2/tools/arping
func (h *ToolsHandler) Arping(w http.ResponseWriter, r *http.Request) {
	var req service.ArpingRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Host == "" {
		Error(w, http.StatusBadRequest, "host is required")
		return
	}

	task := h.execSvc.Arping(&req)
	JSON(w, http.StatusAccepted, map[string]string{"task_id": task.ID})
}

// POST /api/v2/tools/dad-check
func (h *ToolsHandler) DADCheck(w http.ResponseWriter, r *http.Request) {
	var req service.DADCheckRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IP == "" {
		Error(w, http.StatusBadRequest, "ip is required")
		return
	}

	task := h.execSvc.DADCheck(&req)
	JSON(w, http.StatusAccepted, map[string]string{"task_id": task.ID})
}

// GET /api/v2/tools/tasks/{taskId}
func (h *ToolsHandler) GetTask(w http.ResponseWriter, r *http.Request) {
	taskID := chi.URLParam(r, "taskId")
	if taskID == "" {
		Error(w, http.StatusBadRequest, "task_id is required")
		return
	}

	task, ok := h.execSvc.GetTask(taskID)
	if !ok {
		Error(w, http.StatusNotFound, "task not found")
		return
	}

	JSON(w, http.StatusOK, task)
}
