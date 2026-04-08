package handler

import (
	"net/http"

	"new_radar/internal/db"
	"new_radar/internal/device"
)

type SSHHandler struct {
	executor   *device.Executor
	switchRepo *db.SwitchRepo
}

func NewSSHHandler(executor *device.Executor, switchRepo *db.SwitchRepo) *SSHHandler {
	return &SSHHandler{executor: executor, switchRepo: switchRepo}
}

// POST /api/v2/switches/{swId}/ssh/exec — Execute SSH commands on a switch
func (h *SSHHandler) Exec(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid swId")
		return
	}

	sw, err := h.switchRepo.GetByID(swID)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	var req struct {
		Commands []string `json:"commands"`
	}
	if err := DecodeJSON(r, &req); err != nil || len(req.Commands) == 0 {
		Error(w, http.StatusBadRequest, "commands array required")
		return
	}

	result := h.executor.ExecuteSSH(sw, req.Commands)
	JSON(w, http.StatusOK, result)
}

// POST /api/v2/switches/{swId}/reboot — Reboot a switch via profile-defined method
func (h *SSHHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid swId")
		return
	}

	sw, err := h.switchRepo.GetByID(swID)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	result := h.executor.WriteCapability(sw, "ssh.cli.write", "reboot", nil)
	JSON(w, http.StatusOK, result)
}

// POST /api/v2/switches/{swId}/ssh/test — Test SSH connectivity
func (h *SSHHandler) Test(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid swId")
		return
	}

	sw, err := h.switchRepo.GetByID(swID)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	// Just run a simple command to test
	result := h.executor.ExecuteSSH(sw, []string{"show version"})
	if !result.Success {
		// Try Mikrotik style
		result = h.executor.ExecuteSSH(sw, []string{"/system resource print"})
	}
	JSON(w, http.StatusOK, result)
}
