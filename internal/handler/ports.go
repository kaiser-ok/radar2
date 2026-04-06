package handler

import (
	"database/sql"
	"fmt"
	"net/http"
	"strconv"

	"new_radar/internal/db"
	"new_radar/internal/model"
	"new_radar/internal/service"

	"github.com/go-chi/chi/v5"
)

type PortHandler struct {
	portSvc    *service.PortService
	switchRepo *db.SwitchRepo
}

func NewPortHandler(portSvc *service.PortService, switchRepo *db.SwitchRepo) *PortHandler {
	return &PortHandler{portSvc: portSvc, switchRepo: switchRepo}
}

// GET /api/v2/switches/{swId}/ports
func (h *PortHandler) ListPorts(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	ports, err := h.portSvc.GetAllPorts(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]any{"data": ports})
}

// GET /api/v2/switches/{swId}/ports/{port}
func (h *PortHandler) GetPort(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	portIdx, err := strconv.Atoi(chi.URLParam(r, "port"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid port index")
		return
	}

	port, err := h.portSvc.GetPort(sw, portIdx)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, port)
}

// PUT /api/v2/switches/{swId}/ports/{port}/admin
func (h *PortHandler) SetPortAdmin(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	portIdx, err := strconv.Atoi(chi.URLParam(r, "port"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid port index")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.portSvc.SetPortAdmin(sw, portIdx, req.Enabled); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	status := "disabled"
	if req.Enabled {
		status = "enabled"
	}
	JSON(w, http.StatusOK, map[string]any{
		"port":   portIdx,
		"status": status,
	})
}

// GET /api/v2/switches/{swId}/ports/descriptions
func (h *PortHandler) GetDescriptions(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	descs, err := h.portSvc.GetDescriptions(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]any{"data": descs})
}

func (h *PortHandler) getSwitch(r *http.Request) (*model.Switch, error) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		return nil, err
	}
	sw, err := h.switchRepo.GetByID(swID)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("switch %d not found", swID)
	}
	return sw, err
}
