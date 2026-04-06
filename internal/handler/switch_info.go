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

type SwitchInfoHandler struct {
	poeSvc     *service.PoEService
	infoSvc    *service.SwitchInfoService
	switchRepo *db.SwitchRepo
}

func NewSwitchInfoHandler(poeSvc *service.PoEService, infoSvc *service.SwitchInfoService, switchRepo *db.SwitchRepo) *SwitchInfoHandler {
	return &SwitchInfoHandler{poeSvc: poeSvc, infoSvc: infoSvc, switchRepo: switchRepo}
}

// GET /api/v2/switches/{swId}/poe
func (h *SwitchInfoHandler) PoESupport(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	supported, err := h.poeSvc.CheckSupport(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]bool{"supported": supported})
}

// GET /api/v2/switches/{swId}/poe/report
func (h *SwitchInfoHandler) PoEReport(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	report, err := h.poeSvc.GetReport(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, report)
}

// PUT /api/v2/switches/{swId}/poe/{port}
func (h *SwitchInfoHandler) SetPoE(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	port, err := strconv.Atoi(chi.URLParam(r, "port"))
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid port")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.poeSvc.SetPoE(sw, port, req.Enabled); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	status := "disabled"
	if req.Enabled {
		status = "enabled"
	}
	JSON(w, http.StatusOK, map[string]any{"port": port, "poe": status})
}

// GET /api/v2/switches/{swId}/cpu
func (h *SwitchInfoHandler) CPU(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	result, err := h.infoSvc.GetCPU(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, result)
}

// GET /api/v2/switches/{swId}/stats
func (h *SwitchInfoHandler) Stats(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	stats, err := h.infoSvc.GetStats(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]any{"data": stats})
}

// GET /api/v2/switches/{swId}/vlans
func (h *SwitchInfoHandler) VLANs(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	vlans, err := h.infoSvc.GetVLANs(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]any{"data": vlans})
}

func (h *SwitchInfoHandler) getSwitch(r *http.Request) (*model.Switch, error) {
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
