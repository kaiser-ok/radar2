package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"new_radar/internal/model"
	"new_radar/internal/service"
)

type MACHandler struct {
	macSvc *service.MACService
}

func NewMACHandler(macSvc *service.MACService) *MACHandler {
	return &MACHandler{macSvc: macSvc}
}

// GET /api/v2/units/{unitId}/mac/{mac}
func (h *MACHandler) LocateMAC(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}
	mac := chi.URLParam(r, "mac")
	if mac == "" {
		Error(w, http.StatusBadRequest, "mac is required")
		return
	}

	result, err := h.macSvc.LocateMAC(unitID, mac)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	JSON(w, http.StatusOK, result)
}

// GET /api/v2/units/{unitId}/mac/{mac}/ip
func (h *MACHandler) ResolveMACToIP(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}
	mac := chi.URLParam(r, "mac")
	if mac == "" {
		Error(w, http.StatusBadRequest, "mac is required")
		return
	}

	ip, err := h.macSvc.ResolveMACToIP(unitID, mac)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"mac": mac, "ip": ip})
}

// GET /api/v2/units/{unitId}/ip/{ip}/mac
func (h *MACHandler) ResolveIPToMAC(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}
	ip := chi.URLParam(r, "ip")
	if ip == "" {
		Error(w, http.StatusBadRequest, "ip is required")
		return
	}

	mac, err := h.macSvc.ResolveIPToMAC(unitID, ip)
	if err != nil {
		Error(w, http.StatusNotFound, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"ip": ip, "mac": mac})
}

// POST /api/v2/units/{unitId}/topology/rebuild
func (h *MACHandler) RebuildTopology(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}

	result, err := h.macSvc.RebuildTopology(unitID)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, result)
}

// GET /api/v2/units/{unitId}/blocked
func (h *MACHandler) ListBlocked(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}

	blocked, err := h.macSvc.ListBlocked(unitID)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if blocked == nil {
		blocked = []model.BlockedMAC{}
	}
	JSON(w, http.StatusOK, map[string]any{"data": blocked})
}

// POST /api/v2/units/{unitId}/blocked
func (h *MACHandler) BlockMAC(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}

	var req struct {
		MAC string `json:"mac"`
	}
	if err := DecodeJSON(r, &req); err != nil || req.MAC == "" {
		Error(w, http.StatusBadRequest, "mac is required")
		return
	}

	blocked, err := h.macSvc.BlockMAC(unitID, req.MAC)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, blocked)
}

// DELETE /api/v2/units/{unitId}/blocked/{mac}
func (h *MACHandler) UnblockMAC(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}
	mac := chi.URLParam(r, "mac")
	if mac == "" {
		Error(w, http.StatusBadRequest, "mac is required")
		return
	}

	if err := h.macSvc.UnblockMAC(unitID, mac); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "unblocked", "mac": mac})
}
