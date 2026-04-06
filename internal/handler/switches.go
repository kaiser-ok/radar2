package handler

import (
	"database/sql"
	"net/http"

	"new_radar/internal/db"
	"new_radar/internal/model"
)

type SwitchHandler struct {
	switchRepo *db.SwitchRepo
}

func NewSwitchHandler(switchRepo *db.SwitchRepo) *SwitchHandler {
	return &SwitchHandler{switchRepo: switchRepo}
}

// GET /api/v2/units/{unitId}/switches
func (h *SwitchHandler) ListByUnit(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}
	switches, err := h.switchRepo.GetByUnit(unitID)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if switches == nil {
		switches = []model.Switch{}
	}
	JSON(w, http.StatusOK, map[string]any{"data": switches})
}

// GET /api/v2/switches/{swId}
func (h *SwitchHandler) Get(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid switch_id")
		return
	}
	sw, err := h.switchRepo.GetByID(swID)
	if err == sql.ErrNoRows {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, sw)
}

// POST /api/v2/units/{unitId}/switches
func (h *SwitchHandler) Create(w http.ResponseWriter, r *http.Request) {
	unitID, err := URLParamInt64(r, "unitId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid unit_id")
		return
	}

	var req model.Switch
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	req.UnitID = unitID
	if req.IP == "" {
		Error(w, http.StatusBadRequest, "ip is required")
		return
	}
	if req.Community == "" {
		req.Community = "public"
	}
	if req.SNMPVer == "" {
		req.SNMPVer = "2c"
	}
	if req.AccessMethod == "" {
		req.AccessMethod = "snmp"
	}
	if req.SSHPort == 0 {
		req.SSHPort = 22
	}

	if err := h.switchRepo.Create(&req); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusCreated, req)
}

// PUT /api/v2/switches/{swId}
func (h *SwitchHandler) Update(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid switch_id")
		return
	}

	existing, err := h.switchRepo.GetByID(swID)
	if err == sql.ErrNoRows {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	var req model.Switch
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Merge: only update non-zero fields
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.IP != "" {
		existing.IP = req.IP
	}
	if req.Community != "" {
		existing.Community = req.Community
	}
	if req.SNMPVer != "" {
		existing.SNMPVer = req.SNMPVer
	}
	if req.Vendor != "" {
		existing.Vendor = req.Vendor
	}
	if req.Model != "" {
		existing.Model = req.Model
	}
	if req.PortCount != 0 {
		existing.PortCount = req.PortCount
	}
	if req.AccessMethod != "" {
		existing.AccessMethod = req.AccessMethod
	}
	if req.SSHUser != "" {
		existing.SSHUser = req.SSHUser
	}
	if req.SSHPassword != "" {
		existing.SSHPassword = req.SSHPassword
	}
	if req.SSHPort != 0 {
		existing.SSHPort = req.SSHPort
	}
	existing.PoECapable = req.PoECapable

	if err := h.switchRepo.Update(existing); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, existing)
}

// DELETE /api/v2/switches/{swId}
func (h *SwitchHandler) Delete(w http.ResponseWriter, r *http.Request) {
	swID, err := URLParamInt64(r, "swId")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid switch_id")
		return
	}
	if err := h.switchRepo.Delete(swID); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
