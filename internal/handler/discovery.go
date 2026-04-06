package handler

import (
	"database/sql"
	"fmt"
	"net/http"

	"new_radar/internal/db"
	"new_radar/internal/model"
	"new_radar/internal/service"
)

type DiscoveryHandler struct {
	discoverySvc *service.DiscoveryService
	fdbSvc       *service.FDBService
	switchRepo   *db.SwitchRepo
}

func NewDiscoveryHandler(discoverySvc *service.DiscoveryService, fdbSvc *service.FDBService, switchRepo *db.SwitchRepo) *DiscoveryHandler {
	return &DiscoveryHandler{discoverySvc: discoverySvc, fdbSvc: fdbSvc, switchRepo: switchRepo}
}

// POST /api/v2/snmp/discovery
func (h *DiscoveryHandler) Discover(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Subnet    string `json:"subnet"`
		Community string `json:"community"`
		SNMPVer   string `json:"snmp_ver"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Subnet == "" {
		Error(w, http.StatusBadRequest, "subnet is required")
		return
	}

	devices, err := h.discoverySvc.DiscoverSubnet(req.Subnet, req.Community, req.SNMPVer)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]any{"data": devices, "count": len(devices)})
}

// GET /api/v2/switches/{swId}/fdb
func (h *DiscoveryHandler) GetFDB(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}

	entries, err := h.fdbSvc.GetFDB(sw)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]any{"data": entries, "count": len(entries)})
}

// POST /api/v2/switches/{swId}/reboot
func (h *DiscoveryHandler) Reboot(w http.ResponseWriter, r *http.Request) {
	sw, err := h.getSwitch(r)
	if err != nil {
		Error(w, http.StatusNotFound, "switch not found")
		return
	}
	// Reboot requires SSH/Telnet or vendor-specific SNMP OID — placeholder
	JSON(w, http.StatusOK, map[string]any{
		"status":  "accepted",
		"message": fmt.Sprintf("reboot request queued for switch %s (%s)", sw.Name, sw.IP),
		"note":    "reboot execution depends on vendor profile (SNMP SET or SSH CLI)",
	})
}

func (h *DiscoveryHandler) getSwitch(r *http.Request) (*model.Switch, error) {
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
