package handler

import (
	"net/http"

	"new_radar/internal/db"
	"new_radar/internal/device"
	"new_radar/internal/snmp"
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

// GET /api/v2/switches/{swId}/capabilities — Detect and return switch capabilities
func (h *SSHHandler) Capabilities(w http.ResponseWriter, r *http.Request) {
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

	// SNMP fingerprint to detect profile
	snmpClient := h.executor.SNMPClient()
	results, err := snmpClient.Get(sw.IP, sw.Community, snmp.ParseVersion(sw.SNMPVer), []string{
		".1.3.6.1.2.1.1.2.0", // sysObjectID
		".1.3.6.1.2.1.1.1.0", // sysDescr
		".1.3.6.1.2.1.1.5.0", // sysName
		".1.3.6.1.2.1.1.3.0", // sysUpTime
	})
	if err != nil {
		Error(w, http.StatusBadGateway, "SNMP query failed: "+err.Error())
		return
	}

	sysOID := ""
	sysDescr := ""
	sysName := ""
	sysUpTime := ""
	if len(results) > 0 {
		sysOID = results[0].AsString()
	}
	if len(results) > 1 {
		sysDescr = results[1].AsString()
	}
	if len(results) > 2 {
		sysName = results[2].AsString()
	}
	if len(results) > 3 {
		sysUpTime = results[3].AsString()
	}

	profile := h.executor.DetectProfile(sysOID, sysDescr)

	resp := map[string]interface{}{
		"switch_id":     sw.ID,
		"switch_name":   sw.Name,
		"ip":            sw.IP,
		"sys_object_id": sysOID,
		"sys_descr":     sysDescr,
		"sys_name":      sysName,
		"sys_uptime":    sysUpTime,
	}

	if profile != nil {
		resp["profile_id"] = profile.ID
		resp["vendor"] = profile.Vendor
		resp["os"] = profile.OS
		resp["capabilities"] = profile.Capabilities

		// List mapped capabilities with methods
		mappings := map[string]string{}
		for cap := range profile.Mappings {
			m := profile.Mappings[cap]
			method := m.Method
			if m.Primary != nil {
				method = m.Primary.Method
				if m.Fallback != nil {
					method += " + " + m.Fallback.Method + " fallback"
				}
			}
			if method == "" {
				method = "configured"
			}
			mappings[cap] = method
		}
		resp["mappings"] = mappings

		// SSH info
		resp["ssh_enabled"] = profile.Protocols.SSH.Enabled
		if profile.Protocols.SSH.Enabled {
			resp["ssh_configured"] = sw.SSHUser != ""
		}
	} else {
		resp["profile_id"] = nil
		resp["capabilities"] = nil
		resp["message"] = "no matching profile found — run onboarding to add support for this device"
	}

	JSON(w, http.StatusOK, resp)
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
