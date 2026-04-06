package handler

import (
	"net/http"

	"new_radar/internal/snmp"
)

type SNMPHandler struct {
	client *snmp.Client
}

func NewSNMPHandler(client *snmp.Client) *SNMPHandler {
	return &SNMPHandler{client: client}
}

// POST /api/v2/snmp/test
func (h *SNMPHandler) Test(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP        string `json:"ip"`
		Community string `json:"community"`
		SNMPVer   string `json:"snmp_ver"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
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

	ver := snmp.ParseVersion(req.SNMPVer)
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.2.0", // sysObjectID
		"1.3.6.1.2.1.1.3.0", // sysUpTime
		"1.3.6.1.2.1.1.5.0", // sysName
	}

	results, err := h.client.Get(req.IP, req.Community, ver, oids)
	if err != nil {
		JSON(w, http.StatusOK, map[string]any{
			"success": false,
			"error":   err.Error(),
		})
		return
	}

	info := make(map[string]string)
	for _, r := range results {
		switch {
		case endsWith(r.OID, "1.1.0"):
			info["sysDescr"] = r.AsString()
		case endsWith(r.OID, "1.2.0"):
			info["sysObjectID"] = r.AsString()
		case endsWith(r.OID, "1.3.0"):
			info["sysUpTime"] = r.AsString()
		case endsWith(r.OID, "1.5.0"):
			info["sysName"] = r.AsString()
		}
	}

	JSON(w, http.StatusOK, map[string]any{
		"success": true,
		"ip":      req.IP,
		"info":    info,
	})
}

// POST /api/v2/snmp/query
func (h *SNMPHandler) Query(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP        string `json:"ip"`
		Community string `json:"community"`
		SNMPVer   string `json:"snmp_ver"`
		OID       string `json:"oid"`
		Walk      bool   `json:"walk"`
	}
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.IP == "" || req.OID == "" {
		Error(w, http.StatusBadRequest, "ip and oid are required")
		return
	}
	if req.Community == "" {
		req.Community = "public"
	}

	ver := snmp.ParseVersion(req.SNMPVer)

	if req.Walk {
		results, err := h.client.BulkWalk(req.IP, req.Community, ver, req.OID)
		if err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		var data []map[string]string
		for _, r := range results {
			data = append(data, map[string]string{
				"oid":   r.OID,
				"value": r.AsString(),
			})
		}
		JSON(w, http.StatusOK, map[string]any{"data": data, "count": len(data)})
	} else {
		results, err := h.client.Get(req.IP, req.Community, ver, []string{req.OID})
		if err != nil {
			Error(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(results) > 0 {
			JSON(w, http.StatusOK, map[string]any{
				"oid":   results[0].OID,
				"value": results[0].AsString(),
			})
		} else {
			Error(w, http.StatusNotFound, "no result")
		}
	}
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}
