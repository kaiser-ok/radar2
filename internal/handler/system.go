package handler

import (
	"net"
	"net/http"

	"new_radar/internal/config"
)

type SystemHandler struct {
	cfg *config.Config
}

func NewSystemHandler(cfg *config.Config) *SystemHandler {
	return &SystemHandler{cfg: cfg}
}

func (h *SystemHandler) Version(w http.ResponseWriter, r *http.Request) {
	JSON(w, http.StatusOK, map[string]string{
		"version":    h.cfg.Version,
		"build_date": h.cfg.BuildDate,
	})
}

func (h *SystemHandler) Interfaces(w http.ResponseWriter, r *http.Request) {
	ifaces, err := net.Interfaces()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	type ifaceInfo struct {
		Name       string   `json:"name"`
		MAC        string   `json:"mac"`
		MTU        int      `json:"mtu"`
		Flags      string   `json:"flags"`
		Addresses  []string `json:"addresses"`
	}

	var result []ifaceInfo
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		result = append(result, ifaceInfo{
			Name:      iface.Name,
			MAC:       iface.HardwareAddr.String(),
			MTU:       iface.MTU,
			Flags:     iface.Flags.String(),
			Addresses: addrStrs,
		})
	}
	JSON(w, http.StatusOK, result)
}
