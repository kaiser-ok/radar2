package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ProfilesHandler struct {
	baseDir string
}

func NewProfilesHandler(baseDir string) *ProfilesHandler {
	return &ProfilesHandler{baseDir: baseDir}
}

// GET /api/v2/profiles — returns the full 4-layer profile architecture
func (h *ProfilesHandler) GetAll(w http.ResponseWriter, r *http.Request) {
	result := map[string]interface{}{
		"layers": []map[string]string{
			{"name": "fingerprints", "description": "Layer 1: sysObjectID + sysDescr matching"},
			{"name": "capabilities", "description": "Layer 2: Boolean capability matrix per vendor"},
			{"name": "vendors", "description": "Layer 3: OID/CLI mappings with primary/fallback/verify"},
			{"name": "overrides", "description": "Layer 4: Model-specific tweaks"},
		},
		"fingerprints": readYAMLDir(filepath.Join(h.baseDir, "fingerprints")),
		"capabilities": readYAMLDir(filepath.Join(h.baseDir, "capabilities")),
		"vendors":      readYAMLDir(filepath.Join(h.baseDir, "vendors")),
		"overrides":    readYAMLDir(filepath.Join(h.baseDir, "overrides")),
	}
	JSON(w, http.StatusOK, result)
}

func readYAMLDir(dir string) []map[string]interface{} {
	var results []map[string]interface{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return results
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var m map[string]interface{}
		if err := yaml.Unmarshal(data, &m); err != nil {
			continue
		}
		m["_file"] = e.Name()
		results = append(results, m)
	}
	return results
}
