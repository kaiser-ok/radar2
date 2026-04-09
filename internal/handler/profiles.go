package handler

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"
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

// POST /api/v2/profiles/overrides — create or update a Layer 4 override
func (h *ProfilesHandler) CreateOverride(w http.ResponseWriter, r *http.Request) {
	var body map[string]interface{}
	if err := DecodeJSON(r, &body); err != nil {
		Error(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	id, _ := body["id"].(string)
	if id == "" {
		Error(w, http.StatusBadRequest, "id is required")
		return
	}
	extends, _ := body["extends"].(string)
	if extends == "" {
		Error(w, http.StatusBadRequest, "extends is required (base profile ID)")
		return
	}

	data, err := yaml.Marshal(body)
	if err != nil {
		Error(w, http.StatusInternalServerError, "failed to marshal YAML")
		return
	}

	overrideDir := filepath.Join(h.baseDir, "overrides")
	os.MkdirAll(overrideDir, 0755)

	filename := id + ".yaml"
	if err := os.WriteFile(filepath.Join(overrideDir, filename), data, 0644); err != nil {
		Error(w, http.StatusInternalServerError, "failed to write override file: "+err.Error())
		return
	}

	JSON(w, http.StatusCreated, map[string]string{"status": "created", "file": filename})
}

// DELETE /api/v2/profiles/overrides/{filename} — delete a Layer 4 override
func (h *ProfilesHandler) DeleteOverride(w http.ResponseWriter, r *http.Request) {
	filename := chi.URLParam(r, "filename")
	if filename == "" || !strings.HasSuffix(filename, ".yaml") {
		Error(w, http.StatusBadRequest, "invalid filename")
		return
	}

	path := filepath.Join(h.baseDir, "overrides", filename)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		Error(w, http.StatusNotFound, "override not found")
		return
	}

	if err := os.Remove(path); err != nil {
		Error(w, http.StatusInternalServerError, "failed to delete: "+err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
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
