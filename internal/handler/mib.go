package handler

import (
	"net/http"

	"new_radar/internal/mib"
)

type MIBHandler struct {
	store *mib.Store
}

func NewMIBHandler(store *mib.Store) *MIBHandler {
	return &MIBHandler{store: store}
}

// POST /api/v2/mibs/upload
// Multipart form: file (MIB file), vendor (optional string)
func (h *MIBHandler) Upload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(10 << 20); err != nil { // 10MB max
		Error(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		Error(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	vendor := r.FormValue("vendor")
	if vendor == "" {
		vendor = "custom"
	}

	mod, err := h.store.UploadMIB(header.Filename, vendor, file)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	result := map[string]any{
		"status":   "uploaded",
		"filename": header.Filename,
		"vendor":   vendor,
	}
	if mod != nil {
		result["module"] = mod.Name
		result["oids_parsed"] = len(mod.OIDs)
	}
	JSON(w, http.StatusOK, result)
}

// GET /api/v2/mibs/modules
func (h *MIBHandler) ListModules(w http.ResponseWriter, r *http.Request) {
	modules := h.store.ListModules()
	JSON(w, http.StatusOK, map[string]any{"data": modules})
}

// GET /api/v2/mibs/lookup?name=ifAdminStatus
func (h *MIBHandler) LookupByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		Error(w, http.StatusBadRequest, "name parameter required")
		return
	}
	oid := h.store.LookupOID(name)
	if oid == "" {
		Error(w, http.StatusNotFound, "OID not found for: "+name)
		return
	}
	JSON(w, http.StatusOK, map[string]string{"name": name, "oid": oid})
}

// GET /api/v2/mibs/resolve?oid=1.3.6.1.2.1.2.2.1.7
func (h *MIBHandler) ResolveOID(w http.ResponseWriter, r *http.Request) {
	oid := r.URL.Query().Get("oid")
	if oid == "" {
		Error(w, http.StatusBadRequest, "oid parameter required")
		return
	}
	name := h.store.LookupName(oid)
	if name == "" {
		Error(w, http.StatusNotFound, "name not found for: "+oid)
		return
	}
	JSON(w, http.StatusOK, map[string]string{"name": name, "oid": oid})
}

// GET /api/v2/mibs/search?q=cpu
func (h *MIBHandler) Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if q == "" {
		Error(w, http.StatusBadRequest, "q parameter required")
		return
	}
	results := h.store.SearchOIDs(q)
	JSON(w, http.StatusOK, map[string]any{"data": results, "count": len(results)})
}

// DELETE /api/v2/mibs/modules/{name}
func (h *MIBHandler) DeleteModule(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Query().Get("name")
	if name == "" {
		Error(w, http.StatusBadRequest, "name parameter required")
		return
	}
	if err := h.store.DeleteModule(name); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "deleted", "module": name})
}
