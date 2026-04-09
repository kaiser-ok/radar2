package handler

import (
	"net/http"
	"strings"

	"new_radar/internal/onboarding"
	"new_radar/internal/service"
)

type OnboardingHandler struct {
	svc       *onboarding.Service
	taskStore *service.TaskStore
}

func NewOnboardingHandler(svc *onboarding.Service, taskStore *service.TaskStore) *OnboardingHandler {
	return &OnboardingHandler{svc: svc, taskStore: taskStore}
}

// POST /api/v2/onboarding
func (h *OnboardingHandler) CreateCase(w http.ResponseWriter, r *http.Request) {
	var req onboarding.IntakeRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.Vendor == "" || req.Model == "" {
		Error(w, http.StatusBadRequest, "vendor and model are required")
		return
	}

	c, err := h.svc.CreateCase(&req)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			Error(w, http.StatusConflict, err.Error())
		} else {
			Error(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	JSON(w, http.StatusCreated, c)
}

// GET /api/v2/onboarding
func (h *OnboardingHandler) ListCases(w http.ResponseWriter, r *http.Request) {
	cases, err := h.svc.ListCases()
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	if cases == nil {
		cases = []onboarding.Case{}
	}
	JSON(w, http.StatusOK, map[string]any{"data": cases})
}

// GET /api/v2/onboarding/{id}
func (h *OnboardingHandler) GetCase(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	c, err := h.svc.GetCase(id)
	if err != nil {
		Error(w, http.StatusNotFound, "case not found")
		return
	}
	JSON(w, http.StatusOK, c)
}

// DELETE /api/v2/onboarding/{id}
func (h *OnboardingHandler) DeleteCase(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}
	if err := h.svc.DeleteCase(id); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// POST /api/v2/onboarding/{id}/fingerprint
func (h *OnboardingHandler) SubmitFingerprint(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	var req onboarding.FingerprintRequest
	if err := DecodeJSON(r, &req); err != nil {
		Error(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := h.svc.SubmitFingerprint(id, &req); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}
	JSON(w, http.StatusOK, map[string]string{"status": "fingerprint saved"})
}

// POST /api/v2/onboarding/{id}/collect
func (h *OnboardingHandler) Collect(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	task := h.taskStore.Create("onboarding", "collect")
	h.svc.CollectAsync(id, task.ID)

	JSON(w, http.StatusAccepted, map[string]string{
		"task_id": task.ID,
		"status":  "collecting",
		"message": "SNMP walks started in background. Poll /api/v2/tools/tasks/" + task.ID + " for results.",
	})
}

// POST /api/v2/onboarding/{id}/evidence
func (h *OnboardingHandler) UploadEvidence(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := r.ParseMultipartForm(50 << 20); err != nil { // 50MB max
		Error(w, http.StatusBadRequest, "invalid multipart form")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		Error(w, http.StatusBadRequest, "missing file field")
		return
	}
	defer file.Close()

	if err := h.svc.UploadEvidence(id, header.Filename, file); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{
		"status":   "uploaded",
		"filename": header.Filename,
	})
}

// POST /api/v2/onboarding/{id}/analyze
func (h *OnboardingHandler) Analyze(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	report, err := h.svc.Analyze(id)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, report)
}

// GET /api/v2/onboarding/{id}/drafts
func (h *OnboardingHandler) GetDrafts(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	drafts, err := h.svc.GetDrafts(id)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, drafts)
}

// POST /api/v2/onboarding/{id}/approve
func (h *OnboardingHandler) Approve(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	if err := h.svc.Approve(id); err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]string{"status": "approved", "message": "profiles deployed to production"})
}

// POST /api/v2/onboarding/{id}/verify
func (h *OnboardingHandler) Verify(w http.ResponseWriter, r *http.Request) {
	id, err := URLParamInt64(r, "id")
	if err != nil {
		Error(w, http.StatusBadRequest, "invalid id")
		return
	}

	results, err := h.svc.Verify(id)
	if err != nil {
		Error(w, http.StatusInternalServerError, err.Error())
		return
	}

	JSON(w, http.StatusOK, map[string]interface{}{"results": results})
}
