package api

import (
	"encoding/json"
	"net/http"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeAPIError(w http.ResponseWriter, err error) {
	ae, ok := asAPIError(err)
	if !ok {
		ae = newAPIError(http.StatusInternalServerError, "internal_error", "internal server error")
	}
	writeJSON(w, ae.Status, ae)
}
