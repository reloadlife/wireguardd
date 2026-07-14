package api

import (
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
)

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := r.Context()
		// chi middleware also sets request id if used; keep simple
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func bearerAuth(token string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if token == "" {
				writeError(w, http.StatusInternalServerError, "misconfigured", "auth token not configured")
				return
			}
			h := r.Header.Get("Authorization")
			if !strings.HasPrefix(h, "Bearer ") {
				writeError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
				return
			}
			got := strings.TrimPrefix(h, "Bearer ")
			if subtle.ConstantTimeCompare([]byte(got), []byte(token)) != 1 {
				writeError(w, http.StatusUnauthorized, "unauthorized", "invalid token")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func readOnlyGuard(readOnly bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if readOnly {
				switch r.Method {
				case http.MethodGet, http.MethodHead, http.MethodOptions:
				default:
					writeError(w, http.StatusForbidden, "read_only", "daemon is in read-only mode")
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// recoverer is a thin alias so tests can depend on middleware package presence.
var _ = middleware.RequestID
