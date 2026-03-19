package api

import (
	"net/http"
	"strings"
)

func MethodCheckMiddleware(allowedMethods ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, method := range allowedMethods {
				if r.Method == method {
					next.ServeHTTP(w, r)
					return
				}
			}
			//if the method is OPTIONS and it's allowed, specifically handle it.
			//this is useful for CORS pre-flight requests.
			if r.Method == "OPTIONS" && contains(allowedMethods, "OPTIONS") {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Set("Allow", strings.Join(allowedMethods, ", "))
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		})
	}
}

func contains(sliceToCheck []string, targetString string) bool {
	for _, s := range sliceToCheck {
		if s == targetString {
			return true
		}
	}
	return false
}
