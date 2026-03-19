package api

import (
	"net/http"
)

func CORSMiddlewareFactory(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			//Access-Control-Allow-Origin limits what origins can make cross origin requests to us (in this case to baskerville.ai)
			origin := r.Header.Get("Origin")
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
					//Access-Control-Allow-Methods limits the HTTP method set that can be applied
					w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					//Access-Control-Allow-Methods limits the headers to either Authorization or Content-Type
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
					w.Header().Set("Access-Control-Expose-Headers", "Authorization")
					//caches results of preflights for 1 day improving response times
					w.Header().Set("Access-Control-Max-Age", "86400")
					//handle the OPTIONS request for CORS preflight
					if r.Method == "OPTIONS" {
						//return directly without calling the next handler
						w.WriteHeader(http.StatusOK)
						return
					}
					break
				}
			}
			//call the next handler if it's not an OPTIONS request
			next.ServeHTTP(w, r)

			// log.Println("Response headers AFTER CORS:", w.Header())
		})
	}
}
