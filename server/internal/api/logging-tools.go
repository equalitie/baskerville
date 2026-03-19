package api

import (
	"log"
	"net/http"
	"time"
)

func LogMetadataMiddleware(logEndpoint bool, nextHandler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		//request
		startTime := time.Now()
		nextHandler.ServeHTTP(w, r) //moves onto next item in the pipeline so we can
		//log only on the way back up (ie when we have the response in tow)

		//response

		if r.URL.Path == "/health" {
			// Only skip logging if the User-Agent is kube-probe/1.26
			if r.UserAgent() == "kube-probe/1.26" {
				return
			}
			return
		}

		duration := time.Since(startTime)
		if logEndpoint {
			log.Printf("REQUEST: Method: %s, Path: %s, Reverse Proxy IP: %s, From IP: %s, From Host: %s, Duration: %s, User-Agent: %s\n\n",
				r.Method,
				r.URL.Path,
				r.RemoteAddr,
				r.Header.Get("X-Forwarded-Host"),
				r.Header.Get("X-Forwarded-For"),
				duration,
				r.UserAgent(),
			)
		}
	})
}
