package api

import (
	"context"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	paymentchecker "wpsec/internal/stripe"
)

var stripePmtChecker *paymentchecker.PaymentChecker

func StartAPI(

	allowedOrigin []string,
	wg *sync.WaitGroup,
	apiToProducer chan []byte,
	ctx context.Context,
	serverAddress string,
	stripeSecretKey string,

) {

	checker := paymentchecker.NewPaymentChecker(stripeSecretKey)
	checker.StartJanitor(ctx)

	multiplexer := Multiplexer(apiToProducer, checker)
	corsMiddleware := CORSMiddlewareFactory(allowedOrigin)
	defaultHandler := corsMiddleware(multiplexer)

	server := &http.Server{
		Addr:              serverAddress,
		Handler:           defaultHandler,
		IdleTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	listener, err := net.Listen("tcp", server.Addr)
	if err != nil {
		log.Fatalf("[API ERROR]: Error setting up listener: %v", err)
	}

	wg.Done()

	go func() {
		<-ctx.Done()

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Printf("[API ERROR]: graceful shutdown failed: %v", err)
		}
	}()

	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("[API ERROR]: Something went wrong during shutdown: %s", err)
	}
}

func Multiplexer(apiToProducer chan []byte, checker *paymentchecker.PaymentChecker) http.Handler {
	mux := http.NewServeMux()

	//main traffic/log data handler. We receive requests on this endpoint which we subsequently
	//transmit over to the producer go routines that parse and feed into the kafka topic
	logLogsRequestStdout := false
	//ignore options bug for now, new impl has better version than this (this is a test version single server setup)
	methodCheckLogsRequest := MethodCheckMiddleware("POST", "OPTIONS")
	predictionInputsHandler := HandlePredictionDataDelivery(apiToProducer)
	logsPipeline := LogMetadataMiddleware(logLogsRequestStdout, methodCheckLogsRequest(WithValidation(checker, predictionInputsHandler)))
	mux.Handle("/logs", logsPipeline)

	//to collect performance over many queries
	logPerfMetricsRequestStdout := false
	methodCheckLogPerfRequest := MethodCheckMiddleware("POST")
	performanceTrackingHandler := LogMetadataMiddleware(logPerfMetricsRequestStdout, methodCheckLogPerfRequest(http.HandlerFunc(HandlePerformanceTracker)))
	mux.Handle("/perf", performanceTrackingHandler)

	//to lookup the latencies so that we can compute stats
	logQueryPerformanceMetricsStdout := false
	methodCheckPerfLookupRequest := MethodCheckMiddleware("GET")
	performanceLookupHandler := LogMetadataMiddleware(logQueryPerformanceMetricsStdout, methodCheckPerfLookupRequest(http.HandlerFunc(HandleLookupPerformanceQuery)))
	mux.Handle("/historical_latency", performanceLookupHandler)

	//lookup latency statistics
	logQueryPerformanceStatsStdout := false
	methodCheckPerfStatsLookupRequest := MethodCheckMiddleware("GET")
	statsLookupHandler := LogMetadataMiddleware(logQueryPerformanceStatsStdout, methodCheckPerfStatsLookupRequest(http.HandlerFunc(HandleLatencyStats)))
	mux.Handle("/latency_stats", statsLookupHandler)

	// /health
	logHealthCheckStdout := false
	methodCheckHealthCheck := MethodCheckMiddleware("GET")
	healthCheckPipeline := LogMetadataMiddleware(logHealthCheckStdout, methodCheckHealthCheck(http.HandlerFunc(HandleHealthCheck)))
	mux.Handle("/health", healthCheckPipeline)

	// catch all
	logCatchAllStdout := false
	catchAllPipeline := LogMetadataMiddleware(logCatchAllStdout, http.HandlerFunc(HandleCatchall))
	mux.Handle("/", catchAllPipeline)

	return mux
}

/*
Since the plugin calls the API from PHP (server-side) we won’t see browser Origin / Referer reliably.
but we will see:
  - the IP of the WordPress server,
  - whatever headers the plugin sends (like X-WPSEC-Site-Url).

so the correct binding is:
  - store hostname at signup.
  - have plugin send it explicitly.

then just compare server side.
*/
func WithValidation(checker *paymentchecker.PaymentChecker, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-WPSEC-Api-Key")
		siteURL := r.Header.Get("X-WPSEC-Site-Url")

		if apiKey == "" || siteURL == "" {
			http.Error(w, "missing auth", http.StatusUnauthorized)
			return
		}

		// hash(apiKey) to lookup site
		// site, err := db.LookupSiteByApiKeyHash(hash(apiKey))
		// if err != nil || !site.IsEnabled {
		// 	http.Error(w, "invalid api key", http.StatusUnauthorized)
		// 	return
		// }

		// if !domainsMatch(site.Domain, siteURL) {
		// 	http.Error(w, "domain mismatch", http.StatusForbidden)
		// 	return
		// }

		if stripePmtChecker == nil {
			http.Error(w, "billing unavailable", http.StatusServiceUnavailable)
			return
		}

		if err := stripePmtChecker.ValidatePaidAccess(r.Context(), apiKey, siteURL); err != nil {
			http.Error(w, "subscription required", http.StatusPaymentRequired)
			return
		}

		next.ServeHTTP(w, r)
	})
}
