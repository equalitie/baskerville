package api

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"sort"
	"sync"
)

var (
	performanceTracker   = make(map[string][]float64)
	performanceTrackerMu sync.RWMutex
)

// inform prediction pipeline of the new request received from worker using the channel
func HandlePredictionDataDelivery(apiToProducer chan []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBytes, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		select {
		case apiToProducer <- receivedBytes:
			w.WriteHeader(http.StatusNoContent) //ack write to channel
		default:
			http.Error(w, ">:(", http.StatusTooManyRequests)
		}
	})
}

func HandlePerformanceTracker(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	receivedBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	siteURL := r.Header.Get("X-WPSEC-Site-Url")
	if siteURL == "" {
		http.Error(w, "site url unknown", http.StatusBadRequest)
		return
	}

	var perf PerformancePayload
	err = json.Unmarshal(receivedBytes, &perf)
	if err != nil {
		http.Error(w, "expect perf tracker payload", http.StatusBadRequest)
		return
	}

	performanceTrackerMu.Lock()
	defer performanceTrackerMu.Unlock()

	performanceTracker[siteURL] = append(performanceTracker[siteURL], perf.MillisecondPerf)

	w.WriteHeader(http.StatusNoContent)
	log.Printf("Updated performance for site: %s", siteURL)
}

// USAGE:
// curl "https://greything.com/wpsec/historical_latency?url=https://example.com"
func HandleLookupPerformanceQuery(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	queryParams := r.URL.Query()
	siteUrl := queryParams.Get("url")

	if siteUrl == "" {
		http.Error(w, "Missing site url", http.StatusBadRequest)
		return
	}

	performanceTrackerMu.RLock()
	defer performanceTrackerMu.RUnlock()

	res, ok := performanceTracker[siteUrl]
	if !ok {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}

	historicalPerformanceAsBytes, err := json.Marshal(res)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(historicalPerformanceAsBytes)
}

// USAGE:
// curl "https://greything.com/wpsec/latency_stats?url=https://example.com"
func HandleLatencyStats(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	queryParams := r.URL.Query()
	siteURL := queryParams.Get("url")
	if siteURL == "" {
		http.Error(w, "missing site url", http.StatusBadRequest)
		return
	}

	//copy out the slice under read lock to avoid races and to not mutate shared slice when sorting
	performanceTrackerMu.RLock()
	values, ok := performanceTracker[siteURL]
	if !ok || len(values) == 0 {
		performanceTrackerMu.RUnlock()
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	latencies := make([]float64, len(values))
	copy(latencies, values)
	performanceTrackerMu.RUnlock()

	// Compute stats
	var (
		min = latencies[0]
		max = latencies[0]
		sum float64
		n   = len(latencies)
	)

	for _, v := range latencies {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
		sum += v
	}
	avg := sum / float64(n)

	// median: sort a local copy
	sort.Float64s(latencies)
	var median float64
	if n%2 == 1 {
		median = latencies[n/2]
	} else {
		median = (latencies[n/2-1] + latencies[n/2]) / 2
	}

	stats := HistoricalLatency{
		MaxLatency:     max,
		MinLatency:     min,
		SampleCount:    n,
		AverageLatency: avg,
		MedianLatency:  median,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	err := json.NewEncoder(w).Encode(stats)
	if err != nil {
		// best-effort error handling; at this point headers are already written
		log.Printf("Error while encoding stats: %v", err)
		return
	}
}

/*
mux treats all undefined endpoints as root / and returns 404. (unless you explicitly admit a "/" at
which point just all undefined endpoint). We will keep this behaviour but just log it too such
that we can see attempts to contact our server and not signal any other info to those probing.
*/
func HandleCatchall(w http.ResponseWriter, r *http.Request) {
	log.Printf("ErrEndpointDoesNotExist: Attempted to contact: %s\n", r.URL.Path)
	http.NotFound(w, r)
}

/*
defined in the dockerfile such that we can check health of container
no need to log, it's here such that if it doesn't respond after 30 seconds, we consider
it to have failed, at which point kubernetes will redeploy and log
*/
func HandleHealthCheck(w http.ResponseWriter, r *http.Request) {
	/*
		check if the X-Forwarded-For header is set. We use this because any request coming from
		outside the cluster will have its IP set, but since health checks are ONLY meant to be invoked
		by the cluster, they will not (if invoked by the cluster) so we will just return 404 for any attempt
		at health checking from outside the cluster but return 200 for health checks internal to the cluster
	*/
	xForwardedFor := r.Header.Get("X-Forwarded-For")
	//assuming health checks won't have this header set
	if xForwardedFor == "" {
		//Respond with 200 OK for health check
		w.WriteHeader(http.StatusOK)
	} else {
		/*
			for external requests, you might want to hide the endpoint or mimic a different response
			mimicking a 404 Not Found response for external requests. Log requests originating from outside
		*/
		log.Printf("Received EXTERNAL request to health check endpoint: Method: %s, Path: %s, IP: %s\n", r.Method, r.URL.Path, xForwardedFor)
		http.NotFound(w, r)
	}
}
