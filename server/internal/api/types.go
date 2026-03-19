package api

type PerformancePayload struct {
	MillisecondPerf float64 `json:"ms_perf"`
}

type HistoricalLatency struct {
	MaxLatency     float64 `json:"max_latency"`
	MinLatency     float64 `json:"min_latency"`
	SampleCount    int     `json:"sample_count"`
	AverageLatency float64 `json:"average_latency"`
	MedianLatency  float64 `json:"median_latency"`
}
