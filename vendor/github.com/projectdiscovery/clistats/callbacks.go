package clistats

import "time"

// RequestPerSecondCallbackOptions returns a callback function which
// generates requests per second metrics based on total requests and
// time elapsed since the scan.
type RequestPerSecondCallbackOptions struct {
	// StartTimeFieldID is the ID of the start time field for the client.
	StartTimeFieldID string
	// RequestsCounterID is the ID of the request sent counter
	RequestsCounterID string
}

// NewRequestsPerSecondCallback creates a request per second callback function.
func NewRequestsPerSecondCallback(options RequestPerSecondCallbackOptions) DynamicCallback {
	return func(client StatisticsClient) interface{} {
		start, ok := client.GetStatic(options.StartTimeFieldID)
		if !ok {
			return nil
		}
		startTime, ok := start.(time.Time)
		if !ok {
			return nil
		}

		requests, ok := client.GetCounter(options.RequestsCounterID)
		if !ok {
			return nil
		}
		return uint64(float64(requests) / time.Since(startTime).Seconds())
	}
}
