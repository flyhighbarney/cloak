package api

// Dims is a fixed-key dimension set. See internal/obs/meter/names.go for the
// complete vocabulary. Free-form keys at emission sites are a linter failure.
type Dims map[DimKey]string

// Meter is the telemetry contract. Implementations may back Prometheus,
// OpenTelemetry, or in-memory (for tests).
type Meter interface {
	APIVersion() string
	Counter(n MetricName, dims Dims) Counter
	Histogram(n MetricName, dims Dims) Histogram
	Gauge(n MetricName, dims Dims) Gauge
}

type Counter interface {
	Inc()
	Add(delta float64)
}

type Histogram interface {
	Observe(value float64)
}

type Gauge interface {
	Set(value float64)
	Add(delta float64)
}
