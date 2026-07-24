package meter

import (
	"fmt"
	"sort"
	"sync"

	"github.com/prometheus/client_golang/prometheus"

	"cloakline/internal/api"
)

// PromMeter implements api.Meter over a Prometheus registry.
type PromMeter struct {
	reg       *prometheus.Registry
	mu        sync.Mutex
	counters  map[api.MetricName]*prometheus.CounterVec
	gauges    map[api.MetricName]*prometheus.GaugeVec
	histos    map[api.MetricName]*prometheus.HistogramVec
	dimLabels map[api.MetricName][]string
}

// New constructs a PromMeter and pre-registers every metric declared in
// AllMetrics with an empty label baseline. First use of a metric picks up
// dimension labels from the emission site.
func New(reg *prometheus.Registry) *PromMeter {
	return &PromMeter{
		reg:       reg,
		counters:  make(map[api.MetricName]*prometheus.CounterVec),
		gauges:    make(map[api.MetricName]*prometheus.GaugeVec),
		histos:    make(map[api.MetricName]*prometheus.HistogramVec),
		dimLabels: make(map[api.MetricName][]string),
	}
}

func (m *PromMeter) APIVersion() string { return api.MeterAPIVersion }

// Registry exposes the underlying Prometheus registry so the /metrics
// handler can serve it.
func (m *PromMeter) Registry() *prometheus.Registry { return m.reg }

func (m *PromMeter) Counter(n api.MetricName, dims api.Dims) api.Counter {
	labels := dimKeys(dims)
	vec := m.counterVec(n, labels)
	return promCounter{vec.WithLabelValues(dimValues(dims, labels)...)}
}

func (m *PromMeter) Gauge(n api.MetricName, dims api.Dims) api.Gauge {
	labels := dimKeys(dims)
	vec := m.gaugeVec(n, labels)
	return promGauge{vec.WithLabelValues(dimValues(dims, labels)...)}
}

func (m *PromMeter) Histogram(n api.MetricName, dims api.Dims) api.Histogram {
	labels := dimKeys(dims)
	vec := m.histoVec(n, labels, bucketsFor(n))
	return promHisto{vec.WithLabelValues(dimValues(dims, labels)...)}
}

func (m *PromMeter) counterVec(n api.MetricName, labels []string) *prometheus.CounterVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.counters[n]; ok {
		m.assertLabels(n, labels)
		return v
	}
	v := prometheus.NewCounterVec(prometheus.CounterOpts{Name: string(n)}, labels)
	m.reg.MustRegister(v)
	m.counters[n] = v
	m.dimLabels[n] = labels
	return v
}

func (m *PromMeter) gaugeVec(n api.MetricName, labels []string) *prometheus.GaugeVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.gauges[n]; ok {
		m.assertLabels(n, labels)
		return v
	}
	v := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: string(n)}, labels)
	m.reg.MustRegister(v)
	m.gauges[n] = v
	m.dimLabels[n] = labels
	return v
}

func (m *PromMeter) histoVec(n api.MetricName, labels []string, buckets []float64) *prometheus.HistogramVec {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.histos[n]; ok {
		m.assertLabels(n, labels)
		return v
	}
	v := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    string(n),
		Buckets: buckets,
	}, labels)
	m.reg.MustRegister(v)
	m.histos[n] = v
	m.dimLabels[n] = labels
	return v
}

func (m *PromMeter) assertLabels(n api.MetricName, got []string) {
	want := m.dimLabels[n]
	if len(want) != len(got) {
		panic(fmt.Sprintf("meter: %s label set changed: want %v got %v", n, want, got))
	}
	for i := range want {
		if want[i] != got[i] {
			panic(fmt.Sprintf("meter: %s label set changed: want %v got %v", n, want, got))
		}
	}
}

func dimKeys(dims api.Dims) []string {
	keys := make([]string, 0, len(dims))
	for k := range dims {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	return keys
}

func dimValues(dims api.Dims, sortedKeys []string) []string {
	vs := make([]string, len(sortedKeys))
	for i, k := range sortedKeys {
		vs[i] = dims[api.DimKey(k)]
	}
	return vs
}

func bucketsFor(n api.MetricName) []float64 {
	switch n {
	case MetricRequestDurationSeconds, MetricStageDurationSeconds,
		MetricDLPScanDurationSecs, MetricUpstreamDurationSecs,
		MetricRoutePolicyEvalSecs, MetricStreamTTFB:
		return DurationBuckets
	case MetricRequestBytesIn, MetricRequestBytesOut:
		return SizeBuckets
	}
	return DurationBuckets
}

// -------- adapter types --------

type promCounter struct{ c prometheus.Counter }

func (p promCounter) Inc()                { p.c.Inc() }
func (p promCounter) Add(delta float64)   { p.c.Add(delta) }

type promGauge struct{ g prometheus.Gauge }

func (p promGauge) Set(v float64)         { p.g.Set(v) }
func (p promGauge) Add(delta float64)     { p.g.Add(delta) }

type promHisto struct{ h prometheus.Observer }

func (p promHisto) Observe(v float64) { p.h.Observe(v) }
