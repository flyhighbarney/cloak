// Package meter is the Prometheus-backed implementation of api.Meter.
//
// Metric names and dimension keys are constants in this file. Emission sites
// reference the constants — free-form strings are a lint failure.
//
// See docs/telemetry.md for the complete vocabulary.
package meter

import "cloakline/internal/api"

// Metric names. Prefix `cloakline_` for consistency.
const (
	MetricRequestsTotal          api.MetricName = "cloakline_requests_total"
	MetricRequestsInFlight       api.MetricName = "cloakline_requests_in_flight"
	MetricRequestDurationSeconds api.MetricName = "cloakline_request_duration_seconds"
	MetricRequestBytesIn         api.MetricName = "cloakline_request_bytes_in"
	MetricRequestBytesOut        api.MetricName = "cloakline_request_bytes_out"

	MetricStageDurationSeconds api.MetricName = "cloakline_stage_duration_seconds"
	MetricStageErrorsTotal     api.MetricName = "cloakline_stage_errors_total"
	MetricStageSkippedTotal    api.MetricName = "cloakline_stage_skipped_total"

	MetricDLPFindingsTotal      api.MetricName = "cloakline_dlp_findings_total"
	MetricDLPScanDurationSecs   api.MetricName = "cloakline_dlp_scan_duration_seconds"
	MetricVaultActiveSessions   api.MetricName = "cloakline_vault_active_sessions"

	MetricRouteDecisionsTotal   api.MetricName = "cloakline_route_decisions_total"
	MetricRouteNoCandidateTotal api.MetricName = "cloakline_route_no_candidate_total"
	MetricRoutePolicyEvalSecs   api.MetricName = "cloakline_route_policy_eval_seconds"

	MetricUpstreamRequestsTotal   api.MetricName = "cloakline_upstream_requests_total"
	MetricUpstreamErrorsTotal     api.MetricName = "cloakline_upstream_errors_total"
	MetricUpstreamDurationSecs    api.MetricName = "cloakline_upstream_duration_seconds"
	MetricUpstreamHealth          api.MetricName = "cloakline_upstream_health"
	MetricUpstreamTokensInTotal   api.MetricName = "cloakline_upstream_tokens_in_total"
	MetricUpstreamTokensOutTotal  api.MetricName = "cloakline_upstream_tokens_out_total"

	MetricStreamTTFB              api.MetricName = "cloakline_stream_ttfb_seconds"
	MetricStreamChunkCount        api.MetricName = "cloakline_stream_chunk_count"
	MetricStreamBackpressureTotal api.MetricName = "cloakline_stream_backpressure_events_total"

	MetricAuthFailuresTotal       api.MetricName = "cloakline_auth_failures_total"
	MetricAuthKeyExpiriesTotal    api.MetricName = "cloakline_auth_key_expiries_total"

	MetricConfigHash              api.MetricName = "cloakline_config_hash"
	MetricConfigLoadTimestampSecs api.MetricName = "cloakline_config_load_timestamp_seconds"
	MetricComponentVersion        api.MetricName = "cloakline_component_version"
	MetricMetricCardinality       api.MetricName = "cloakline_metric_cardinality"
)

// Dimension keys.
const (
	DimTenant       api.DimKey = "tenant"
	DimPrincipal    api.DimKey = "principal"
	DimStage        api.DimKey = "stage"
	DimOutcome      api.DimKey = "outcome"
	DimUpstream     api.DimKey = "upstream"
	DimUpstreamKind api.DimKey = "upstream_kind"
	DimRoutePolicy  api.DimKey = "route_policy"
	DimMode         api.DimKey = "mode"
	DimModality     api.DimKey = "modality"
	DimFindingKind  api.DimKey = "finding_kind"
	DimErrorClass   api.DimKey = "error_class"
	DimComponent    api.DimKey = "component"
	DimImpl         api.DimKey = "impl"
	DimVersion      api.DimKey = "version"
)

// AllMetrics is enumerated for boot-time registration verification.
var AllMetrics = []api.MetricName{
	MetricRequestsTotal, MetricRequestsInFlight, MetricRequestDurationSeconds,
	MetricRequestBytesIn, MetricRequestBytesOut,
	MetricStageDurationSeconds, MetricStageErrorsTotal, MetricStageSkippedTotal,
	MetricDLPFindingsTotal, MetricDLPScanDurationSecs, MetricVaultActiveSessions,
	MetricRouteDecisionsTotal, MetricRouteNoCandidateTotal, MetricRoutePolicyEvalSecs,
	MetricUpstreamRequestsTotal, MetricUpstreamErrorsTotal, MetricUpstreamDurationSecs,
	MetricUpstreamHealth, MetricUpstreamTokensInTotal, MetricUpstreamTokensOutTotal,
	MetricStreamTTFB, MetricStreamChunkCount, MetricStreamBackpressureTotal,
	MetricAuthFailuresTotal, MetricAuthKeyExpiriesTotal,
	MetricConfigHash, MetricConfigLoadTimestampSecs, MetricComponentVersion,
	MetricMetricCardinality,
}

// AllDims is enumerated for lint-side validation.
var AllDims = []api.DimKey{
	DimTenant, DimPrincipal, DimStage, DimOutcome, DimUpstream, DimUpstreamKind,
	DimRoutePolicy, DimMode, DimModality, DimFindingKind, DimErrorClass,
	DimComponent, DimImpl, DimVersion,
}

// Standard histogram buckets.
var (
	DurationBuckets = []float64{
		0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30,
	}
	SizeBuckets = []float64{
		128, 512, 2048, 8192, 32768, 131072, 524288, 2097152, 8388608,
	}
)
