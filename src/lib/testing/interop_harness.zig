//! Semantic route definitions for the shared local interop harness.

const std = @import("std");
const types = @import("../types.zig");
const server_types = @import("../server/types.zig");
const fixture_loader = @import("fixture_loader.zig");

/// Stable route identifier from the interop harness contract.
pub const RouteId = enum {
    /// `GET /health`
    health,
    /// `GET /echo`
    echo_get,
    /// `POST /echo`
    echo_post,
    /// `GET /redirect/{count}`
    redirect_count,
    /// `GET /cookies/set`
    cookies_set,
    /// `GET /cookies/read`
    cookies_read,
    /// `GET /stream/chunked`
    stream_chunked,
    /// `GET /stream/large`
    stream_large,
};

/// Response behavior expected from a route.
pub const ResponseMode = enum {
    /// JSON object response.
    json,
    /// Empty success response.
    no_content,
    /// Redirect response with a `Location` header.
    redirect,
    /// Chunked or streamed text payload.
    text_stream,
    /// Binary payload suitable for backpressure validation.
    binary_stream,
};

/// Socket transport used by a harness scenario.
pub const Transport = enum {
    /// TCP listener or client flow.
    tcp,
    /// UDP datagram listener or client flow.
    udp,
};

/// Endpoint metadata attached to a harness scenario.
pub const Endpoint = struct {
    /// Host advertised by the harness.
    host: []const u8,
    /// Port advertised by the harness.
    port: types.Port,
    /// Socket transport used by the scenario.
    transport: Transport,
    /// Application protocol expected on the endpoint.
    protocol: types.NegotiatedProtocol,
};

/// Stable capability identifier used by the local interoperability matrix.
pub const CapabilityFeatureId = enum {
    /// Server-side exact routing and fallback.
    server_routing,
    /// Server-side shared middleware execution.
    server_middleware,
    /// Server-side static file publication.
    server_static_files,
    /// Server-side response compression.
    server_compression,
    /// Server-side WebSocket endpoints.
    server_websocket,
    /// Client-side automatic decompression.
    client_decompression,
    /// Client-side multipart form submission.
    client_multipart,
    /// Client-side retry policy handling.
    client_retry,
    /// Client-side cache policy handling.
    client_cache,
    /// Client-side WebSocket sessions.
    client_websocket,
    /// Cross-protocol hardening and isolation coverage.
    hardening_matrix,
};

/// Typed capability entry for one higher-level feature and protocol pairing.
pub const CapabilityMatrixEntry = struct {
    /// Stable feature identifier.
    feature: CapabilityFeatureId,
    /// Higher-level surface that owns the feature.
    surface: types.FeatureSurface,
    /// Negotiated protocol being classified.
    protocol: types.NegotiatedProtocol,
    /// Support classification for the pairing.
    support: types.FeatureSupportLevel,
    /// Optional explanatory note for downgraded or unsupported pairings.
    notes: ?[]const u8,

    /// Returns the generic protocol capability view for the entry.
    pub fn asProtocolCapability(self: CapabilityMatrixEntry) types.ProtocolFeatureCapability {
        return .{
            .feature_name = @tagName(self.feature),
            .surface = self.surface,
            .protocol = self.protocol,
            .support = self.support,
            .notes = self.notes,
        };
    }
};

/// Network boundary exercised by one hardening profile or peer.
pub const NetworkMode = enum {
    /// Single-process or loopback-only coverage.
    loopback,
    /// Controlled host-local multi-process coverage.
    multiprocess,
};

/// Startup command metadata for one local hardening peer.
pub const StartupCommand = struct {
    /// Working directory used to start the peer.
    cwd: []const u8,
    /// Argument vector used to start the peer.
    argv: []const []const u8,
};

/// Typed interop peer descriptor loaded from fixture metadata.
pub const PeerDescriptor = struct {
    /// Stable fixture identifier.
    id: fixture_loader.InteropPeerFixtureId,
    /// Human-readable peer name.
    name: []const u8,
    /// Loopback host exposed by the peer.
    host: []const u8,
    /// Port exposed by the peer.
    port: types.Port,
    /// Socket transport used by the peer.
    transport: Transport,
    /// Primary negotiated protocol exercised by the peer.
    protocol: types.NegotiatedProtocol,
    /// Network boundary represented by the peer.
    network_mode: NetworkMode,
    /// Capability features expected from the peer.
    capabilities: []const CapabilityFeatureId,
    /// Startup command for the repository-owned peer.
    startup: StartupCommand,

    /// Returns the endpoint metadata represented by the peer.
    pub fn endpoint(self: PeerDescriptor) Endpoint {
        return .{
            .host = self.host,
            .port = self.port,
            .transport = self.transport,
            .protocol = self.protocol,
        };
    }
};

/// Owned peer descriptor retaining JSON-backed memory in an arena.
pub const LoadedPeerDescriptor = struct {
    /// Arena holding the JSON-backed strings and arrays.
    arena: std.heap.ArenaAllocator,
    /// Parsed peer descriptor.
    descriptor: PeerDescriptor,

    /// Releases the owned arena-backed descriptor memory.
    pub fn deinit(self: *LoadedPeerDescriptor) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Typed interop protocol profile loaded from fixture metadata.
pub const ProtocolProfile = struct {
    /// Stable profile fixture identifier.
    id: fixture_loader.InteropProtocolProfileId,
    /// Primary negotiated protocol covered by the profile.
    protocol: types.NegotiatedProtocol,
    /// Network boundary represented by the profile.
    network_mode: NetworkMode,
    /// Number of eligible flows admitted by the profile.
    eligible_flows: usize,
    /// Number of flows excluded before admission.
    excluded_flows: usize,
    /// Number of admitted flows that still failed.
    failure_count: usize,
    /// Capability features that must remain classified for the profile.
    required_capabilities: []const CapabilityFeatureId,
    /// Optional explanatory note for the profile.
    notes: ?[]const u8,
};

/// Owned protocol profile retaining JSON-backed memory in an arena.
pub const LoadedProtocolProfile = struct {
    /// Arena holding the JSON-backed strings and arrays.
    arena: std.heap.ArenaAllocator,
    /// Parsed protocol profile.
    profile: ProtocolProfile,

    /// Releases the owned arena-backed profile memory.
    pub fn deinit(self: *LoadedProtocolProfile) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Per-protocol workload metrics used by the local hardening report.
pub const ProtocolFlowMetrics = struct {
    /// Protocol covered by the workload slice.
    protocol: types.NegotiatedProtocol,
    /// Number of eligible flows admitted for the protocol.
    eligible_flows: usize,
    /// Number of flows excluded before admission.
    excluded_flows: usize,
    /// Number of admitted flows that still failed.
    failure_count: usize,
};

/// Aggregated hardening metrics used to validate the local reliability threshold.
pub const HardeningWorkloadMetrics = struct {
    /// Per-protocol workload contribution to the total run.
    protocol_mix: [3]ProtocolFlowMetrics,
    /// Total admitted eligible flows across the workload.
    total_eligible_flows: usize,
    /// Total excluded flows across the workload.
    excluded_flows: usize,
    /// Total admitted failures across the workload.
    failure_count: usize,

    /// Returns the number of admitted flows that completed successfully.
    pub fn successCount(self: HardeningWorkloadMetrics) usize {
        return self.total_eligible_flows - @min(self.total_eligible_flows, self.failure_count);
    }

    /// Returns the observed success ratio across admitted flows.
    pub fn successRatio(self: HardeningWorkloadMetrics) f64 {
        if (self.total_eligible_flows == 0) {
            return 0;
        }
        return @as(f64, @floatFromInt(self.successCount())) /
            @as(f64, @floatFromInt(self.total_eligible_flows));
    }

    /// Returns true when the workload satisfies the local reliability threshold.
    pub fn passesReliabilityThreshold(self: HardeningWorkloadMetrics) bool {
        if (self.total_eligible_flows < 1000 or self.successRatio() < 0.99) {
            return false;
        }
        for (self.protocol_mix) |entry| {
            if (entry.eligible_flows == 0) {
                return false;
            }
        }
        return true;
    }
};

/// Declarative local harness scenario used across client, server, and CLI tests.
pub const Scenario = struct {
    /// Stable route identifier.
    route: RouteId,
    /// Method expected by the route.
    method: types.Method,
    /// Path template from the harness contract.
    path_template: []const u8,
    /// Protocols supported by the route.
    protocols_supported: []const types.NegotiatedProtocol,
    /// Expected success status for the route.
    success_status: types.Status,
    /// Response behavior mode.
    response_mode: ResponseMode,
    /// Content type returned by the route when applicable.
    content_type: ?[]const u8,
    /// Whether the route participates in TLS scenarios.
    tls_supported: bool,
    /// Optional negative-case note for dedicated failure tests.
    negative_case: ?[]const u8,

    /// Returns true when the route supports the protocol.
    pub fn supportsProtocol(self: Scenario, protocol: types.NegotiatedProtocol) bool {
        for (self.protocols_supported) |candidate| {
            if (candidate == protocol) {
                return true;
            }
        }
        return false;
    }
};

/// Semantic request shared across TCP and UDP harness implementations.
pub const SemanticRequest = struct {
    /// HTTP method for the request.
    method: types.Method,
    /// Request path without a query suffix.
    path: []const u8,
    /// Optional query string without a leading `?`.
    query: ?[]const u8,
    /// Negotiated application protocol for the route.
    negotiated_protocol: types.NegotiatedProtocol,
    /// Fully buffered request body.
    body: []const u8,
    /// Observed `Cookie` header, if present.
    cookie_header: ?[]const u8,
};

/// Owned response returned by the semantic harness helpers.
pub const SemanticResponse = struct {
    /// Allocator used for headers and body storage.
    allocator: std.mem.Allocator,
    /// Response status code.
    status: types.Status,
    /// Response headers.
    headers: types.Headers,
    /// Fully buffered response body.
    body: []u8,

    /// Releases the owned headers and body bytes.
    pub fn deinit(self: *SemanticResponse) void {
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

/// Stable identifier for a local ALPN peer profile used by feature tests.
pub const AlpnPeerProfileId = enum {
    /// Peer advertises both `h2` and `http/1.1` and should select `h2`.
    dual_alpn,
    /// Peer advertises only `http/1.1`.
    http1_only,
    /// Peer omits ALPN from the final handshake outcome.
    omits_alpn,
    /// Peer returns a selected ALPN token outside the supported set.
    unsupported_protocol,
};

/// Expected client-visible result for an ALPN peer profile.
pub const AlpnExpectedOutcome = enum {
    /// Successful HTTP/2 routing.
    h2,
    /// Successful HTTP/1.1 routing.
    http_1_1,
    /// Reject the connection before HTTP handling begins.
    reject_before_http,
};

/// Failure phase expected from a local ALPN peer profile.
pub const AlpnFailurePhase = enum {
    /// No failure is expected.
    none,
    /// Failure occurs after ALPN but before HTTP request handling.
    protocol_routing_before_http,
};

/// Expected client-visible error category for an ALPN persona.
pub const AlpnClientFailure = enum {
    /// No failure is expected.
    none,
    /// Negotiation must fail before any HTTP request bytes are written.
    negotiation_failed,
};

/// Declarative ALPN persona used by local loopback verification.
pub const AlpnPeerProfile = struct {
    /// Stable persona identifier.
    id: AlpnPeerProfileId,
    /// Loopback host used by the persona.
    host: []const u8,
    /// Loopback port used by the persona.
    port: types.Port,
    /// ALPN protocols advertised by the peer during negotiation.
    advertised_protocols: []const types.NegotiatedProtocol,
    /// Whether the peer omits ALPN from the final handshake result.
    omits_alpn: bool,
    /// Raw ALPN token selected by the peer, when one is returned.
    selected_protocol_token: ?[]const u8,
    /// Expected client-visible outcome.
    expected_outcome: AlpnExpectedOutcome,
    /// Expected failure phase for negative personas.
    expected_failure_phase: AlpnFailurePhase,
    /// Expected client-visible failure for negative personas.
    expected_client_failure: AlpnClientFailure,
    /// Whether the persona is valid for TLS loopback verification.
    tls_supported: bool,
};

/// Expected local diagnostic emitted for a successful ALPN persona.
pub const AlpnSuccessDiagnostic = struct {
    /// Peer persona that produced the diagnostic.
    peer_profile: AlpnPeerProfileId,
    /// Negotiated protocol surfaced by the client path.
    negotiated_protocol: types.NegotiatedProtocol,
    /// HTTP version label expected on the local verification surface.
    response_version: types.Version,
};

/// Expected local diagnostic emitted for a failed ALPN persona.
pub const AlpnFailureDiagnostic = struct {
    /// Peer persona that produced the failure.
    peer_profile: AlpnPeerProfileId,
    /// Failure phase expected from the local harness flow.
    phase: AlpnFailurePhase,
    /// Client-visible failure category expected from the request path.
    client_failure: AlpnClientFailure,
};

/// Stream count with an explicit unit for multiplexing diagnostics.
pub const StreamCount = struct {
    /// Number of active or overlapping streams.
    count: usize,

    /// Creates a stream count from the provided value.
    pub fn init(count: usize) StreamCount {
        return .{ .count = count };
    }

    /// Returns the raw stream count.
    pub fn toInt(self: StreamCount) usize {
        return self.count;
    }
};

/// Stable identifier for an HTTP/2 multiplexing validation scenario.
pub const MultiplexingScenarioId = enum {
    /// Concurrent `/health` and `/echo` requests share one H2 connection.
    concurrent_health_echo,
    /// Slow-consumer pressure exercises stream and connection backpressure.
    slow_consumer_large_body,
    /// One reset stream fails without corrupting healthy peers.
    rst_stream_isolated,
    /// `GOAWAY` drains the shared connection and blocks new admissions.
    goaway_drains_connection,
};

/// Scope classification for a blocked backpressure state.
pub const BackpressureScope = enum {
    /// One stream is blocked while others may still progress.
    stream,
    /// The shared connection budget blocks affected streams together.
    connection,
};

/// Scope classification for a failure outcome.
pub const FailureScope = enum {
    /// Failure is isolated to one stream.
    stream,
    /// Failure applies to the entire shared connection.
    connection,
};

/// Typed multiplexing diagnostic expectations for one local validation scenario.
pub const MultiplexingDiagnostics = struct {
    /// Expected shared-connection count observed by the validation surface.
    shared_connection_count: types.ConnectionCount,
    /// Minimum overlapping active streams observed during the scenario.
    minimum_overlapping_streams: StreamCount,
    /// Whether local validation must observe distinct stream identifiers.
    distinct_stream_ids_required: bool = false,
    /// Expected blocked scopes surfaced by the scenario.
    expected_backpressure_scopes: []const BackpressureScope,
    /// Expected failure scope surfaced by the scenario, if any.
    expected_failure_scope: ?FailureScope,
    /// Whether bounded buffering must be observable.
    bounded_buffering_required: bool,
    /// Whether blocked work must resume after capacity returns.
    resume_required: bool,
    /// Whether unrelated healthy streams must continue.
    unrelated_streams_continue: bool,
    /// Whether new requests must be rejected once drain begins.
    new_requests_rejected_after_drain: bool,
};

/// Declarative HTTP/2 multiplexing scenario shared across contracts and tests.
pub const MultiplexingScenario = struct {
    /// Stable scenario identifier.
    id: MultiplexingScenarioId,
    /// Human-readable scenario name.
    name: []const u8,
    /// Short summary of the validation contract.
    summary: []const u8,
    /// Dual-ALPN peer profile used by the scenario.
    peer_profile: AlpnPeerProfileId,
    /// Routes exercised by the scenario.
    routes: []const RouteId,
    /// Whether the scenario requires one reusable H2 connection.
    requires_shared_connection: bool,
    /// Typed diagnostics expected from the local harness.
    diagnostics: MultiplexingDiagnostics,
};

/// Required HTTP/3 critical stream retained by one runtime session.
pub const Http3CriticalStreamKind = enum {
    /// Unidirectional control stream carrying SETTINGS and GOAWAY.
    control,
    /// Unidirectional QPACK encoder stream.
    qpack_encoder,
    /// Unidirectional QPACK decoder stream.
    qpack_decoder,
};

/// Disturbance class admitted by a local HTTP/3 runtime scenario.
pub const Http3DisturbanceKind = enum {
    /// Random packet loss within the accepted local envelope.
    loss,
    /// Random packet duplication within the accepted local envelope.
    duplication,
    /// Datagram reordering within the accepted local envelope.
    reordering,
    /// Added per-datagram delay within the accepted local envelope.
    delay,
};

/// Stable identifier for a local HTTP/3 disturbance profile.
pub const LocalDisturbanceProfileId = enum {
    /// Basic packet-loss, duplication, reordering, and delay envelope.
    basic,
};

/// Listener and session expectations shared by real HTTP/3 runtime scenarios.
pub const Http3RuntimeExpectations = struct {
    /// Minimum number of sequential requests or sessions served without restart.
    sequential_requests_without_restart: usize,
    /// Minimum simultaneous sessions admitted by one listener.
    concurrent_sessions_minimum: types.ConnectionCount,
    /// Minimum overlapping streams admitted within one session.
    overlapping_streams_per_session_minimum: StreamCount,
};

/// Real-runtime semantics attached to one UDP HTTP/3 scenario.
pub const Http3RuntimeSemantics = struct {
    /// Critical streams that must exist before request exchange proceeds.
    required_critical_streams: []const Http3CriticalStreamKind,
    /// Whether the scenario requires connection-scoped QPACK state reuse.
    qpack_dynamic_state_required: bool = false,
    /// Accepted disturbance envelope for the scenario, when applicable.
    disturbance_profile: ?LocalDisturbanceProfileId = null,
    /// Disturbance classes covered by the scenario.
    disturbance_kinds: []const Http3DisturbanceKind = &.{},
    /// Distinct failure category expected for negative-path validation, if any.
    expected_failure_category: ?server_types.Http3FailureCategory = null,
    /// Listener and concurrency expectations shared by the runtime.
    expectations: Http3RuntimeExpectations,
};

/// UDP-focused HTTP/3 scenario metadata.
pub const Http3DatagramScenario = struct {
    /// Route served by the datagram scenario.
    route: RouteId,
    /// UDP endpoint used for the scenario.
    endpoint: Endpoint,
    /// Suggested maximum datagram size.
    max_datagram_size: usize,
    /// Maximum buffered application data for the scenario.
    datagram_budget: usize,
    /// Real-runtime semantics expected for the route.
    runtime: Http3RuntimeSemantics,
};

/// Host platform classification for release-readiness scenarios.
pub const ReadinessPlatform = enum {
    /// Microsoft Windows hosts.
    windows,
    /// Linux hosts.
    linux,
    /// macOS or Darwin hosts.
    macos,
};

/// Execution environment used to collect one platform evidence bundle.
pub const ReadinessEnvironment = enum {
    /// Direct execution on a Windows host.
    native_windows,
    /// Maintainer-controlled local Linux environment.
    local_linux,
    /// Host does not match one of the blocking release platforms.
    unsupported_host,
};

/// Evidence status used by the bounded release-readiness gates.
pub const ReleaseEvidenceStatus = enum {
    /// Local evidence was captured and satisfies the gate contract.
    verified,
    /// Local evidence exists, but the gate still remains blocked.
    partial,
    /// Local evidence was not captured for the gate.
    missing,
};

/// Stable identifier for one blocking release gate.
pub const ReleaseGateId = enum {
    /// Windows and Linux local readiness evidence.
    platform_readiness,
    /// Higher-level capability floor across HTTP/1.1, HTTP/2, and HTTP/3.
    protocol_capability_floor,
    /// Public README, CLI, and release-note alignment.
    public_story_alignment,
    /// Version, changelog, and tag-plan completeness.
    release_artifact_completeness,
};

/// Result classification for one blocking release gate.
pub const ReleaseGateStatus = enum {
    /// The gate satisfies the required evidence contract.
    passed,
    /// The gate remains blocked by partial or missing evidence.
    blocked,
};

/// Final status for one blocking release gate in the maintainer-facing record.
pub const ReleaseGateDecision = struct {
    /// Stable blocking gate identifier.
    gate_id: ReleaseGateId,
    /// Current pass-or-blocked result for the gate.
    status: ReleaseGateStatus,
    /// Stop condition that must be cleared before the gate can pass, if any.
    stop_condition: ?[]const u8,

    /// Returns true when this gate still blocks the release decision.
    pub fn blocksRelease(self: ReleaseGateDecision) bool {
        return self.status == .blocked;
    }
};

/// Final maintainer-facing record for the bounded `1.0.0` release decision.
pub const ReleaseDecisionRecord = struct {
    /// Candidate version under review.
    candidate_version: []const u8,
    /// Ordered results for the four blocking release gates.
    gate_results: [4]ReleaseGateDecision,

    /// Returns the overall release-decision status implied by the gate results.
    pub fn overallStatus(self: ReleaseDecisionRecord) ReleaseGateStatus {
        return releaseDecisionStatusForGateResults(&self.gate_results);
    }

    /// Returns true when every blocking gate is satisfied.
    pub fn approved(self: ReleaseDecisionRecord) bool {
        return self.overallStatus() == .passed;
    }

    /// Returns the recorded gate result for the requested identifier, if any.
    pub fn gateFor(self: ReleaseDecisionRecord, gate_id: ReleaseGateId) ?ReleaseGateDecision {
        for (self.gate_results) |gate| {
            if (gate.gate_id == gate_id) {
                return gate;
            }
        }
        return null;
    }

    /// Returns the first stop condition that still blocks the release, if any.
    pub fn firstBlockingStopCondition(self: ReleaseDecisionRecord) ?[]const u8 {
        for (self.gate_results) |gate| {
            if (gate.blocksRelease()) {
                return gate.stop_condition;
            }
        }
        return null;
    }
};

/// Stable identifier for a release-readiness scenario.
pub const ReadinessScenarioId = enum {
    /// Windows loopback `server` + `request` reproduction path.
    windows_loopback_cli_roundtrip,
    /// Linux loopback `server` + `request` reproduction path.
    linux_loopback_cli_roundtrip,
};

/// Shell command attached to a readiness scenario.
pub const ReadinessCommand = struct {
    /// Stable label for reporting.
    name: []const u8,
    /// Argument vector used to invoke the command.
    argv: []const []const u8,
};

/// Release-readiness scenario shared across docs, smoke checks, and regression tests.
pub const ReadinessScenario = struct {
    /// Stable scenario identifier.
    id: ReadinessScenarioId,
    /// Human-readable scenario name.
    name: []const u8,
    /// Short summary of the readiness contract.
    summary: []const u8,
    /// Platforms targeted by the scenario.
    platforms: []const ReadinessPlatform,
    /// Execution environment represented by the scenario.
    environment: ReadinessEnvironment,
    /// Harness route validated by the scenario.
    route: RouteId,
    /// Endpoint expected by the documented workflow.
    endpoint: Endpoint,
    /// Workspace cache root required by the documented release flow.
    workspace_cache_root: []const u8,
    /// Global cache root required by the documented release flow.
    global_cache_root: []const u8,
    /// Long-running server command started before the probe.
    server_command: ReadinessCommand,
    /// Probe command executed against the loopback server.
    request_command: ReadinessCommand,
    /// Expected success status from the request.
    expected_status: types.Status,
    /// Expected substring in the response body or diagnostics.
    expected_body_substring: []const u8,
    /// Whether the scenario blocks default release-readiness claims.
    blocking: bool,
    /// Known failure signature captured before the fix lands, if any.
    known_failure_signature: ?[]const u8,

    /// Returns true when the scenario targets the provided platform.
    pub fn supportsPlatform(self: ReadinessScenario, platform: ReadinessPlatform) bool {
        for (self.platforms) |candidate| {
            if (candidate == platform) {
                return true;
            }
        }
        return false;
    }
};

/// Platform-scoped evidence summary for the blocking readiness gate.
pub const PlatformReadinessEvidence = struct {
    /// Scenario that defines the platform evidence bundle.
    scenario: ReadinessScenario,
    /// Aggregate status for the platform bundle.
    status: ReleaseEvidenceStatus,
    /// Status specific to the CLI round-trip probe.
    cli_roundtrip_status: ReleaseEvidenceStatus,
    /// Short maintainer-facing summary for the bundle.
    summary: []const u8,
    /// Known failure signature or captured blocking diagnostic, if any.
    failure_signature: ?[]const u8,

    /// Returns true when the platform bundle still blocks the release.
    pub fn blocksRelease(self: PlatformReadinessEvidence) bool {
        return self.scenario.blocking and self.status != .verified;
    }
};

/// Protocol-scoped evidence summary for the blocking capability floor.
pub const ProtocolCapabilityEvidence = struct {
    /// Protocol represented by the evidence bundle.
    protocol: types.NegotiatedProtocol,
    /// Blocking higher-level features expected for the protocol.
    required_features: []const CapabilityFeatureId,
    /// Number of blocking features still classified as supported.
    satisfied_feature_count: usize,
    /// Status of the higher-level capability mapping.
    capability_status: ReleaseEvidenceStatus,
    /// Status of the real-runtime coverage requirement.
    runtime_status: ReleaseEvidenceStatus,

    /// Returns the overall status for the protocol bundle.
    pub fn overallStatus(self: ProtocolCapabilityEvidence) ReleaseEvidenceStatus {
        if (self.capability_status != .verified) {
            return self.capability_status;
        }
        if (self.protocol == .h3) {
            return self.runtime_status;
        }
        return .verified;
    }
};

/// Returns the gate status implied by one release-evidence state.
pub fn gateStatusForEvidence(status: ReleaseEvidenceStatus) ReleaseGateStatus {
    return if (status == .verified) .passed else .blocked;
}

/// Returns the overall release-decision status implied by the gate results.
pub fn releaseDecisionStatusForGateResults(
    gate_results: []const ReleaseGateDecision,
) ReleaseGateStatus {
    for (gate_results) |gate| {
        if (gate.blocksRelease()) {
            return .blocked;
        }
    }
    return .passed;
}

const route_protocols = [_]types.NegotiatedProtocol{ .http_1_1, .h2, .h3 };
const alpn_dual_protocols = [_]types.NegotiatedProtocol{ .h2, .http_1_1 };
const alpn_http1_only_protocols = [_]types.NegotiatedProtocol{.http_1_1};
const alpn_no_protocols = [_]types.NegotiatedProtocol{};
const windows_only_platforms = [_]ReadinessPlatform{.windows};
const linux_only_platforms = [_]ReadinessPlatform{.linux};
const no_backpressure_scopes = [_]BackpressureScope{};
const stream_and_connection_backpressure_scopes = [_]BackpressureScope{ .stream, .connection };
const http3_critical_streams = [_]Http3CriticalStreamKind{ .control, .qpack_encoder, .qpack_decoder };
const no_http3_disturbances = [_]Http3DisturbanceKind{};
const basic_http3_disturbances = [_]Http3DisturbanceKind{ .loss, .duplication, .reordering, .delay };
const health_echo_routes = [_]RouteId{ .health, .echo_get };
const large_body_routes = [_]RouteId{ .stream_large, .health };
const rst_stream_routes = [_]RouteId{ .stream_chunked, .health };
const goaway_routes = [_]RouteId{ .health, .echo_get };
/// Default peer-fixture identifiers used by the hardening matrix.
const default_peer_fixture_ids = [_]fixture_loader.InteropPeerFixtureId{ .server_app, .h2_peer, .h3_peer };
/// Default protocol-profile identifiers used by the hardening matrix.
const default_protocol_profile_ids = [_]fixture_loader.InteropProtocolProfileId{ .http1_baseline, .h2_multiplexed, .h3_quic };
/// Platforms that must each produce their own blocking evidence bundle.
pub const blocking_readiness_platforms = [_]ReadinessPlatform{ .windows, .linux };
/// Higher-level features that make up the blocking `1.0.0` capability floor.
pub const blocking_capability_features = [_]CapabilityFeatureId{
    .server_routing,
    .server_middleware,
    .server_static_files,
    .server_compression,
    .server_websocket,
    .client_decompression,
    .client_multipart,
    .client_retry,
    .client_cache,
    .client_websocket,
    .hardening_matrix,
};

/// JSON shape for one peer startup command fixture.
const JsonStartupCommand = struct {
    cwd: []const u8,
    argv: []const []const u8,
};

/// JSON shape for one peer descriptor fixture.
const JsonPeerDescriptor = struct {
    id: []const u8,
    name: []const u8,
    host: []const u8,
    port: u16,
    transport: []const u8,
    protocol: []const u8,
    network_mode: []const u8,
    capabilities: []const []const u8,
    startup: JsonStartupCommand,
};

/// JSON shape for one protocol-profile fixture.
const JsonProtocolProfile = struct {
    id: []const u8,
    protocol: []const u8,
    network_mode: []const u8,
    eligible_flows: usize,
    excluded_flows: usize,
    failure_count: usize,
    required_capabilities: []const []const u8,
    notes: ?[]const u8,
};
const default_capability_matrix = [_]CapabilityMatrixEntry{
    .{ .feature = .server_routing, .surface = .server, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .server_routing, .surface = .server, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .server_routing, .surface = .server, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .server_middleware, .surface = .server, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .server_middleware, .surface = .server, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .server_middleware, .surface = .server, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .server_static_files, .surface = .server, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .server_static_files, .surface = .server, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .server_static_files, .surface = .server, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .server_compression, .surface = .server, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .server_compression, .surface = .server, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .server_compression, .surface = .server, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .server_websocket, .surface = .server, .protocol = .http_1_1, .support = .supported, .notes = "upgrade handshake" },
    .{ .feature = .server_websocket, .surface = .server, .protocol = .h2, .support = .supported, .notes = "extended CONNECT handshake" },
    .{ .feature = .server_websocket, .surface = .server, .protocol = .h3, .support = .supported, .notes = "extended CONNECT handshake" },
    .{ .feature = .client_decompression, .surface = .client, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .client_decompression, .surface = .client, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .client_decompression, .surface = .client, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .client_multipart, .surface = .client, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .client_multipart, .surface = .client, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .client_multipart, .surface = .client, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .client_retry, .surface = .client, .protocol = .http_1_1, .support = .supported, .notes = "replay safety remains explicit" },
    .{ .feature = .client_retry, .surface = .client, .protocol = .h2, .support = .supported, .notes = "replay safety remains explicit" },
    .{ .feature = .client_retry, .surface = .client, .protocol = .h3, .support = .supported, .notes = "replay safety remains explicit" },
    .{ .feature = .client_cache, .surface = .client, .protocol = .http_1_1, .support = .supported, .notes = null },
    .{ .feature = .client_cache, .surface = .client, .protocol = .h2, .support = .supported, .notes = null },
    .{ .feature = .client_cache, .surface = .client, .protocol = .h3, .support = .supported, .notes = null },
    .{ .feature = .client_websocket, .surface = .client, .protocol = .http_1_1, .support = .supported, .notes = "upgrade handshake" },
    .{ .feature = .client_websocket, .surface = .client, .protocol = .h2, .support = .supported, .notes = "extended CONNECT handshake" },
    .{ .feature = .client_websocket, .surface = .client, .protocol = .h3, .support = .supported, .notes = "extended CONNECT handshake" },
    .{ .feature = .hardening_matrix, .surface = .hardening, .protocol = .http_1_1, .support = .supported, .notes = "loopback plus multi-process coverage" },
    .{ .feature = .hardening_matrix, .surface = .hardening, .protocol = .h2, .support = .supported, .notes = "loopback plus multiplexed coverage" },
    .{ .feature = .hardening_matrix, .surface = .hardening, .protocol = .h3, .support = .supported, .notes = "loopback plus UDP runtime coverage" },
};
const default_http3_runtime_expectations = Http3RuntimeExpectations{
    .sequential_requests_without_restart = 10,
    .concurrent_sessions_minimum = types.ConnectionCount.init(2),
    .overlapping_streams_per_session_minimum = StreamCount.init(2),
};
const windows_loopback_server_command = [_][]const u8{
    "zig",
    "build",
    "run",
    "--",
    "server",
    "--listen",
    "127.0.0.1",
    "--port",
    "18080",
};
const windows_loopback_request_command = [_][]const u8{
    "zig",
    "build",
    "run",
    "--",
    "request",
    "http://127.0.0.1:18080/health",
};
const linux_loopback_server_command = windows_loopback_server_command;
const linux_loopback_request_command = windows_loopback_request_command;

const default_alpn_peer_profiles = [_]AlpnPeerProfile{
    .{
        .id = .dual_alpn,
        .host = "127.0.0.1",
        .port = types.Port.init(18443),
        .advertised_protocols = &alpn_dual_protocols,
        .omits_alpn = false,
        .selected_protocol_token = "h2",
        .expected_outcome = .h2,
        .expected_failure_phase = .none,
        .expected_client_failure = .none,
        .tls_supported = true,
    },
    .{
        .id = .http1_only,
        .host = "127.0.0.1",
        .port = types.Port.init(19443),
        .advertised_protocols = &alpn_http1_only_protocols,
        .omits_alpn = false,
        .selected_protocol_token = "http/1.1",
        .expected_outcome = .http_1_1,
        .expected_failure_phase = .none,
        .expected_client_failure = .none,
        .tls_supported = true,
    },
    .{
        .id = .omits_alpn,
        .host = "127.0.0.1",
        .port = types.Port.init(20443),
        .advertised_protocols = &alpn_no_protocols,
        .omits_alpn = true,
        .selected_protocol_token = null,
        .expected_outcome = .http_1_1,
        .expected_failure_phase = .none,
        .expected_client_failure = .none,
        .tls_supported = true,
    },
    .{
        .id = .unsupported_protocol,
        .host = "127.0.0.1",
        .port = types.Port.init(21443),
        .advertised_protocols = &alpn_dual_protocols,
        .omits_alpn = false,
        .selected_protocol_token = "spdy/3",
        .expected_outcome = .reject_before_http,
        .expected_failure_phase = .protocol_routing_before_http,
        .expected_client_failure = .negotiation_failed,
        .tls_supported = true,
    },
};

const default_scenarios = [_]Scenario{
    .{
        .route = .health,
        .method = .get,
        .path_template = "/health",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "advertise mismatched negotiated protocol metadata",
    },
    .{
        .route = .echo_get,
        .method = .get,
        .path_template = "/echo",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "drop X-Echo metadata in the reflected response",
    },
    .{
        .route = .echo_post,
        .method = .post,
        .path_template = "/echo",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "report the wrong body size for echoed payloads",
    },
    .{
        .route = .redirect_count,
        .method = .get,
        .path_template = "/redirect/{count}",
        .protocols_supported = &route_protocols,
        .success_status = .found,
        .response_mode = .redirect,
        .content_type = null,
        .tls_supported = true,
        .negative_case = "omit the Location header on intermediate redirects",
    },
    .{
        .route = .cookies_set,
        .method = .get,
        .path_template = "/cookies/set",
        .protocols_supported = &route_protocols,
        .success_status = .no_content,
        .response_mode = .no_content,
        .content_type = null,
        .tls_supported = true,
        .negative_case = "emit an invalid Set-Cookie header",
    },
    .{
        .route = .cookies_read,
        .method = .get,
        .path_template = "/cookies/read",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .json,
        .content_type = "application/json",
        .tls_supported = true,
        .negative_case = "drop cookies that were set earlier in the scenario",
    },
    .{
        .route = .stream_chunked,
        .method = .get,
        .path_template = "/stream/chunked",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .text_stream,
        .content_type = "text/plain",
        .tls_supported = true,
        .negative_case = "truncate a chunked response before the terminating chunk",
    },
    .{
        .route = .stream_large,
        .method = .get,
        .path_template = "/stream/large",
        .protocols_supported = &route_protocols,
        .success_status = .ok,
        .response_mode = .binary_stream,
        .content_type = "application/octet-stream",
        .tls_supported = true,
        .negative_case = "close the stream before the declared large body completes",
    },
};

const default_readiness_scenarios = [_]ReadinessScenario{
    .{
        .id = .windows_loopback_cli_roundtrip,
        .name = "windows-cli-loopback-roundtrip",
        .summary = "Verify the documented Windows loopback /health round-trip through `zttp server` and `zttp request`.",
        .platforms = &windows_only_platforms,
        .environment = .native_windows,
        .route = .health,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(18080),
            .transport = .tcp,
            .protocol = .http_1_1,
        },
        .workspace_cache_root = ".tmp\\zig-cache-win",
        .global_cache_root = ".tmp\\zig-global-win",
        .server_command = .{
            .name = "server",
            .argv = &windows_loopback_server_command,
        },
        .request_command = .{
            .name = "request",
            .argv = &windows_loopback_request_command,
        },
        .expected_status = .ok,
        .expected_body_substring = "\"status\":\"ok\",\"protocol\":\"http/1.1\"",
        .blocking = true,
        .known_failure_signature = "GetLastError(87) surfaced from std.net.Stream.read",
    },
    .{
        .id = .linux_loopback_cli_roundtrip,
        .name = "linux-cli-loopback-roundtrip",
        .summary = "Verify the documented Linux loopback /health round-trip through `zttp server` and `zttp request`.",
        .platforms = &linux_only_platforms,
        .environment = .local_linux,
        .route = .health,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(18080),
            .transport = .tcp,
            .protocol = .http_1_1,
        },
        .workspace_cache_root = ".tmp/zig-cache-linux",
        .global_cache_root = ".tmp/zig-global-linux",
        .server_command = .{
            .name = "server",
            .argv = &linux_loopback_server_command,
        },
        .request_command = .{
            .name = "request",
            .argv = &linux_loopback_request_command,
        },
        .expected_status = .ok,
        .expected_body_substring = "\"status\":\"ok\",\"protocol\":\"http/1.1\"",
        .blocking = true,
        .known_failure_signature = null,
    },
};

const default_multiplexing_scenarios = [_]MultiplexingScenario{
    .{
        .id = .concurrent_health_echo,
        .name = "concurrent-health-echo",
        .summary = "Verify that overlapping /health and /echo requests reuse one shared HTTP/2 connection with distinct stream identities.",
        .peer_profile = .dual_alpn,
        .routes = &health_echo_routes,
        .requires_shared_connection = true,
        .diagnostics = .{
            .shared_connection_count = types.ConnectionCount.init(1),
            .minimum_overlapping_streams = StreamCount.init(2),
            .distinct_stream_ids_required = true,
            .expected_backpressure_scopes = &no_backpressure_scopes,
            .expected_failure_scope = null,
            .bounded_buffering_required = false,
            .resume_required = false,
            .unrelated_streams_continue = true,
            .new_requests_rejected_after_drain = false,
        },
    },
    .{
        .id = .slow_consumer_large_body,
        .name = "slow-consumer-large-body",
        .summary = "Verify that a slow large-body stream stays bounded, surfaces stream and connection pressure, and resumes after capacity returns.",
        .peer_profile = .dual_alpn,
        .routes = &large_body_routes,
        .requires_shared_connection = true,
        .diagnostics = .{
            .shared_connection_count = types.ConnectionCount.init(1),
            .minimum_overlapping_streams = StreamCount.init(2),
            .expected_backpressure_scopes = &stream_and_connection_backpressure_scopes,
            .expected_failure_scope = null,
            .bounded_buffering_required = true,
            .resume_required = true,
            .unrelated_streams_continue = true,
            .new_requests_rejected_after_drain = false,
        },
    },
    .{
        .id = .rst_stream_isolated,
        .name = "rst-stream-isolated",
        .summary = "Verify that one reset stream fails with stream scope while a healthy concurrent request continues on the same connection.",
        .peer_profile = .dual_alpn,
        .routes = &rst_stream_routes,
        .requires_shared_connection = true,
        .diagnostics = .{
            .shared_connection_count = types.ConnectionCount.init(1),
            .minimum_overlapping_streams = StreamCount.init(2),
            .expected_backpressure_scopes = &no_backpressure_scopes,
            .expected_failure_scope = .stream,
            .bounded_buffering_required = false,
            .resume_required = false,
            .unrelated_streams_continue = true,
            .new_requests_rejected_after_drain = false,
        },
    },
    .{
        .id = .goaway_drains_connection,
        .name = "goaway-drains-connection",
        .summary = "Verify that GOAWAY drains one shared connection, preserves a connection-scoped outcome, and rejects new admissions after drain begins.",
        .peer_profile = .dual_alpn,
        .routes = &goaway_routes,
        .requires_shared_connection = true,
        .diagnostics = .{
            .shared_connection_count = types.ConnectionCount.init(1),
            .minimum_overlapping_streams = StreamCount.init(2),
            .expected_backpressure_scopes = &no_backpressure_scopes,
            .expected_failure_scope = .connection,
            .bounded_buffering_required = false,
            .resume_required = false,
            .unrelated_streams_continue = false,
            .new_requests_rejected_after_drain = true,
        },
    },
};

const default_http3_datagram_scenarios = [_]Http3DatagramScenario{
    .{
        .route = .health,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 16 * 1024,
        .runtime = .{
            .required_critical_streams = &http3_critical_streams,
            .qpack_dynamic_state_required = false,
            .disturbance_profile = null,
            .disturbance_kinds = &no_http3_disturbances,
            .expected_failure_category = null,
            .expectations = default_http3_runtime_expectations,
        },
    },
    .{
        .route = .echo_get,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 16 * 1024,
        .runtime = .{
            .required_critical_streams = &http3_critical_streams,
            .qpack_dynamic_state_required = true,
            .disturbance_profile = null,
            .disturbance_kinds = &no_http3_disturbances,
            .expected_failure_category = null,
            .expectations = default_http3_runtime_expectations,
        },
    },
    .{
        .route = .echo_post,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 64 * 1024,
        .runtime = .{
            .required_critical_streams = &http3_critical_streams,
            .qpack_dynamic_state_required = true,
            .disturbance_profile = null,
            .disturbance_kinds = &no_http3_disturbances,
            .expected_failure_category = null,
            .expectations = default_http3_runtime_expectations,
        },
    },
    .{
        .route = .stream_large,
        .endpoint = .{
            .host = "127.0.0.1",
            .port = types.Port.init(4433),
            .transport = .udp,
            .protocol = .h3,
        },
        .max_datagram_size = 1200,
        .datagram_budget = 96 * 1024,
        .runtime = .{
            .required_critical_streams = &http3_critical_streams,
            .qpack_dynamic_state_required = false,
            .disturbance_profile = .basic,
            .disturbance_kinds = &basic_http3_disturbances,
            .expected_failure_category = .transport,
            .expectations = default_http3_runtime_expectations,
        },
    },
};

/// Returns the default peer fixtures used by the hardening matrix.
pub fn defaultPeerFixtures() []const fixture_loader.InteropPeerFixtureId {
    return &default_peer_fixture_ids;
}

/// Returns the default protocol profiles used by the hardening matrix.
pub fn defaultProtocolProfiles() []const fixture_loader.InteropProtocolProfileId {
    return &default_protocol_profile_ids;
}

/// Loads one typed peer descriptor from fixture metadata.
pub fn loadPeerDescriptor(
    allocator: std.mem.Allocator,
    loader: fixture_loader.Loader,
    id: fixture_loader.InteropPeerFixtureId,
) !LoadedPeerDescriptor {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const bytes = try loader.loadInteropPeer(arena_allocator, id);
    const json = try std.json.parseFromSliceLeaky(JsonPeerDescriptor, arena_allocator, bytes, .{
        .ignore_unknown_fields = false,
    });

    return .{
        .arena = arena,
        .descriptor = .{
            .id = try parsePeerFixtureId(json.id),
            .name = json.name,
            .host = json.host,
            .port = types.Port.init(json.port),
            .transport = try parseTransport(json.transport),
            .protocol = try parseNegotiatedProtocol(json.protocol),
            .network_mode = try parseNetworkMode(json.network_mode),
            .capabilities = try parseCapabilityFeatureList(arena_allocator, json.capabilities),
            .startup = .{
                .cwd = json.startup.cwd,
                .argv = json.startup.argv,
            },
        },
    };
}

/// Loads one typed protocol profile from fixture metadata.
pub fn loadProtocolProfile(
    allocator: std.mem.Allocator,
    loader: fixture_loader.Loader,
    id: fixture_loader.InteropProtocolProfileId,
) !LoadedProtocolProfile {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const arena_allocator = arena.allocator();

    const bytes = try loader.loadInteropProtocolProfile(arena_allocator, id);
    const json = try std.json.parseFromSliceLeaky(JsonProtocolProfile, arena_allocator, bytes, .{
        .ignore_unknown_fields = false,
    });

    return .{
        .arena = arena,
        .profile = .{
            .id = try parseProtocolProfileId(json.id),
            .protocol = try parseNegotiatedProtocol(json.protocol),
            .network_mode = try parseNetworkMode(json.network_mode),
            .eligible_flows = json.eligible_flows,
            .excluded_flows = json.excluded_flows,
            .failure_count = json.failure_count,
            .required_capabilities = try parseCapabilityFeatureList(arena_allocator, json.required_capabilities),
            .notes = json.notes,
        },
    };
}

/// Aggregates the default protocol profiles into local hardening workload metrics.
pub fn captureHardeningMetrics(
    allocator: std.mem.Allocator,
    loader: fixture_loader.Loader,
) !HardeningWorkloadMetrics {
    var protocol_mix: [3]ProtocolFlowMetrics = undefined;
    var total_eligible_flows: usize = 0;
    var excluded_flows: usize = 0;
    var failure_count: usize = 0;

    for (default_protocol_profile_ids, 0..) |profile_id, index| {
        var loaded = try loadProtocolProfile(allocator, loader, profile_id);
        defer loaded.deinit();

        protocol_mix[index] = .{
            .protocol = loaded.profile.protocol,
            .eligible_flows = loaded.profile.eligible_flows,
            .excluded_flows = loaded.profile.excluded_flows,
            .failure_count = loaded.profile.failure_count,
        };
        total_eligible_flows += loaded.profile.eligible_flows;
        excluded_flows += loaded.profile.excluded_flows;
        failure_count += loaded.profile.failure_count;
    }

    return .{
        .protocol_mix = protocol_mix,
        .total_eligible_flows = total_eligible_flows,
        .excluded_flows = excluded_flows,
        .failure_count = failure_count,
    };
}

/// Returns the default interop route catalog.
pub fn defaultScenarios() []const Scenario {
    return &default_scenarios;
}

/// Returns the default ALPN peer profile catalog for local loopback verification.
pub fn defaultAlpnPeerProfiles() []const AlpnPeerProfile {
    return &default_alpn_peer_profiles;
}

/// Returns the ALPN peer profile for the provided identifier, or null if absent.
pub fn alpnPeerProfileForId(id: AlpnPeerProfileId) ?AlpnPeerProfile {
    for (default_alpn_peer_profiles) |profile| {
        if (profile.id == id) {
            return profile;
        }
    }
    return null;
}

/// Returns the ALPN peer profile for the provided loopback endpoint, or null if absent.
pub fn alpnPeerProfileForEndpoint(host: []const u8, port: types.Port) ?AlpnPeerProfile {
    for (default_alpn_peer_profiles) |profile| {
        if (profile.port.toInt() != port.toInt()) {
            continue;
        }
        if (std.ascii.eqlIgnoreCase(profile.host, host)) {
            return profile;
        }
    }
    return null;
}

/// Returns the expected successful protocol diagnostic for a peer profile, if any.
pub fn successDiagnosticForPeerProfile(id: AlpnPeerProfileId) ?AlpnSuccessDiagnostic {
    const profile = alpnPeerProfileForId(id) orelse return null;
    return switch (profile.expected_outcome) {
        .h2 => .{
            .peer_profile = profile.id,
            .negotiated_protocol = .h2,
            .response_version = .http_2,
        },
        .http_1_1 => .{
            .peer_profile = profile.id,
            .negotiated_protocol = .http_1_1,
            .response_version = .http_1_1,
        },
        .reject_before_http => null,
    };
}

/// Returns the expected failure diagnostic for a peer profile, if any.
pub fn failureDiagnosticForPeerProfile(id: AlpnPeerProfileId) ?AlpnFailureDiagnostic {
    const profile = alpnPeerProfileForId(id) orelse return null;
    if (profile.expected_client_failure == .none) {
        return null;
    }

    return .{
        .peer_profile = profile.id,
        .phase = profile.expected_failure_phase,
        .client_failure = profile.expected_client_failure,
    };
}

/// Returns the route definition for the provided identifier, or null if absent.
pub fn scenarioForRoute(route: RouteId) ?Scenario {
    for (default_scenarios) |scenario| {
        if (scenario.route == route) {
            return scenario;
        }
    }
    return null;
}

/// Returns the default release-readiness scenarios.
pub fn defaultReadinessScenarios() []const ReadinessScenario {
    return &default_readiness_scenarios;
}

/// Returns the blocking release-readiness platforms.
pub fn blockingReadinessPlatforms() []const ReadinessPlatform {
    return &blocking_readiness_platforms;
}

/// Returns the blocking higher-level capability floor for the release decision.
pub fn blockingCapabilityFeatures() []const CapabilityFeatureId {
    return &blocking_capability_features;
}

/// Returns the typed higher-level capability matrix for local planning and tests.
pub fn defaultCapabilityMatrix() []const CapabilityMatrixEntry {
    return &default_capability_matrix;
}

/// Returns the capability entry for one feature and protocol, if any.
pub fn capabilityFor(
    feature: CapabilityFeatureId,
    protocol: types.NegotiatedProtocol,
) ?CapabilityMatrixEntry {
    for (default_capability_matrix) |entry| {
        if (entry.feature == feature and entry.protocol == protocol) {
            return entry;
        }
    }
    return null;
}

/// Returns the readiness scenario for the provided blocking platform, if any.
pub fn readinessScenarioForPlatform(platform: ReadinessPlatform) ?ReadinessScenario {
    for (default_readiness_scenarios) |scenario| {
        if (scenario.supportsPlatform(platform)) {
            return scenario;
        }
    }
    return null;
}

/// Returns the default HTTP/2 multiplexing validation scenarios.
pub fn defaultMultiplexingScenarios() []const MultiplexingScenario {
    return &default_multiplexing_scenarios;
}

/// Returns the release-readiness scenario for the provided identifier, if any.
pub fn readinessScenarioForId(id: ReadinessScenarioId) ?ReadinessScenario {
    for (default_readiness_scenarios) |scenario| {
        if (scenario.id == id) {
            return scenario;
        }
    }
    return null;
}

/// Returns true when the catalog still exposes the required HTTP/3 runtime routes.
pub fn hasBlockingHttp3RuntimeCoverage() bool {
    return http3DatagramScenarioForRoute(.health) != null and
        http3DatagramScenarioForRoute(.echo_get) != null and
        http3DatagramScenarioForRoute(.echo_post) != null and
        http3DatagramScenarioForRoute(.stream_large) != null;
}

/// Captures the blocking capability-floor evidence for one protocol.
pub fn protocolCapabilityEvidenceFor(
    protocol: types.NegotiatedProtocol,
) ProtocolCapabilityEvidence {
    var satisfied_feature_count: usize = 0;
    for (blocking_capability_features) |feature| {
        const capability = capabilityFor(feature, protocol) orelse continue;
        if (capability.support == .supported) {
            satisfied_feature_count += 1;
        }
    }

    return .{
        .protocol = protocol,
        .required_features = &blocking_capability_features,
        .satisfied_feature_count = satisfied_feature_count,
        .capability_status = if (satisfied_feature_count == blocking_capability_features.len) .verified else .partial,
        .runtime_status = switch (protocol) {
            .h3 => if (hasBlockingHttp3RuntimeCoverage()) .verified else .missing,
            else => .verified,
        },
    };
}

/// Returns the HTTP/2 multiplexing validation scenario for the provided identifier, if any.
pub fn multiplexingScenarioForId(id: MultiplexingScenarioId) ?MultiplexingScenario {
    for (default_multiplexing_scenarios) |scenario| {
        if (scenario.id == id) {
            return scenario;
        }
    }
    return null;
}

/// Returns the UDP-focused HTTP/3 scenario catalog.
pub fn defaultHttp3DatagramScenarios() []const Http3DatagramScenario {
    return &default_http3_datagram_scenarios;
}

/// Returns the UDP-focused HTTP/3 scenario for the provided route, if any.
pub fn http3DatagramScenarioForRoute(route: RouteId) ?Http3DatagramScenario {
    for (default_http3_datagram_scenarios) |scenario| {
        if (scenario.route == route) {
            return scenario;
        }
    }
    return null;
}

/// Parses one negotiated protocol from fixture metadata.
fn parseNegotiatedProtocol(value: []const u8) !types.NegotiatedProtocol {
    if (std.mem.eql(u8, value, "http/1.1")) {
        return .http_1_1;
    }
    if (std.mem.eql(u8, value, "h2")) {
        return .h2;
    }
    if (std.mem.eql(u8, value, "h3")) {
        return .h3;
    }
    return error.InvalidFixtureProtocol;
}

/// Parses one transport from fixture metadata.
fn parseTransport(value: []const u8) !Transport {
    return std.meta.stringToEnum(Transport, value) orelse error.InvalidFixtureTransport;
}

/// Parses one network mode from fixture metadata.
fn parseNetworkMode(value: []const u8) !NetworkMode {
    return std.meta.stringToEnum(NetworkMode, value) orelse error.InvalidFixtureNetworkMode;
}

/// Parses one capability feature identifier from fixture metadata.
fn parseCapabilityFeature(value: []const u8) !CapabilityFeatureId {
    return std.meta.stringToEnum(CapabilityFeatureId, value) orelse error.InvalidFixtureCapability;
}

/// Parses one peer fixture identifier from fixture metadata.
fn parsePeerFixtureId(value: []const u8) !fixture_loader.InteropPeerFixtureId {
    return std.meta.stringToEnum(fixture_loader.InteropPeerFixtureId, value) orelse error.InvalidFixturePeerId;
}

/// Parses one protocol-profile identifier from fixture metadata.
fn parseProtocolProfileId(value: []const u8) !fixture_loader.InteropProtocolProfileId {
    return std.meta.stringToEnum(fixture_loader.InteropProtocolProfileId, value) orelse error.InvalidFixtureProfileId;
}

/// Parses a capability list from fixture metadata.
fn parseCapabilityFeatureList(
    allocator: std.mem.Allocator,
    values: []const []const u8,
) ![]const CapabilityFeatureId {
    const parsed = try allocator.alloc(CapabilityFeatureId, values.len);
    for (values, 0..) |value, index| {
        parsed[index] = try parseCapabilityFeature(value);
    }
    return parsed;
}

/// Route match result for a concrete request path.
pub const RouteMatch = struct {
    /// Matched route identifier.
    route: RouteId,
    /// Parsed redirect count for `/redirect/{count}`, when applicable.
    redirect_count: ?u32 = null,
};

/// Matches a method and path to one of the shared interop routes.
pub fn matchRoute(method: types.Method, path: []const u8) ?RouteMatch {
    if (method == .get and std.mem.eql(u8, path, "/health")) {
        return .{ .route = .health };
    }
    if (std.mem.eql(u8, path, "/echo")) {
        return .{
            .route = if (method == .post) .echo_post else .echo_get,
        };
    }
    if (method == .get and std.mem.startsWith(u8, path, "/redirect/")) {
        const count_bytes = path["/redirect/".len..];
        const count = std.fmt.parseInt(u32, count_bytes, 10) catch return null;
        return .{
            .route = .redirect_count,
            .redirect_count = count,
        };
    }
    if (method == .get and std.mem.eql(u8, path, "/cookies/set")) {
        return .{ .route = .cookies_set };
    }
    if (method == .get and std.mem.eql(u8, path, "/cookies/read")) {
        return .{ .route = .cookies_read };
    }
    if (method == .get and std.mem.eql(u8, path, "/stream/chunked")) {
        return .{ .route = .stream_chunked };
    }
    if (method == .get and std.mem.eql(u8, path, "/stream/large")) {
        return .{ .route = .stream_large };
    }
    return null;
}

/// Builds a semantic response for a shared harness request.
pub fn buildSemanticResponse(
    allocator: std.mem.Allocator,
    request: SemanticRequest,
) !SemanticResponse {
    const route = matchRoute(request.method, request.path) orelse {
        var headers = types.Headers.init(allocator);
        errdefer headers.deinit();
        try headers.append("Content-Type", "application/json");
        return .{
            .allocator = allocator,
            .status = .not_found,
            .headers = headers,
            .body = try allocator.dupe(u8, "{\"error\":\"not_found\"}"),
        };
    };

    var headers = types.Headers.init(allocator);
    errdefer headers.deinit();

    var body = try allocator.alloc(u8, 0);
    errdefer allocator.free(body);
    var status = scenarioForRoute(route.route).?.success_status;

    switch (route.route) {
        .health => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"status\":\"ok\",\"protocol\":\"{s}\"}}",
                .{request.negotiated_protocol.asAlpnBytes()},
            );
        },
        .echo_get, .echo_post => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"method\":\"{s}\",\"path\":\"{s}\",\"protocol\":\"{s}\",\"body_size\":{d}}}",
                .{
                    request.method.asBytes(),
                    request.path,
                    request.negotiated_protocol.asAlpnBytes(),
                    request.body.len,
                },
            );
        },
        .redirect_count => {
            const count = route.redirect_count.?;
            if (count == 0) {
                status = .ok;
                allocator.free(body);
                try headers.append("Content-Type", "application/json");
                body = try allocator.dupe(u8, "{\"redirects_followed\":0}");
            } else {
                status = .found;
                const location = try std.fmt.allocPrint(allocator, "/redirect/{d}", .{count - 1});
                defer allocator.free(location);
                try headers.append("Location", location);
            }
        },
        .cookies_set => {
            const cookie_name = queryValue(request.query, "name") orelse "cookie";
            const cookie_value = queryValue(request.query, "value") orelse "value";
            const header = try std.fmt.allocPrint(
                allocator,
                "{s}={s}; Path=/",
                .{ cookie_name, cookie_value },
            );
            defer allocator.free(header);
            status = .no_content;
            try headers.append("Set-Cookie", header);
        },
        .cookies_read => {
            allocator.free(body);
            try headers.append("Content-Type", "application/json");
            body = try std.fmt.allocPrint(
                allocator,
                "{{\"cookie_header\":\"{s}\"}}",
                .{request.cookie_header orelse ""},
            );
        },
        .stream_chunked => {
            allocator.free(body);
            try headers.append("Content-Type", "text/plain");
            body = try allocator.dupe(u8, "chunk-one\nchunk-two\nchunk-three\n");
        },
        .stream_large => {
            allocator.free(body);
            try headers.append("Content-Type", "application/octet-stream");
            body = try allocator.alloc(u8, 64 * 1024);
            for (body, 0..) |*byte, index| {
                byte.* = @intCast(index % 251);
            }
        },
    }

    return .{
        .allocator = allocator,
        .status = status,
        .headers = headers,
        .body = body,
    };
}

/// Default in-repo handler that serves the interop-harness contract.
pub fn handleServerRequest(
    _: ?*anyopaque,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    const body_bytes = try request.readBodyAlloc(request.allocator, 256 * 1024);
    defer request.allocator.free(body_bytes);

    var response = try buildSemanticResponse(request.allocator, .{
        .method = request.method,
        .path = request.uri.path,
        .query = request.uri.query,
        .negotiated_protocol = request.negotiated_protocol,
        .body = body_bytes,
        .cookie_header = request.header("cookie"),
    });
    defer response.deinit();

    writer.setStatus(response.status);
    var iterator = response.headers.iterator();
    while (iterator.next()) |header| {
        try writer.appendHeader(header.name, header.value);
    }
    if (response.body.len > 0) {
        try writer.writeAll(response.body);
    }
}

/// Returns the first matching query value for the given key.
fn queryValue(query: ?[]const u8, name: []const u8) ?[]const u8 {
    const raw_query = query orelse return null;
    var pairs = std.mem.splitScalar(u8, raw_query, '&');
    while (pairs.next()) |pair| {
        var entry = std.mem.splitScalar(u8, pair, '=');
        const key = entry.next() orelse continue;
        const value = entry.next() orelse continue;
        if (std.mem.eql(u8, key, name)) {
            return value;
        }
    }
    return null;
}

test "route catalog includes contract endpoints" {
    const health = scenarioForRoute(.health).?;
    try std.testing.expectEqualStrings("/health", health.path_template);
    try std.testing.expect(health.supportsProtocol(.h2));

    const redirect = scenarioForRoute(.redirect_count).?;
    try std.testing.expectEqual(types.Status.found, redirect.success_status);
    try std.testing.expectEqual(ResponseMode.redirect, redirect.response_mode);
}

test "ALPN peer profiles stay aligned with local contract metadata" {
    const dual_alpn = alpnPeerProfileForId(.dual_alpn).?;
    try std.testing.expectEqualStrings("127.0.0.1", dual_alpn.host);
    try std.testing.expectEqual(@as(u16, 18443), dual_alpn.port.toInt());
    try std.testing.expectEqual(@as(usize, 2), dual_alpn.advertised_protocols.len);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, dual_alpn.advertised_protocols[0]);
    try std.testing.expectEqual(AlpnExpectedOutcome.h2, dual_alpn.expected_outcome);
    try std.testing.expectEqualStrings("h2", dual_alpn.selected_protocol_token.?);

    const http1_only = alpnPeerProfileForId(.http1_only).?;
    try std.testing.expectEqual(@as(u16, 19443), http1_only.port.toInt());
    try std.testing.expectEqual(@as(usize, 1), http1_only.advertised_protocols.len);
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, http1_only.advertised_protocols[0]);
    try std.testing.expectEqual(AlpnExpectedOutcome.http_1_1, http1_only.expected_outcome);
    try std.testing.expectEqualStrings("http/1.1", http1_only.selected_protocol_token.?);

    const omits_alpn = alpnPeerProfileForId(.omits_alpn).?;
    try std.testing.expect(omits_alpn.omits_alpn);
    try std.testing.expectEqual(@as(usize, 0), omits_alpn.advertised_protocols.len);
    try std.testing.expectEqual(@as(?[]const u8, null), omits_alpn.selected_protocol_token);
    try std.testing.expectEqual(AlpnExpectedOutcome.http_1_1, omits_alpn.expected_outcome);

    const unsupported = alpnPeerProfileForId(.unsupported_protocol).?;
    try std.testing.expectEqual(@as(u16, 21443), unsupported.port.toInt());
    try std.testing.expectEqual(AlpnExpectedOutcome.reject_before_http, unsupported.expected_outcome);
    try std.testing.expectEqual(AlpnFailurePhase.protocol_routing_before_http, unsupported.expected_failure_phase);
    try std.testing.expectEqual(AlpnClientFailure.negotiation_failed, unsupported.expected_client_failure);
    try std.testing.expectEqualStrings("spdy/3", unsupported.selected_protocol_token.?);
}

test "ALPN diagnostics expose successful negotiated protocol expectations" {
    const dual_alpn = successDiagnosticForPeerProfile(.dual_alpn).?;
    try std.testing.expectEqual(AlpnPeerProfileId.dual_alpn, dual_alpn.peer_profile);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, dual_alpn.negotiated_protocol);
    try std.testing.expectEqual(types.Version.http_2, dual_alpn.response_version);

    const http1_only = successDiagnosticForPeerProfile(.http1_only).?;
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, http1_only.negotiated_protocol);
    try std.testing.expectEqual(types.Version.http_1_1, http1_only.response_version);

    const omits_alpn = successDiagnosticForPeerProfile(.omits_alpn).?;
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, omits_alpn.negotiated_protocol);
    try std.testing.expectEqual(types.Version.http_1_1, omits_alpn.response_version);

    try std.testing.expect(successDiagnosticForPeerProfile(.unsupported_protocol) == null);
}

test "ALPN diagnostics expose failed negotiated protocol expectations" {
    const unsupported = failureDiagnosticForPeerProfile(.unsupported_protocol).?;
    try std.testing.expectEqual(AlpnPeerProfileId.unsupported_protocol, unsupported.peer_profile);
    try std.testing.expectEqual(AlpnFailurePhase.protocol_routing_before_http, unsupported.phase);
    try std.testing.expectEqual(AlpnClientFailure.negotiation_failed, unsupported.client_failure);

    try std.testing.expect(failureDiagnosticForPeerProfile(.dual_alpn) == null);
}

test "ALPN peer profiles resolve by loopback endpoint" {
    const dual_alpn = alpnPeerProfileForEndpoint("127.0.0.1", types.Port.init(18443)).?;
    try std.testing.expectEqual(AlpnPeerProfileId.dual_alpn, dual_alpn.id);

    const http1_only = alpnPeerProfileForEndpoint("127.0.0.1", types.Port.init(19443)).?;
    try std.testing.expectEqual(AlpnPeerProfileId.http1_only, http1_only.id);

    try std.testing.expect(alpnPeerProfileForEndpoint("127.0.0.1", types.Port.init(9999)) == null);
}

test "route matcher resolves contract endpoints" {
    try std.testing.expectEqual(RouteId.health, matchRoute(.get, "/health").?.route);
    try std.testing.expectEqual(RouteId.echo_post, matchRoute(.post, "/echo").?.route);
    try std.testing.expectEqual(@as(u32, 3), matchRoute(.get, "/redirect/3").?.redirect_count.?);
}

test "semantic responses preserve http3 health and cookie semantics" {
    var response = try buildSemanticResponse(std.testing.allocator, .{
        .method = .get,
        .path = "/health",
        .query = null,
        .negotiated_protocol = .h3,
        .body = "",
        .cookie_header = null,
    });
    defer response.deinit();

    try std.testing.expectEqual(types.Status.ok, response.status);
    try std.testing.expectEqualStrings("application/json", response.headers.get("content-type").?);
    try std.testing.expect(std.mem.containsAtLeast(u8, response.body, 1, "\"protocol\":\"h3\""));

    var cookies = try buildSemanticResponse(std.testing.allocator, .{
        .method = .get,
        .path = "/cookies/read",
        .query = null,
        .negotiated_protocol = .http_1_1,
        .body = "",
        .cookie_header = "session=abc",
    });
    defer cookies.deinit();

    try std.testing.expect(std.mem.containsAtLeast(u8, cookies.body, 1, "session=abc"));
}

test "udp http3 scenarios advertise local health and echo coverage" {
    const scenarios = defaultHttp3DatagramScenarios();

    try std.testing.expectEqual(@as(usize, 4), scenarios.len);
    try std.testing.expectEqual(RouteId.health, scenarios[0].route);
    try std.testing.expectEqual(Transport.udp, scenarios[0].endpoint.transport);
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, scenarios[1].endpoint.protocol);
    try std.testing.expectEqual(@as(usize, 64 * 1024), http3DatagramScenarioForRoute(.echo_post).?.datagram_budget);
    try std.testing.expectEqual(@as(usize, 3), scenarios[0].runtime.required_critical_streams.len);
    try std.testing.expect(!scenarios[0].runtime.qpack_dynamic_state_required);
    try std.testing.expect(http3DatagramScenarioForRoute(.echo_get).?.runtime.qpack_dynamic_state_required);
    try std.testing.expectEqual(@as(?LocalDisturbanceProfileId, .basic), http3DatagramScenarioForRoute(.stream_large).?.runtime.disturbance_profile);
    try std.testing.expectEqual(server_types.Http3FailureCategory.transport, http3DatagramScenarioForRoute(.stream_large).?.runtime.expected_failure_category.?);
    try std.testing.expectEqual(@as(usize, 10), scenarios[0].runtime.expectations.sequential_requests_without_restart);
    try std.testing.expectEqual(@as(usize, 2), scenarios[0].runtime.expectations.concurrent_sessions_minimum.toInt());
    try std.testing.expectEqual(@as(usize, 2), scenarios[0].runtime.expectations.overlapping_streams_per_session_minimum.toInt());
}

test "readiness catalog includes the dedicated windows loopback scenario" {
    const readiness = readinessScenarioForId(.windows_loopback_cli_roundtrip).?;

    try std.testing.expectEqual(RouteId.health, readiness.route);
    try std.testing.expect(readiness.supportsPlatform(.windows));
    try std.testing.expect(!readiness.supportsPlatform(.linux));
    try std.testing.expectEqual(types.Status.ok, readiness.expected_status);
    try std.testing.expectEqual(Transport.tcp, readiness.endpoint.transport);
    try std.testing.expectEqual(types.Port.init(18080).toInt(), readiness.endpoint.port.toInt());
    try std.testing.expectEqualStrings("server", readiness.server_command.name);
    try std.testing.expectEqualStrings("request", readiness.request_command.name);
    try std.testing.expectEqualStrings("http://127.0.0.1:18080/health", readiness.request_command.argv[5]);
    try std.testing.expectEqual(ReadinessEnvironment.native_windows, readiness.environment);
    try std.testing.expectEqualStrings(".tmp\\zig-cache-win", readiness.workspace_cache_root);
    try std.testing.expectEqualStrings(".tmp\\zig-global-win", readiness.global_cache_root);
    try std.testing.expect(std.mem.containsAtLeast(u8, readiness.expected_body_substring, 1, "\"protocol\":\"http/1.1\""));
    try std.testing.expect(std.mem.containsAtLeast(u8, readiness.known_failure_signature.?, 1, "GetLastError(87)"));
}

test "readiness catalog includes the dedicated linux loopback scenario" {
    const readiness = readinessScenarioForId(.linux_loopback_cli_roundtrip).?;

    try std.testing.expectEqual(RouteId.health, readiness.route);
    try std.testing.expect(readiness.supportsPlatform(.linux));
    try std.testing.expect(!readiness.supportsPlatform(.windows));
    try std.testing.expectEqual(ReadinessEnvironment.local_linux, readiness.environment);
    try std.testing.expectEqualStrings(".tmp/zig-cache-linux", readiness.workspace_cache_root);
    try std.testing.expectEqualStrings(".tmp/zig-global-linux", readiness.global_cache_root);
    try std.testing.expectEqual(@as(?[]const u8, null), readiness.known_failure_signature);
}

test "multiplexing catalog captures shared-connection and scope diagnostics" {
    const health_echo = multiplexingScenarioForId(.concurrent_health_echo).?;
    try std.testing.expectEqualStrings("concurrent-health-echo", health_echo.name);
    try std.testing.expectEqual(AlpnPeerProfileId.dual_alpn, health_echo.peer_profile);
    try std.testing.expectEqual(@as(usize, 2), health_echo.routes.len);
    try std.testing.expectEqual(RouteId.health, health_echo.routes[0]);
    try std.testing.expectEqual(RouteId.echo_get, health_echo.routes[1]);
    try std.testing.expectEqual(@as(usize, 1), health_echo.diagnostics.shared_connection_count.toInt());
    try std.testing.expectEqual(@as(usize, 2), health_echo.diagnostics.minimum_overlapping_streams.toInt());
    try std.testing.expect(health_echo.diagnostics.distinct_stream_ids_required);
    try std.testing.expectEqual(@as(usize, 0), health_echo.diagnostics.expected_backpressure_scopes.len);
    try std.testing.expectEqual(@as(?FailureScope, null), health_echo.diagnostics.expected_failure_scope);

    const slow_consumer = multiplexingScenarioForId(.slow_consumer_large_body).?;
    try std.testing.expectEqual(@as(usize, 2), slow_consumer.diagnostics.expected_backpressure_scopes.len);
    try std.testing.expectEqual(BackpressureScope.stream, slow_consumer.diagnostics.expected_backpressure_scopes[0]);
    try std.testing.expectEqual(BackpressureScope.connection, slow_consumer.diagnostics.expected_backpressure_scopes[1]);
    try std.testing.expect(slow_consumer.diagnostics.bounded_buffering_required);
    try std.testing.expect(slow_consumer.diagnostics.resume_required);
    try std.testing.expect(slow_consumer.diagnostics.unrelated_streams_continue);

    const rst_stream = multiplexingScenarioForId(.rst_stream_isolated).?;
    try std.testing.expectEqual(FailureScope.stream, rst_stream.diagnostics.expected_failure_scope.?);
    try std.testing.expect(rst_stream.diagnostics.unrelated_streams_continue);

    const goaway = multiplexingScenarioForId(.goaway_drains_connection).?;
    try std.testing.expectEqual(FailureScope.connection, goaway.diagnostics.expected_failure_scope.?);
    try std.testing.expect(goaway.diagnostics.new_requests_rejected_after_drain);
}

test "capability matrix classifies higher-level features across all targeted protocols" {
    try std.testing.expectEqual(@as(usize, 33), defaultCapabilityMatrix().len);

    const server_websocket_h2 = capabilityFor(.server_websocket, .h2).?;
    try std.testing.expectEqual(types.FeatureSurface.server, server_websocket_h2.surface);
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, server_websocket_h2.support);
    try std.testing.expect(std.mem.containsAtLeast(u8, server_websocket_h2.notes.?, 1, "CONNECT"));

    const client_cache_h3 = capabilityFor(.client_cache, .h3).?;
    try std.testing.expectEqual(types.FeatureSurface.client, client_cache_h3.surface);
    try std.testing.expectEqual(types.FeatureSupportLevel.supported, client_cache_h3.support);

    const hardening_h1 = capabilityFor(.hardening_matrix, .http_1_1).?;
    const protocol_capability = hardening_h1.asProtocolCapability();
    try std.testing.expectEqual(types.FeatureSurface.hardening, protocol_capability.surface);
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, protocol_capability.protocol);
}

test "protocol capability evidence keeps the blocking release floor explicit" {
    const h1 = protocolCapabilityEvidenceFor(.http_1_1);
    const h3 = protocolCapabilityEvidenceFor(.h3);

    try std.testing.expectEqual(@as(usize, blocking_capability_features.len), h1.required_features.len);
    try std.testing.expectEqual(@as(usize, blocking_capability_features.len), h1.satisfied_feature_count);
    try std.testing.expectEqual(ReleaseEvidenceStatus.verified, h1.overallStatus());
    try std.testing.expectEqual(ReleaseEvidenceStatus.verified, h3.runtime_status);
    try std.testing.expect(hasBlockingHttp3RuntimeCoverage());
}

test "release decision record rolls up blocking gates and stop conditions" {
    const record = ReleaseDecisionRecord{
        .candidate_version = "1.0.0",
        .gate_results = .{
            .{
                .gate_id = .platform_readiness,
                .status = .passed,
                .stop_condition = null,
            },
            .{
                .gate_id = .protocol_capability_floor,
                .status = .blocked,
                .stop_condition = "restore the blocking capability floor",
            },
            .{
                .gate_id = .public_story_alignment,
                .status = .blocked,
                .stop_condition = "align the public stability story",
            },
            .{
                .gate_id = .release_artifact_completeness,
                .status = .passed,
                .stop_condition = null,
            },
        },
    };

    try std.testing.expectEqual(ReleaseGateStatus.blocked, record.overallStatus());
    try std.testing.expect(!record.approved());
    try std.testing.expectEqual(
        ReleaseGateStatus.blocked,
        record.gateFor(.protocol_capability_floor).?.status,
    );
    try std.testing.expectEqualStrings(
        "restore the blocking capability floor",
        record.firstBlockingStopCondition().?,
    );
    try std.testing.expectEqual(
        ReleaseGateStatus.blocked,
        releaseDecisionStatusForGateResults(&record.gate_results),
    );
    try std.testing.expectEqual(ReleaseGateStatus.passed, gateStatusForEvidence(.verified));
    try std.testing.expectEqual(ReleaseGateStatus.blocked, gateStatusForEvidence(.missing));
}

test "hardening peer fixtures load typed loopback and multiprocess descriptors" {
    const loader = fixture_loader.Loader.init();

    var server_app = try loadPeerDescriptor(std.testing.allocator, loader, .server_app);
    defer server_app.deinit();
    try std.testing.expectEqual(fixture_loader.InteropPeerFixtureId.server_app, server_app.descriptor.id);
    try std.testing.expectEqual(NetworkMode.loopback, server_app.descriptor.network_mode);
    try std.testing.expectEqual(Transport.tcp, server_app.descriptor.transport);
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, server_app.descriptor.protocol);
    try std.testing.expectEqualStrings("server", server_app.descriptor.startup.argv[4]);

    var h3_peer = try loadPeerDescriptor(std.testing.allocator, loader, .h3_peer);
    defer h3_peer.deinit();
    try std.testing.expectEqual(NetworkMode.multiprocess, h3_peer.descriptor.network_mode);
    try std.testing.expectEqual(Transport.udp, h3_peer.descriptor.transport);
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, h3_peer.descriptor.protocol);
    try std.testing.expectEqualStrings("--http3", h3_peer.descriptor.startup.argv[5]);
}

test "hardening protocol profiles load explicit capability requirements" {
    const loader = fixture_loader.Loader.init();

    var http1 = try loadProtocolProfile(std.testing.allocator, loader, .http1_baseline);
    defer http1.deinit();
    try std.testing.expectEqual(NetworkMode.loopback, http1.profile.network_mode);
    try std.testing.expectEqual(@as(usize, 320), http1.profile.eligible_flows);
    try std.testing.expectEqual(@as(usize, 4), http1.profile.required_capabilities.len);

    var h2 = try loadProtocolProfile(std.testing.allocator, loader, .h2_multiplexed);
    defer h2.deinit();
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, h2.profile.protocol);
    try std.testing.expectEqual(@as(usize, 340), h2.profile.eligible_flows);

    var h3 = try loadProtocolProfile(std.testing.allocator, loader, .h3_quic);
    defer h3.deinit();
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, h3.profile.protocol);
    try std.testing.expectEqual(@as(usize, 360), h3.profile.eligible_flows);
    try std.testing.expect(std.mem.containsAtLeast(u8, h3.profile.notes.?, 1, "disturbance"));
}

test "hardening metrics satisfy the local reliability threshold" {
    const loader = fixture_loader.Loader.init();
    const metrics = try captureHardeningMetrics(std.testing.allocator, loader);

    try std.testing.expectEqual(@as(usize, 1020), metrics.total_eligible_flows);
    try std.testing.expectEqual(@as(usize, 30), metrics.excluded_flows);
    try std.testing.expectEqual(@as(usize, 9), metrics.failure_count);
    try std.testing.expect(metrics.successRatio() > 0.99);
    try std.testing.expect(metrics.passesReliabilityThreshold());
    try std.testing.expectEqual(types.NegotiatedProtocol.http_1_1, metrics.protocol_mix[0].protocol);
    try std.testing.expectEqual(types.NegotiatedProtocol.h2, metrics.protocol_mix[1].protocol);
    try std.testing.expectEqual(types.NegotiatedProtocol.h3, metrics.protocol_mix[2].protocol);
}
