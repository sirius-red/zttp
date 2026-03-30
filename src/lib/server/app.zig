//! Higher-level server application dispatch built on top of the canonical runtime.

const std = @import("std");
const core = @import("../types.zig");
const server_types = @import("types.zig");
const static_files = @import("static.zig");
const compression = @import("compression.zig");
const websocket_server = @import("../websocket/server.zig");
const http1 = @import("http1.zig");
const http2 = @import("http2.zig");
const http3 = @import("http3.zig");

/// Middleware scope selected for one route binding.
pub const MiddlewareScope = enum {
    /// Use application-wide middleware only.
    application,
    /// Apply route-group middleware after the application-wide chain.
    route_group,
};

/// Higher-level route registration for the server application surface.
pub const RouteBinding = struct {
    /// Stable route name for diagnostics.
    name: []const u8,
    /// Exact HTTP method handled by the route.
    method: core.Method,
    /// Exact request path handled by the route.
    path: []const u8,
    /// Route callback executed for the request.
    handler: server_types.Handler,
    /// Optional route callback context.
    handler_context: ?*anyopaque,
    /// Middleware scope used for the route.
    middleware_scope: MiddlewareScope,
    /// Optional feature policy override for the route.
    feature_policy: server_types.ServerFeaturePolicy,
    /// Optional static publication identifier for route-owned assets.
    static_publication_id: ?[]const u8,
    /// Optional compression preference override.
    compression_override: server_types.ServerPolicyPreference,
    /// Optional WebSocket endpoint identifier for protocol upgrades.
    websocket_endpoint_id: ?[]const u8,

    /// Returns a direct route binding with default feature policies.
    pub fn init(
        name: []const u8,
        method: core.Method,
        path: []const u8,
        handler: server_types.Handler,
    ) RouteBinding {
        return .{
            .name = name,
            .method = method,
            .path = path,
            .handler = handler,
            .handler_context = null,
            .middleware_scope = .application,
            .feature_policy = server_types.ServerFeaturePolicy.default(),
            .static_publication_id = null,
            .compression_override = .inherit,
            .websocket_endpoint_id = null,
        };
    }
};

/// Group of routes that share a path prefix and middleware chain.
pub const RouteGroup = struct {
    /// Stable group name for diagnostics.
    name: []const u8,
    /// Prefix prepended to every route path in the group.
    prefix: []const u8,
    /// Middleware applied after the application-wide chain for matched routes.
    middleware: []const server_types.Middleware,
    /// Routes owned by the group.
    routes: []const RouteBinding,

    /// Returns an empty route group for the provided prefix.
    pub fn init(name: []const u8, prefix: []const u8, routes: []const RouteBinding) RouteGroup {
        return .{
            .name = name,
            .prefix = prefix,
            .middleware = &.{},
            .routes = routes,
        };
    }

    /// Validates the route-group definition.
    pub fn validate(self: RouteGroup) !void {
        if (self.name.len == 0) {
            return error.InvalidServerApplication;
        }
        if (self.prefix.len == 0 or self.prefix[0] != '/') {
            return error.InvalidServerApplication;
        }
        for (self.routes) |route| {
            if (route.path.len == 0 or route.path[0] != '/') {
                return error.InvalidServerApplication;
            }
        }
    }
};

/// Resolved exact route plus any route-group middleware that applies to it.
pub const ResolvedRoute = struct {
    /// Route matched for the request.
    binding: RouteBinding,
    /// Route-group middleware that also applies to the request.
    route_group_middleware: []const server_types.Middleware,
};

/// Complete first-party server application definition.
pub const Application = struct {
    /// Direct routes registered on the application.
    routes: []const RouteBinding,
    /// Application-wide middleware.
    middleware: []const server_types.Middleware,
    /// Route groups registered on the application.
    route_groups: []const RouteGroup,
    /// Static publications owned by the application.
    static_publications: []const static_files.Publication,
    /// Shared compression policy for buffered responses.
    compression_policy: compression.Policy,
    /// WebSocket endpoints owned by the application.
    websocket_endpoints: []const websocket_server.Endpoint,
    /// Optional fallback handler for unmatched requests.
    fallback: ?server_types.FallbackHandler,
    /// Exact-route ambiguity policy.
    ambiguity_policy: server_types.RouteAmbiguityPolicy,

    /// Returns an empty application with default policies.
    pub fn init() Application {
        return .{
            .routes = &.{},
            .middleware = &.{},
            .route_groups = &.{},
            .static_publications = &.{},
            .compression_policy = compression.Policy.default(),
            .websocket_endpoints = &.{},
            .fallback = null,
            .ambiguity_policy = .reject_duplicates,
        };
    }

    /// Configures the canonical server runtime to dispatch through the application.
    pub fn configure(self: *const Application, config: *server_types.ServerConfig) void {
        config.router = null;
        config.handler = dispatchConfiguredApplication;
        config.handler_context = @ptrCast(@constCast(self));
    }

    /// Validates the application before it is attached to the runtime.
    pub fn validate(self: Application) !void {
        for (self.route_groups) |route_group| {
            try route_group.validate();
        }
        for (self.static_publications) |publication| {
            try publication.validate();
        }
        for (self.websocket_endpoints) |endpoint| {
            try endpoint.validate();
        }

        if (self.ambiguity_policy == .reject_duplicates) {
            try validateDuplicateRoutes(self.routes);
            for (self.route_groups) |route_group| {
                try validateDuplicateRoutes(route_group.routes);
            }
            try validateRouteCollisions(self);
        }
    }

    /// Dispatches a request through middleware, routes, static assets, fallback, and compression.
    pub fn dispatch(
        self: *const Application,
        request: *server_types.ServerRequest,
        writer: *server_types.ServerResponseWriter,
    ) !void {
        var buffer = compression.ResponseBuffer.init(writer.headers.allocator);
        defer buffer.deinit();

        var buffered_writer = buffer.responseWriter();
        defer buffered_writer.deinit();

        for (self.middleware) |middleware| {
            const decision = try middleware.handler(middleware.context, request, &buffered_writer);
            if (decision == .handled) {
                try compression.flushBufferedResponse(
                    self.compression_policy,
                    request,
                    &buffered_writer,
                    &buffer,
                    writer,
                );
                return;
            }
        }

        const resolved_route = self.resolveRoute(request.method, request.uri.path);
        if (resolved_route) |route| {
            for (route.route_group_middleware) |middleware| {
                const decision = try middleware.handler(middleware.context, request, &buffered_writer);
                if (decision == .handled) {
                    try compression.flushBufferedResponse(
                        self.compression_policy.withPreference(route.binding.compression_override),
                        request,
                        &buffered_writer,
                        &buffer,
                        writer,
                    );
                    return;
                }
            }

            if (route.binding.websocket_endpoint_id) |endpoint_id| {
                if (self.endpointForId(endpoint_id)) |endpoint| {
                    try dispatchWebSocketEndpoint(endpoint, request, &buffered_writer);
                } else {
                    try writeBadApplicationState(&buffered_writer, "unknown_websocket_endpoint");
                }
            } else {
                try route.binding.handler(route.binding.handler_context, request, &buffered_writer);
            }
            try compression.flushBufferedResponse(
                self.compression_policy.withPreference(route.binding.compression_override),
                request,
                &buffered_writer,
                &buffer,
                writer,
            );
            return;
        }

        if (self.resolveWebSocketEndpoint(request)) |endpoint| {
            try dispatchWebSocketEndpoint(endpoint, request, &buffered_writer);
            try compression.flushBufferedResponse(
                self.compression_policy,
                request,
                &buffered_writer,
                &buffer,
                writer,
            );
            return;
        }

        for (self.static_publications) |publication| {
            const outcome = try publication.serve(writer.headers.allocator, request, &buffered_writer);
            if (outcome == .served) {
                try compression.flushBufferedResponse(
                    self.compression_policy,
                    request,
                    &buffered_writer,
                    &buffer,
                    writer,
                );
                return;
            }
        }

        if (self.fallback) |fallback| {
            try fallback.handler(fallback.handler_context, request, &buffered_writer);
        } else {
            try writeDefaultNotFound(&buffered_writer);
        }
        try compression.flushBufferedResponse(
            self.compression_policy,
            request,
            &buffered_writer,
            &buffer,
            writer,
        );
    }

    /// Resolves the first exact route matching the method and path.
    pub fn resolveRoute(self: Application, method: core.Method, path: []const u8) ?ResolvedRoute {
        for (self.routes) |route| {
            if (routeMatches(route, method, path)) {
                return .{
                    .binding = route,
                    .route_group_middleware = &.{},
                };
            }
        }

        for (self.route_groups) |route_group| {
            for (route_group.routes) |route| {
                if (routeMatchesWithPrefix(route_group.prefix, route, method, path)) {
                    var matched_route = route;
                    matched_route.path = path;
                    return .{
                        .binding = matched_route,
                        .route_group_middleware = route_group.middleware,
                    };
                }
            }
        }

        return null;
    }

    /// Resolves the first WebSocket endpoint matching the request path and handshake shape.
    pub fn resolveWebSocketEndpoint(self: Application, request: *const server_types.ServerRequest) ?websocket_server.Endpoint {
        for (self.websocket_endpoints) |endpoint| {
            if (websocket_server.isHandshakeRequest(endpoint, request)) {
                return endpoint;
            }
        }
        return null;
    }

    /// Returns the endpoint matching the provided identifier, when one exists.
    pub fn endpointForId(self: Application, endpoint_id: []const u8) ?websocket_server.Endpoint {
        for (self.websocket_endpoints) |endpoint| {
            if (std.mem.eql(u8, endpoint.name, endpoint_id)) {
                return endpoint;
            }
        }
        return null;
    }
};

/// Dispatches a request through the configured application handler.
pub fn dispatchConfiguredApplication(
    ctx: ?*anyopaque,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    const self: *const Application = @ptrCast(@alignCast(ctx.?));
    try self.dispatch(request, writer);
}

/// Validates an application attached through `Application.configure`, when present.
pub fn validateConfiguredHandler(handler: server_types.Handler, ctx: ?*anyopaque) !void {
    if (handler != dispatchConfiguredApplication) {
        return;
    }
    const self: *const Application = @ptrCast(@alignCast(ctx.?));
    try self.validate();
}

/// Returns true when the route matches the request exactly.
fn routeMatches(route: RouteBinding, method: core.Method, path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(route.method.asBytes(), method.asBytes()) and
        std.mem.eql(u8, route.path, path);
}

/// Returns true when the prefixed route matches the request exactly.
fn routeMatchesWithPrefix(prefix: []const u8, route: RouteBinding, method: core.Method, path: []const u8) bool {
    if (!std.ascii.eqlIgnoreCase(route.method.asBytes(), method.asBytes())) {
        return false;
    }
    if (std.mem.eql(u8, prefix, "/")) {
        return std.mem.eql(u8, route.path, path);
    }
    if (!std.mem.startsWith(u8, path, prefix)) {
        return false;
    }
    if (std.mem.eql(u8, route.path, "/")) {
        return path.len == prefix.len;
    }
    const suffix = if (path.len == prefix.len) "/" else path[prefix.len..];
    return std.mem.eql(u8, suffix, route.path);
}

/// Validates duplicate exact method/path registrations within one route slice.
fn validateDuplicateRoutes(routes: []const RouteBinding) !void {
    for (routes, 0..) |route, index| {
        for (routes[index + 1 ..]) |other| {
            if (std.ascii.eqlIgnoreCase(route.method.asBytes(), other.method.asBytes()) and
                std.mem.eql(u8, route.path, other.path))
            {
                return error.InvalidServerApplication;
            }
        }
    }
}

/// Validates collisions between direct routes and route-group routes.
fn validateRouteCollisions(application: Application) !void {
    for (application.routes) |route| {
        for (application.route_groups) |route_group| {
            for (route_group.routes) |group_route| {
                if (std.ascii.eqlIgnoreCase(route.method.asBytes(), group_route.method.asBytes()) and
                    routeMatchesWithPrefix(route_group.prefix, group_route, route.method, route.path))
                {
                    return error.InvalidServerApplication;
                }
            }
        }
    }
}

/// Dispatches a WebSocket endpoint through the protocol-aware server adapter.
fn dispatchWebSocketEndpoint(
    endpoint: websocket_server.Endpoint,
    request: *server_types.ServerRequest,
    writer: *server_types.ServerResponseWriter,
) !void {
    switch (request.negotiated_protocol) {
        .http_1_1 => try http1.dispatchWebSocketEndpoint(endpoint, request, writer),
        .h2 => try http2.dispatchWebSocketEndpoint(endpoint, request, writer),
        .h3 => try http3.dispatchWebSocketEndpoint(endpoint, request, writer),
    }
}

/// Writes the default JSON 404 response for the application surface.
fn writeDefaultNotFound(writer: *server_types.ServerResponseWriter) !void {
    writer.setStatus(.not_found);
    try writer.appendHeader("Content-Type", "application/json");
    try writer.writeAll("{\"error\":\"not_found\"}");
}

/// Writes a predictable internal error when the application references invalid state.
fn writeBadApplicationState(writer: *server_types.ServerResponseWriter, reason: []const u8) !void {
    writer.setStatus(.internal_server_error);
    try writer.appendHeader("Content-Type", "application/json");
    const body = try std.fmt.allocPrint(writer.headers.allocator, "{{\"error\":\"{s}\"}}", .{reason});
    defer writer.headers.allocator.free(body);
    try writer.writeAll(body);
}

/// No-op application handler used by basic route tests.
pub fn noopHandler(
    _: ?*anyopaque,
    _: *server_types.ServerRequest,
    _: *server_types.ServerResponseWriter,
) !void {}

test "server application resolves direct routes before grouped routes" {
    const direct = [_]RouteBinding{
        RouteBinding.init("health", .get, "/health", noopHandler),
    };
    const grouped = [_]RouteBinding{
        RouteBinding.init("chat", .get, "/chat", noopHandler),
    };
    const groups = [_]RouteGroup{
        RouteGroup.init("ws", "/ws", &grouped),
    };

    const application = Application{
        .routes = &direct,
        .middleware = &.{},
        .route_groups = &groups,
        .static_publications = &.{},
        .compression_policy = compression.Policy.default(),
        .websocket_endpoints = &.{},
        .fallback = null,
        .ambiguity_policy = .reject_duplicates,
    };

    try std.testing.expect(application.resolveRoute(.get, "/health") != null);
    try std.testing.expect(application.resolveRoute(.get, "/ws/chat") != null);
}
