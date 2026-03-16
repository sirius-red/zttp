//! Socket I/O helpers that avoid deprecated stream paths on Windows.

const builtin = @import("builtin");
const std = @import("std");
const windows = std.os.windows;

/// Error set returned by socket reads.
pub const ReadError = std.net.Stream.ReadError;

/// Reads bytes from the socket, using `recv` on Windows to avoid `ReadFile`.
pub fn read(stream: std.net.Stream, dest: []u8) ReadError!usize {
    if (builtin.os.tag != .windows) {
        return stream.read(dest);
    }
    return readWindows(stream, dest);
}

/// Reads bytes from the socket using the Winsock receive path.
fn readWindows(stream: std.net.Stream, dest: []u8) ReadError!usize {
    if (dest.len == 0) {
        return 0;
    }
    const read_len = windows.ws2_32.recv(
        stream.handle,
        dest.ptr,
        @intCast(@min(dest.len, std.math.maxInt(i32))),
        0,
    );
    if (read_len == windows.ws2_32.SOCKET_ERROR) {
        try handleRecvError(windows.ws2_32.WSAGetLastError());
    }
    return @intCast(read_len);
}

/// Maps Winsock receive failures into the stream read error set.
fn handleRecvError(err: windows.ws2_32.WinsockError) ReadError!void {
    switch (err) {
        .WSAECONNRESET,
        .WSAENETRESET,
        => return error.ConnectionResetByPeer,
        .WSAEFAULT => unreachable,
        .WSAEINPROGRESS,
        .WSAEINTR,
        .WSA_IO_PENDING,
        .WSA_OPERATION_ABORTED,
        => unreachable,
        .WSAEINVAL => return error.SocketNotBound,
        .WSAEMSGSIZE => return error.MessageTooBig,
        .WSAENETDOWN => return error.NetworkSubsystemFailed,
        .WSAENOTCONN => return error.SocketNotConnected,
        .WSAEWOULDBLOCK => return error.WouldBlock,
        .WSAETIMEDOUT => return error.ConnectionTimedOut,
        .WSANOTINITIALISED => unreachable,
        else => |unexpected| return windows.unexpectedWSAError(unexpected),
    }
}
