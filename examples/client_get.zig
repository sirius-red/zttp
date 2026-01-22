//! Minimal zttp client example.

const std = @import("std");
const zttp = @import("zttp");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var client = zttp.Client.init(allocator, zttp.Client.Options.default());
    defer client.deinit();

    const uri = zttp.Uri.init(.http, "example.com", null, "/", null, null);
    var request = zttp.Request.init(allocator, zttp.Method.get, uri);
    defer request.deinit();
}
