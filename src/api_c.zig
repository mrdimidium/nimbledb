const nimbledb = @import("main.zig");

export fn add(a: i32, b: i32) i32 {
    return nimbledb.add(a, b);
}
