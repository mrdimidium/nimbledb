// Copyright (c) 2021 Kenta Iwasaki <kenta@lithdew.net>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

const std = @import("std");

const os = std.os;
const fs = std.fs;
const mem = std.mem;
const math = std.math;
const meta = std.meta;
const debug = std.debug;

const panic = debug.panic;
const assert = debug.assert;

// To make it easier to get started, we take a dependency on lmdb.
// This will allow us to design a formal interface and a test suite and infrastructure.
// Rewriting incrementally is easier than building from scratch.
const lmdb = @cImport(@cInclude("lmdb.h"));

fn ResultOf(comptime function: anytype) type {
    return if (@typeInfo(@TypeOf(function)).Fn.return_type == c_int) anyerror!void else void;
}

fn call(comptime function: anytype, args: anytype) ResultOf(function) {
    const rc = @call(.{}, function, args);
    if (ResultOf(function) == void) return rc;

    return switch (rc) {
        lmdb.MDB_SUCCESS => {},
        lmdb.MDB_KEYEXIST => error.AlreadyExists,
        lmdb.MDB_NOTFOUND => error.NotFound,
        lmdb.MDB_PAGE_NOTFOUND => error.PageNotFound,
        lmdb.MDB_CORRUPTED => error.PageCorrupted,
        lmdb.MDB_PANIC => error.Panic,
        lmdb.MDB_VERSION_MISMATCH => error.VersionMismatch,
        lmdb.MDB_INVALID => error.FileNotDatabase,
        lmdb.MDB_MAP_FULL => error.MapSizeLimitReached,
        lmdb.MDB_DBS_FULL => error.MaxNumDatabasesLimitReached,
        lmdb.MDB_READERS_FULL => error.MaxNumReadersLimitReached,
        lmdb.MDB_TLS_FULL => error.TooManyEnvironmentsOpen,
        lmdb.MDB_TXN_FULL => error.TransactionTooBig,
        lmdb.MDB_CURSOR_FULL => error.CursorStackLimitReached,
        lmdb.MDB_PAGE_FULL => error.OutOfPageMemory,
        lmdb.MDB_MAP_RESIZED => error.DatabaseExceedsMapSizeLimit,
        lmdb.MDB_INCOMPATIBLE => error.IncompatibleOperation,
        lmdb.MDB_BAD_RSLOT => error.InvalidReaderLocktableSlotReuse,
        lmdb.MDB_BAD_TXN => error.TransactionNotAborted,
        lmdb.MDB_BAD_VALSIZE => error.UnsupportedSize,
        lmdb.MDB_BAD_DBI => error.BadDatabaseHandle,
        @intFromEnum(os.E.NOENT) => error.NoSuchFileOrDirectory,
        @intFromEnum(os.E.IO) => error.InputOutputError,
        @intFromEnum(os.E.NOMEM) => error.OutOfMemory,
        @intFromEnum(os.E.ACCES) => error.ReadOnly,
        @intFromEnum(os.E.BUSY) => error.DeviceOrResourceBusy,
        @intFromEnum(os.E.INVAL) => error.InvalidParameter,
        @intFromEnum(os.E.NOSPC) => error.NoSpaceLeftOnDevice,
        @intFromEnum(os.E.EXIST) => error.FileAlreadyExists,
        else => panic("({}) {s}", .{ rc, lmdb.mdb_strerror(rc) }),
    };
}

pub const Environment = packed struct {
    pub const Statistics = struct {
        page_size: usize,
        tree_height: usize,
        num_branch_pages: usize,
        num_leaf_pages: usize,
        num_overflow_pages: usize,
        num_entries: usize,
    };

    pub const Info = struct {
        map_address: ?[*]u8,
        map_size: usize,
        last_page_num: usize,
        last_tx_id: usize,
        max_num_reader_slots: usize,
        num_used_reader_slots: usize,
    };

    const Self = @This();

    inner: ?*lmdb.MDB_env,

    pub const OpenFlags = struct {
        mode: lmdb.mdb_mode_t = 0o664,
        map_size: ?usize = null,
        max_num_readers: ?usize = null,
        max_num_dbs: ?usize = null,

        fix_mapped_address: bool = false,
        no_sub_directory: bool = false,
        read_only: bool = false,
        use_writable_memory_map: bool = false,
        dont_sync_metadata: bool = false,
        dont_sync: bool = false,
        flush_asynchronously: bool = false,
        disable_thread_local_storage: bool = false,
        disable_locks: bool = false,
        disable_readahead: bool = false,
        disable_memory_initialization: bool = false,

        pub fn into(self: Self.OpenFlags) c_uint {
            var flags: c_uint = 0;
            if (self.fix_mapped_address) flags |= lmdb.MDB_FIXEDMAP;
            if (self.no_sub_directory) flags |= lmdb.MDB_NOSUBDIR;
            if (self.read_only) flags |= lmdb.MDB_RDONLY;
            if (self.use_writable_memory_map) flags |= lmdb.MDB_WRITEMAP;
            if (self.dont_sync_metadata) flags |= lmdb.MDB_NOMETASYNC;
            if (self.dont_sync) flags |= lmdb.MDB_NOSYNC;
            if (self.flush_asynchronously) flags |= lmdb.MDB_MAPASYNC;
            if (self.disable_thread_local_storage) flags |= lmdb.MDB_NOTLS;
            if (self.disable_locks) flags |= lmdb.MDB_NOLOCK;
            if (self.disable_readahead) flags |= lmdb.MDB_NORDAHEAD;
            if (self.disable_memory_initialization) flags |= lmdb.MDB_NOMEMINIT;
            return flags;
        }
    };

    pub fn init(env_path: []const u8, flags: Self.OpenFlags) !Self {
        var inner: ?*lmdb.MDB_env = null;

        try call(lmdb.mdb_env_create, .{&inner});
        errdefer call(lmdb.mdb_env_close, .{inner});

        if (flags.map_size) |map_size| {
            try call(lmdb.mdb_env_set_mapsize, .{ inner, map_size });
        }
        if (flags.max_num_readers) |max_num_readers| {
            try call(lmdb.mdb_env_set_maxreaders, .{ inner, @intCast(max_num_readers) });
        }
        if (flags.max_num_dbs) |max_num_dbs| {
            try call(lmdb.mdb_env_set_maxdbs, .{ inner, @intCast(max_num_dbs) });
        }

        if (!mem.endsWith(u8, env_path, &[_]u8{0})) {
            assert(env_path.len + 1 <= fs.MAX_PATH_BYTES);

            var fixed_path: [fs.MAX_PATH_BYTES + 1]u8 = undefined;
            mem.copy(u8, &fixed_path, env_path);
            fixed_path[env_path.len] = 0;

            try call(lmdb.mdb_env_open, .{ inner, fixed_path[0 .. env_path.len + 1].ptr, flags.into(), flags.mode });
        } else {
            try call(lmdb.mdb_env_open, .{ inner, env_path.ptr, flags.into(), flags.mode });
        }

        return Self{ .inner = inner };
    }

    pub fn deinit(self: Self) void {
        call(lmdb.mdb_env_close, .{self.inner});
    }

    pub const CopyFlags = packed struct {
        compact: bool = false,
        pub fn into(self: Self.CopyFlags) c_uint {
            var flags: c_uint = 0;
            if (self.compact) flags |= lmdb.MDB_CP_COMPACT;
            return flags;
        }
    };

    pub fn copyTo(self: Self, backup_path: []const u8, flags: CopyFlags) !void {
        if (!mem.endsWith(u8, backup_path, &[_]u8{0})) {
            assert(backup_path.len + 1 <= fs.MAX_PATH_BYTES);

            var fixed_path: [fs.MAX_PATH_BYTES + 1]u8 = undefined;
            mem.copy(u8, &fixed_path, backup_path);
            fixed_path[backup_path.len] = 0;

            try call(lmdb.mdb_env_copy2, .{ self.inner, fixed_path[0 .. backup_path.len + 1].ptr, flags.into() });
        } else {
            try call(lmdb.mdb_env_copy2, .{ self.inner, backup_path.ptr, flags.into() });
        }
    }

    pub fn pipeTo(self: Self, fd_handle: os.fd_t, flags: CopyFlags) !void {
        try call(lmdb.mdb_env_copyfd2, .{ self.inner, fd_handle, flags.into() });
    }

    pub fn getMaxKeySize(self: Self) usize {
        return @intCast(lmdb.mdb_env_get_maxkeysize(self.inner));
    }

    pub fn getMaxNumReaders(self: Self) usize {
        var max_num_readers: c_uint = 0;
        call(lmdb.mdb_env_get_maxreaders, .{ self.inner, &max_num_readers }) catch |err| {
            panic("Environment.getMaxNumReaders(): {}", .{err});
        };
        return @intCast(max_num_readers);
    }

    pub fn setMapSize(self: Self, map_size: ?usize) !void {
        try call(lmdb.mdb_env_set_mapsize, .{ self.inner, if (map_size) |size| size else 0 });
    }

    pub const Flags = struct {
        fix_mapped_address: bool = false,
        no_sub_directory: bool = false,
        read_only: bool = false,
        use_writable_memory_map: bool = false,
        dont_sync_metadata: bool = false,
        dont_sync: bool = false,
        flush_asynchronously: bool = false,
        disable_thread_local_storage: bool = false,
        disable_locks: bool = false,
        disable_readahead: bool = false,
        disable_memory_initialization: bool = false,

        pub fn from(flags: c_uint) Flags {
            return Flags{
                .fix_mapped_address = flags & lmdb.MDB_FIXEDMAP != 0,
                .no_sub_directory = flags & lmdb.MDB_NOSUBDIR != 0,
                .read_only = flags & lmdb.MDB_RDONLY != 0,
                .use_writable_memory_map = flags & lmdb.MDB_WRITEMAP != 0,
                .dont_sync_metadata = flags & lmdb.MDB_NOMETASYNC != 0,
                .dont_sync = flags & lmdb.MDB_NOSYNC != 0,
                .flush_asynchronously = flags & lmdb.MDB_MAPASYNC != 0,
                .disable_thread_local_storage = flags & lmdb.MDB_NOTLS != 0,
                .disable_locks = flags & lmdb.MDB_NOLOCK != 0,
                .disable_readahead = flags & lmdb.MDB_NORDAHEAD != 0,
                .disable_memory_initialization = flags & lmdb.MDB_NOMEMINIT != 0,
            };
        }

        pub fn into(self: Self.Flags) c_uint {
            var flags: c_uint = 0;
            if (self.fix_mapped_address) flags |= lmdb.MDB_FIXEDMAP;
            if (self.no_sub_directory) flags |= lmdb.MDB_NOSUBDIR;
            if (self.read_only) flags |= lmdb.MDB_RDONLY;
            if (self.use_writable_memory_map) flags |= lmdb.MDB_WRITEMAP;
            if (self.dont_sync_metadata) flags |= lmdb.MDB_NOMETASYNC;
            if (self.dont_sync) flags |= lmdb.MDB_NOSYNC;
            if (self.flush_asynchronously) flags |= lmdb.MDB_MAPASYNC;
            if (self.disable_thread_local_storage) flags |= lmdb.MDB_NOTLS;
            if (self.disable_locks) flags |= lmdb.MDB_NOLOCK;
            if (self.disable_readahead) flags |= lmdb.MDB_NORDAHEAD;
            if (self.disable_memory_initialization) flags |= lmdb.MDB_NOMEMINIT;
            return flags;
        }
    };

    pub fn getFlags(self: Self) Flags {
        var inner: c_uint = undefined;
        call(lmdb.mdb_env_get_flags, .{ self.inner, &inner }) catch |err| {
            panic("Environment.getFlags(): {}", .{err});
        };
        return Flags.from(inner);
    }

    pub const MutableFlags = struct {
        dont_sync_metadata: bool = false,
        dont_sync: bool = false,
        flush_asynchronously: bool = false,
        disable_memory_initialization: bool = false,
        pub fn into(self: Self.MutableFlags) c_uint {
            var flags: c_uint = 0;
            if (self.dont_sync_metadata) flags |= lmdb.MDB_NOMETASYNC;
            if (self.dont_sync) flags |= lmdb.MDB_NOSYNC;
            if (self.flush_asynchronously) flags |= lmdb.MDB_MAPASYNC;
            if (self.disable_memory_initialization) flags |= lmdb.MDB_NOMEMINIT;
            return flags;
        }
    };

    pub fn enableFlags(self: Self, flags: MutableFlags) void {
        call(lmdb.mdb_env_set_flags, .{ self.inner, flags.into(), 1 }) catch |err| {
            panic("Environment.enableFlags(): {}", .{err});
        };
    }

    pub fn disableFlags(self: Self, flags: MutableFlags) void {
        call(lmdb.mdb_env_set_flags, .{ self.inner, flags.into(), 0 }) catch |err| {
            panic("Environment.disableFlags(): {}", .{err});
        };
    }

    pub fn path(self: Self) []const u8 {
        var env_path: [:0]const u8 = undefined;
        call(lmdb.mdb_env_get_path, .{ self.inner, @ptrCast(&env_path.ptr) }) catch |err| {
            panic("Environment.path(): {}", .{err});
        };
        env_path.len = mem.indexOfSentinel(u8, 0, env_path.ptr);
        return mem.span(env_path);
    }

    pub fn stat(self: Self) Statistics {
        var inner: lmdb.MDB_stat = undefined;
        call(lmdb.mdb_env_stat, .{ self.inner, &inner }) catch |err| {
            panic("Environment.stat(): {}", .{err});
        };
        return Statistics{
            .page_size = @intCast(inner.ms_psize),
            .tree_height = @intCast(inner.ms_depth),
            .num_branch_pages = @intCast(inner.ms_branch_pages),
            .num_leaf_pages = @intCast(inner.ms_leaf_pages),
            .num_overflow_pages = @intCast(inner.ms_overflow_pages),
            .num_entries = @intCast(inner.ms_entries),
        };
    }

    pub fn fd(self: Self) os.fd_t {
        var inner: os.fd_t = undefined;
        call(lmdb.mdb_env_get_fd, .{ self.inner, &inner }) catch |err| {
            panic("Environment.fd(): {}", .{err});
        };
        return inner;
    }

    pub fn info(self: Self) Info {
        var inner: lmdb.MDB_envinfo = undefined;
        call(lmdb.mdb_env_info, .{ self.inner, &inner }) catch |err| {
            panic("Environment.info(): {}", .{err});
        };
        return Info{
            .map_address = @ptrCast(inner.me_mapaddr),
            .map_size = @intCast(inner.me_mapsize),
            .last_page_num = @intCast(inner.me_last_pgno),
            .last_tx_id = @intCast(inner.me_last_txnid),
            .max_num_reader_slots = @intCast(inner.me_maxreaders),
            .num_used_reader_slots = @intCast(inner.me_numreaders),
        };
    }

    pub fn begin(self: Self, flags: Transaction.Flags) !Transaction {
        var inner: ?*lmdb.MDB_txn = null;
        const maybe_parent = if (flags.parent) |parent| parent.inner else null;
        try call(lmdb.mdb_txn_begin, .{ self.inner, maybe_parent, flags.into(), &inner });
        return Transaction{ .inner = inner };
    }

    pub fn sync(self: Self, force: bool) !void {
        try call(lmdb.mdb_env_sync, .{ self.inner, @as(c_int, if (force) 1 else 0) });
    }

    pub fn purge(self: Self) !usize {
        var count: c_int = undefined;
        try call(lmdb.mdb_reader_check, .{ self.inner, &count });
        return @intCast(count);
    }
};

pub const Database = struct {
    pub const OpenFlags = packed struct {
        compare_keys_in_reverse_order: bool = false,
        allow_duplicate_keys: bool = false,
        keys_are_integers: bool = false,
        duplicate_entries_are_fixed_size: bool = false,
        duplicate_keys_are_integers: bool = false,
        compare_duplicate_keys_in_reverse_order: bool = false,

        pub fn into(self: Self.OpenFlags) c_uint {
            var flags: c_uint = 0;
            if (self.compare_keys_in_reverse_order) flags |= lmdb.MDB_REVERSEKEY;
            if (self.allow_duplicate_keys) flags |= lmdb.MDB_DUPSORT;
            if (self.keys_are_integers) flags |= lmdb.MDB_INTEGERKEY;
            if (self.duplicate_entries_are_fixed_size) flags |= lmdb.MDB_DUPFIXED;
            if (self.duplicate_keys_are_integers) flags |= lmdb.MDB_INTEGERDUP;
            if (self.compare_duplicate_keys_in_reverse_order) flags |= lmdb.MDB_REVERSEDUP;
            return flags;
        }
    };

    pub const UseFlags = packed struct {
        compare_keys_in_reverse_order: bool = false,
        allow_duplicate_keys: bool = false,
        keys_are_integers: bool = false,
        duplicate_entries_are_fixed_size: bool = false,
        duplicate_keys_are_integers: bool = false,
        compare_duplicate_keys_in_reverse_order: bool = false,
        create_if_not_exists: bool = false,

        pub fn into(self: Self.UseFlags) c_uint {
            var flags: c_uint = 0;
            if (self.compare_keys_in_reverse_order) flags |= lmdb.MDB_REVERSEKEY;
            if (self.allow_duplicate_keys) flags |= lmdb.MDB_DUPSORT;
            if (self.keys_are_integers) flags |= lmdb.MDB_INTEGERKEY;
            if (self.duplicate_entries_are_fixed_size) flags |= lmdb.MDB_DUPFIXED;
            if (self.duplicate_keys_are_integers) flags |= lmdb.MDB_INTEGERDUP;
            if (self.compare_duplicate_keys_in_reverse_order) flags |= lmdb.MDB_REVERSEDUP;
            if (self.create_if_not_exists) flags |= lmdb.MDB_CREATE;
            return flags;
        }
    };

    const Self = @This();

    inner: lmdb.MDB_dbi,

    pub fn close(self: Self, env: Environment) void {
        call(lmdb.mdb_dbi_close, .{ env.inner, self.inner });
    }
};

pub const Transaction = packed struct {
    pub const Flags = struct {
        parent: ?Self = null,
        read_only: bool = false,
        dont_sync: bool = false,
        dont_sync_metadata: bool = false,

        pub fn into(self: Self.Flags) c_uint {
            var flags: c_uint = 0;
            if (self.read_only) flags |= lmdb.MDB_RDONLY;
            if (self.dont_sync) flags |= lmdb.MDB_NOSYNC;
            if (self.dont_sync_metadata) flags |= lmdb.MDB_NOMETASYNC;
            return flags;
        }
    };

    const Self = @This();

    inner: ?*lmdb.MDB_txn,

    pub fn id(self: Self) usize {
        return @intCast(lmdb.mdb_txn_id(self.inner));
    }

    pub fn open(self: Self, flags: Database.OpenFlags) !Database {
        var inner: lmdb.MDB_dbi = 0;
        try call(lmdb.mdb_dbi_open, .{ self.inner, null, flags.into(), &inner });
        return Database{ .inner = inner };
    }

    pub fn use(self: Self, name: []const u8, flags: Database.UseFlags) !Database {
        var inner: lmdb.MDB_dbi = 0;
        try call(lmdb.mdb_dbi_open, .{ self.inner, name.ptr, flags.into(), &inner });
        return Database{ .inner = inner };
    }

    pub fn cursor(self: Self, db: Database) !Cursor {
        var inner: ?*lmdb.MDB_cursor = undefined;
        try call(lmdb.mdb_cursor_open, .{ self.inner, db.inner, &inner });
        return Cursor{ .inner = inner };
    }

    pub fn setKeyOrder(self: Self, db: Database, comptime order: fn (a: []const u8, b: []const u8) math.Order) !void {
        const S = struct {
            fn cmp(a: ?*const lmdb.MDB_val, b: ?*const lmdb.MDB_val) callconv(.lmdb) c_int {
                const slice_a = @as([*]const u8, @ptrCast(a.?.mv_data))[0..a.?.mv_size];
                const slice_b = @as([*]const u8, @ptrCast(b.?.mv_data))[0..b.?.mv_size];
                return switch (order(slice_a, slice_b)) {
                    .eq => 0,
                    .lt => -1,
                    .gt => 1,
                };
            }
        };
        try call(lmdb.mdb_set_compare, .{ self.inner, db.inner, S.cmp });
    }

    pub fn setItemOrder(self: Self, db: Database, comptime order: fn (a: []const u8, b: []const u8) math.Order) !void {
        const S = struct {
            fn cmp(a: ?*const lmdb.MDB_val, b: ?*const lmdb.MDB_val) callconv(.lmdb) c_int {
                const slice_a = @as([*]const u8, @ptrCast(a.?.mv_data))[0..a.?.mv_size];
                const slice_b = @as([*]const u8, @ptrCast(b.?.mv_data))[0..b.?.mv_size];
                return switch (order(slice_a, slice_b)) {
                    .eq => 0,
                    .lt => -1,
                    .gt => 1,
                };
            }
        };

        try call(lmdb.mdb_set_dupsort, .{ self.inner, db.inner, S.cmp });
    }

    pub fn get(self: Self, db: Database, key: []const u8) ![]const u8 {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        var v: lmdb.MDB_val = undefined;
        try call(lmdb.mdb_get, .{ self.inner, db.inner, k, &v });

        return @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size];
    }

    pub const PutFlags = packed struct {
        dont_overwrite_key: bool = false,
        dont_overwrite_item: bool = false,
        data_already_sorted: bool = false,
        set_already_sorted: bool = false,

        pub fn into(self: PutFlags) c_uint {
            var flags: c_uint = 0;
            if (self.dont_overwrite_key) flags |= lmdb.MDB_NOOVERWRITE;
            if (self.dont_overwrite_item) flags |= lmdb.MDB_NODUPDATA;
            if (self.data_already_sorted) flags |= lmdb.MDB_APPEND;
            if (self.set_already_sorted) flags |= lmdb.MDB_APPENDDUP;
            return flags;
        }
    };

    pub fn putItem(self: Self, db: Database, key: []const u8, val: anytype, flags: PutFlags) !void {
        const bytes = if (meta.trait.isIndexable(@TypeOf(val))) mem.span(val) else mem.asBytes(&val);
        return self.put(db, key, bytes, flags);
    }

    pub fn put(self: Self, db: Database, key: []const u8, val: []const u8, flags: PutFlags) !void {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };
        try call(lmdb.mdb_put, .{ self.inner, db.inner, k, v, flags.into() });
    }

    pub fn getOrPut(self: Self, db: Database, key: []const u8, val: []const u8) !?[]const u8 {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };

        call(lmdb.mdb_put, .{ self.inner, db.inner, k, v, lmdb.MDB_NOOVERWRITE }) catch |err| switch (err) {
            error.AlreadyExists => return @as([*]u8, @ptrCast(v.mv_data))[0..v.mv_size],
            else => return err,
        };

        return null;
    }

    pub const ReserveFlags = packed struct {
        dont_overwrite_key: bool = false,
        data_already_sorted: bool = false,

        pub fn into(self: ReserveFlags) c_uint {
            var flags: c_uint = lmdb.MDB_RESERVE;
            if (self.dont_overwrite_key) flags |= lmdb.MDB_NOOVERWRITE;
            if (self.data_already_sorted) flags |= lmdb.MDB_APPEND;
            return flags;
        }
    };

    pub const ReserveResult = union(enum) {
        successful: []u8,
        found_existing: []const u8,
    };

    pub fn reserve(self: Self, db: Database, key: []const u8, val_len: usize, flags: ReserveFlags) !ReserveResult {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val_len, .mv_data = null };

        call(lmdb.mdb_put, .{ self.inner, db.inner, k, v, flags.into() }) catch |err| switch (err) {
            error.AlreadyExists => return ReserveResult{
                .found_existing = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
            },
            else => return err,
        };

        return ReserveResult{
            .successful = @as([*]u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub fn del(self: Self, db: Database, key: []const u8, op: union(enum) { key: void, item: []const u8 }) !void {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v: ?*lmdb.MDB_val = switch (op) {
            .key => null,
            .item => |item| &lmdb.MDB_val{
                .mv_size = item.len,
                .mv_data = @ptrCast(item.ptr),
            },
        };
        try call(lmdb.mdb_del, .{ self.inner, db.inner, k, v });
    }

    pub fn drop(self: Self, db: Database, method: enum(c_int) { empty = 0, delete = 1 }) !void {
        try call(lmdb.mdb_drop, .{ self.inner, db.inner, @intFromEnum(method) });
    }

    pub fn deinit(self: Self) void {
        call(lmdb.mdb_txn_abort, .{self.inner});
    }

    pub fn commit(self: Self) !void {
        try call(lmdb.mdb_txn_commit, .{self.inner});
    }

    pub fn renew(self: Self) !void {
        try call(lmdb.mdb_txn_renew, .{self.inner});
    }

    pub fn reset(self: Self) !void {
        try call(lmdb.mdb_txn_reset, .{self.inner});
    }
};

pub const Cursor = packed struct {
    pub const Entry = struct {
        key: []const u8,
        val: []const u8,
    };

    pub fn Page(comptime T: type) type {
        return struct {
            key: []const u8,
            items: []align(1) const T,
        };
    }

    const Self = @This();

    inner: ?*lmdb.MDB_cursor,

    pub fn deinit(self: Self) void {
        call(lmdb.mdb_cursor_close, .{self.inner});
    }

    pub fn tx(self: Self) Transaction {
        return Transaction{ .inner = lmdb.mdb_cursor_txn(self.inner) };
    }

    pub fn db(self: Self) Database {
        return Database{ .inner = lmdb.mdb_cursor_dbi(self.inner) };
    }

    pub fn renew(self: Self, parent: Transaction) !void {
        try call(lmdb.mdb_cursor_renew, .{ parent.inner, self.inner });
    }

    pub fn count(self: Self) usize {
        var inner: lmdb.mdb_size_t = undefined;
        call(lmdb.mdb_cursor_count, .{ self.inner, &inner }) catch |err| {
            panic("cursor is initialized, or database does not support duplicate keys: {}", .{err});
        };
        return @intCast(inner);
    }

    pub fn updateItemInPlace(self: Self, current_key: []const u8, new_val: anytype) !void {
        const bytes = if (meta.trait.isIndexable(@TypeOf(new_val))) mem.span(new_val) else mem.asBytes(&new_val);
        return self.updateInPlace(current_key, bytes);
    }

    pub fn updateInPlace(self: Self, current_key: []const u8, new_val: []const u8) !void {
        const k = &lmdb.MDB_val{ .mv_size = current_key.len, .mv_data = @ptrCast(current_key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = new_val.len, .mv_data = @ptrCast(new_val.ptr) };
        try call(lmdb.mdb_cursor_put, .{ self.inner, k, v, lmdb.MDB_CURRENT });
    }

    /// May not be used with databases supporting duplicate keys.
    pub fn reserveInPlace(self: Self, current_key: []const u8, new_val_len: usize) ![]u8 {
        const k = &lmdb.MDB_val{ .mv_size = current_key.len, .mv_data = @ptrCast(current_key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = new_val_len, .mv_data = null };
        try call(lmdb.mdb_cursor_put, .{ self.inner, k, v, lmdb.MDB_CURRENT | lmdb.MDB_RESERVE });
        return @as([*]u8, @ptrCast(v.mv_data))[0..v.mv_size];
    }

    pub const PutFlags = packed struct {
        dont_overwrite_key: bool = false,
        dont_overwrite_item: bool = false,
        data_already_sorted: bool = false,
        set_already_sorted: bool = false,

        pub fn into(self: PutFlags) c_uint {
            var flags: c_uint = 0;
            if (self.dont_overwrite_key) flags |= lmdb.MDB_NOOVERWRITE;
            if (self.dont_overwrite_item) flags |= lmdb.MDB_NODUPDATA;
            if (self.data_already_sorted) flags |= lmdb.MDB_APPEND;
            if (self.set_already_sorted) flags |= lmdb.MDB_APPENDDUP;
            return flags;
        }
    };

    pub fn putItem(self: Self, key: []const u8, val: anytype, flags: PutFlags) !void {
        const bytes = if (meta.trait.isIndexable(@TypeOf(val))) mem.span(val) else mem.asBytes(&val);
        return self.put(key, bytes, flags);
    }

    pub fn put(self: Self, key: []const u8, val: []const u8, flags: PutFlags) !void {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };
        try call(lmdb.mdb_cursor_put, .{ self.inner, k, v, flags.into() });
    }

    pub fn putBatch(self: Self, key: []const u8, batch: anytype, flags: PutFlags) !usize {
        comptime assert(meta.trait.isIndexable(@TypeOf(batch)));

        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = [_]lmdb.MDB_val{
            .{ .mv_size = @sizeOf(meta.Elem(@TypeOf(batch))), .mv_data = @ptrCast(&batch[0]) },
            .{ .mv_size = mem.len(batch), .mv_data = undefined },
        };
        try call(lmdb.mdb_cursor_put, .{ self.inner, k, &v, @as(c_uint, @intCast(lmdb.MDB_MULTIPLE)) | flags.into() });

        return @intCast(v[1].mv_size);
    }

    pub fn getOrPut(self: Self, key: []const u8, val: []const u8) !?[]const u8 {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };

        call(lmdb.mdb_cursor_put, .{ self.inner, k, v, lmdb.MDB_NOOVERWRITE }) catch |err| switch (err) {
            error.AlreadyExists => return @as([*]u8, @ptrCast(v.mv_data))[0..v.mv_size],
            else => return err,
        };

        return null;
    }

    pub const ReserveFlags = packed struct {
        dont_overwrite_key: bool = false,
        data_already_sorted: bool = false,

        pub fn into(self: ReserveFlags) c_uint {
            var flags: c_uint = lmdb.MDB_RESERVE;
            if (self.dont_overwrite_key) flags |= lmdb.MDB_NOOVERWRITE;
            if (self.data_already_sorted) flags |= lmdb.MDB_APPEND;
            return flags;
        }
    };

    pub const ReserveResult = union(enum) {
        successful: []u8,
        found_existing: []const u8,
    };

    pub fn reserve(self: Self, key: []const u8, val_len: usize, flags: ReserveFlags) !ReserveResult {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val_len, .mv_data = null };

        call(lmdb.mdb_cursor_put, .{ self.inner, k, v, flags.into() }) catch |err| switch (err) {
            error.AlreadyExists => return ReserveResult{
                .found_existing = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
            },
            else => return err,
        };

        return ReserveResult{
            .successful = @as([*]u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub fn del(self: Self, op: enum(c_uint) { key = lmdb.MDB_NODUPDATA, item = 0 }) !void {
        call(lmdb.mdb_cursor_del, .{ self.inner, @intFromEnum(op) }) catch |err| switch (err) {
            error.InvalidParameter => return error.NotFound,
            else => return err,
        };
    }

    pub const Position = enum(lmdb.MDB_cursor_op) {
        first = lmdb.MDB_FIRST,
        first_item = lmdb.MDB_FIRST_DUP,
        current = lmdb.MDB_GET_CURRENT,
        last = lmdb.MDB_LAST,
        last_item = lmdb.MDB_LAST_DUP,
        next = lmdb.MDB_NEXT,
        next_item = lmdb.MDB_NEXT_DUP,
        next_key = lmdb.MDB_NEXT_NODUP,
        prev = lmdb.MDB_PREV,
        prev_item = lmdb.MDB_PREV_DUP,
        prev_key = lmdb.MDB_PREV_NODUP,
    };

    pub fn get(self: Self, pos: Position) !?Entry {
        var k: lmdb.MDB_val = undefined;
        var v: lmdb.MDB_val = undefined;
        call(lmdb.mdb_cursor_get, .{ self.inner, &k, &v, @intFromEnum(pos) }) catch |err| switch (err) {
            error.InvalidParameter => return if (pos == .current) null else err,
            error.NotFound => return null,
            else => return err,
        };
        return Entry{
            .key = @as([*]const u8, @ptrCast(k.mv_data))[0..k.mv_size],
            .val = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub const PagePosition = enum(lmdb.MDB_cursor_op) {
        current = lmdb.MDB_GET_MULTIPLE,
        next = lmdb.MDB_NEXT_MULTIPLE,
        prev = lmdb.MDB_PREV_MULTIPLE,
    };

    pub fn getPage(self: Self, comptime T: type, pos: PagePosition) !?Page(T) {
        var k: lmdb.MDB_val = undefined;
        var v: lmdb.MDB_val = undefined;
        call(lmdb.mdb_cursor_get, .{ self.inner, &k, &v, @intFromEnum(pos) }) catch |err| switch (err) {
            error.NotFound => return null,
            else => return err,
        };
        return Page(T){
            .key = @as([*]const u8, @ptrCast(k.mv_data))[0..k.mv_size],
            .items = mem.bytesAsSlice(T, @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size]),
        };
    }

    pub fn seekToItem(self: Self, key: []const u8, val: []const u8) !void {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };
        try call(lmdb.mdb_cursor_get, .{ self.inner, k, v, .MDB_GET_BOTH });
    }

    pub fn seekFromItem(self: Self, key: []const u8, val: []const u8) ![]const u8 {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        const v = &lmdb.MDB_val{ .mv_size = val.len, .mv_data = @ptrCast(val.ptr) };
        try call(lmdb.mdb_cursor_get, .{ self.inner, k, v, lmdb.MDB_GET_BOTH_RANGE });
        return @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size];
    }

    pub fn seekTo(self: Self, key: []const u8) ![]const u8 {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        var v: lmdb.MDB_val = undefined;
        try call(lmdb.mdb_cursor_get, .{ self.inner, k, &v, lmdb.MDB_SET_KEY });
        return @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size];
    }

    pub fn seekFrom(self: Self, key: []const u8) !Entry {
        const k = &lmdb.MDB_val{ .mv_size = key.len, .mv_data = @ptrCast(key.ptr) };
        var v: lmdb.MDB_val = undefined;
        try call(lmdb.mdb_cursor_get, .{ self.inner, k, &v, lmdb.MDB_SET_RANGE });
        return Entry{
            .key = @as([*]const u8, @ptrCast(k.mv_data))[0..k.mv_size],
            .val = @as([*]const u8, @ptrCast(v.mv_data))[0..v.mv_size],
        };
    }

    pub fn first(self: Self) !?Entry {
        return self.get(.first);
    }

    pub fn firstItem(self: Self) !?Entry {
        return self.get(.first_item);
    }

    pub fn current(self: Self) !?Entry {
        return self.get(.current);
    }

    pub fn last(self: Self) !?Entry {
        return self.get(.last);
    }

    pub fn lastItem(self: Self) !?Entry {
        return self.get(.last_item);
    }

    pub fn next(self: Self) !?Entry {
        return self.get(.next);
    }

    pub fn nextItem(self: Self) !?Entry {
        return self.get(.next_item);
    }

    pub fn nextKey(self: Self) !?Entry {
        return self.get(.next_key);
    }

    pub fn prev(self: Self) !?Entry {
        return self.get(.prev);
    }

    pub fn prevItem(self: Self) !?Entry {
        return self.get(.prev_item);
    }

    pub fn prevKey(self: Self) !?Entry {
        return self.get(.prev_key);
    }

    pub fn currentPage(self: Self, comptime T: type) !?Page(T) {
        return self.getPage(T, .current);
    }

    pub fn nextPage(self: Self, comptime T: type) !?Page(T) {
        return self.getPage(T, .next);
    }

    pub fn prevPage(self: Self, comptime T: type) !?Page(T) {
        return self.getPage(T, .prev);
    }
};
