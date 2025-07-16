const std = @import("std");
const s = @cImport({
    @cInclude("secp256k1.h");
});

pub fn main() !void {
    const ctx = s.secp256k1_context_create(s.SECP256K1_CONTEXT_NONE);
    defer s.secp256k1_context_destroy(ctx);

    var seckey: [32]u8 = undefined;
    std.mem.writeInt(u256, &seckey, 1, .big);

    var pubkey: s.secp256k1_pubkey = undefined;
    const ret = s.secp256k1_ec_pubkey_create(ctx, &pubkey, &seckey);
    std.debug.assert(ret == 1);

    var pubkey_bytes: [33]u8 = undefined;
    var pubkey_len: usize = 33;
    const ret2 = s.secp256k1_ec_pubkey_serialize(ctx, &pubkey_bytes, &pubkey_len, &pubkey, s.SECP256K1_EC_COMPRESSED);
    std.debug.assert(ret2 == 1 and pubkey_len == 33);
    const pubkey_hex = std.fmt.bytesToHex(&pubkey_bytes, .lower);
    std.debug.print("pubkey of seckey 1: {s}\n", .{pubkey_hex});
}
