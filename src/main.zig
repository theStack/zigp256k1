const std = @import("std");
const s = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_silentpayments.h");
});

const N_INPUTS = 1;
const K_MAX = s.SECP256K1_SILENTPAYMENTS_RECIPIENT_GROUP_LIMIT;
const N_RECIPIENTS = 23250;
const LABEL_CACHE_ENTRIES = 100_000;

fn pubkeySerialize(ctx: ?*const s.secp256k1_context, pubkey: *const s.secp256k1_pubkey) [33]u8 {
    var pubkey_ser: [33]u8 = undefined;
    var pubkey_len: usize = 33;
    const ret = s.secp256k1_ec_pubkey_serialize(ctx, &pubkey_ser, &pubkey_len, pubkey, s.SECP256K1_EC_COMPRESSED);
    std.debug.assert(ret == 1 and pubkey_len == 33);
    return pubkey_ser;
}

fn xonlyPubkeySerialize(ctx: ?*const s.secp256k1_context, xonly_pubkey: *const s.secp256k1_xonly_pubkey) [32]u8 {
    var xonly_pubkey_ser: [32]u8 = undefined;
    const ret = s.secp256k1_xonly_pubkey_serialize(ctx, &xonly_pubkey_ser, xonly_pubkey);
    std.debug.assert(ret == 1);
    return xonly_pubkey_ser;
}

const KeyMaterial = struct {
    seckey: [32]u8,
    plain_pubkey: s.secp256k1_pubkey,
    xonly_pubkey: s.secp256k1_xonly_pubkey,
    keypair: s.secp256k1_keypair,
};

fn deterministicKeypair(ctx: ?*const s.secp256k1_context, id: u64) KeyMaterial {
    var seckey: [32]u8 = undefined;
    var plain_pubkey: s.secp256k1_pubkey = undefined;
    var xonly_pubkey: s.secp256k1_xonly_pubkey = undefined;
    var keypair: s.secp256k1_keypair = undefined;

    @memset(&seckey, 0);
    std.mem.writeInt(u64, seckey[24..], id, .big);
    var ret = s.secp256k1_keypair_create(ctx, &keypair, &seckey);
    std.debug.assert(ret == 1);
    ret = s.secp256k1_keypair_pub(ctx, &plain_pubkey, &keypair);
    std.debug.assert(ret == 1);
    ret = s.secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey, null, &keypair);
    std.debug.assert(ret == 1);
    return KeyMaterial {
        .seckey = seckey,
        .plain_pubkey = plain_pubkey,
        .xonly_pubkey = xonly_pubkey,
        .keypair = keypair
    };
}

const LabelData = struct {
    label: s.secp256k1_silentpayments_label,
    label_serialized: [33]u8,
    label_tweak: [32]u8,
};

fn spCreateLabel(ctx: ?*const s.secp256k1_context, scan_key: [32]u8, m: u32) LabelData {
    var new_label: LabelData = undefined;
    var ret = s.secp256k1_silentpayments_recipient_label_create(ctx,
        &new_label.label, &new_label.label_tweak, &scan_key, m);
    std.debug.assert(ret == 1);
    ret = s.secp256k1_silentpayments_recipient_label_serialize(ctx,
        &new_label.label_serialized, &new_label.label);
    std.debug.assert(ret == 1);
    return new_label;
}

fn spCreateLabeledSpendPubkey(ctx: ?*const s.secp256k1_context, unlabeled_spend_pubkey: *const s.secp256k1_pubkey, label: *const s.secp256k1_silentpayments_label) s.secp256k1_pubkey {
    var labeled_spend_pubkey: s.secp256k1_pubkey = undefined;
    const ret = s.secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(ctx,
        &labeled_spend_pubkey, unlabeled_spend_pubkey, label);
    std.debug.assert(ret == 1);
    return labeled_spend_pubkey;
}

fn labelLookupFn(label33: [*c]const u8, label_context: ?*const anyopaque) callconv(.c) [*c]const u8 {
    const label_cache: *std.AutoHashMap([33]u8, [32]u8) = @constCast(@ptrCast(@alignCast(label_context.?)));
    var label: [33]u8 = undefined;
    @memcpy(&label, label33);
    if (label_cache.getPtr(label)) |label_tweak| {
        return label_tweak;
    }
    return null;
}

pub fn main() !void {
    const ctx = s.secp256k1_context_create(s.SECP256K1_CONTEXT_NONE);
    defer s.secp256k1_context_destroy(ctx);

    // silent payments key material
    const scan_keymaterial = deterministicKeypair(ctx, 0xdead);
    const spend_keymaterial = deterministicKeypair(ctx, 0xbeef);
    const scan_pubkey_bytes = pubkeySerialize(ctx, &scan_keymaterial.plain_pubkey);
    const spend_pubkey_bytes = pubkeySerialize(ctx, &spend_keymaterial.plain_pubkey);
    // label it (only change label for now, i.e. m=0)
    const change_label_data = spCreateLabel(ctx, scan_keymaterial.seckey, 0);
    const labeled_spend_pubkey = spCreateLabeledSpendPubkey(ctx, &spend_keymaterial.plain_pubkey, &change_label_data.label);
    const labeled_spend_pubkey_bytes = pubkeySerialize(ctx, &labeled_spend_pubkey);
    var label_cache = std.AutoHashMap([33]u8, [32]u8).init(std.heap.page_allocator);
    defer label_cache.deinit();
    try label_cache.put(change_label_data.label_serialized, change_label_data.label_tweak);
    for (0..LABEL_CACHE_ENTRIES-1) |_i| {
        const i: u64 = @intCast(_i);
        var label_tweak: [32]u8 = undefined;
        @memset(&label_tweak, 0x42);
        std.mem.writeInt(u64, label_tweak[24..], i, .big);
        var label: s.secp256k1_pubkey = undefined;
        const ret = s.secp256k1_ec_pubkey_create(ctx, &label, &label_tweak);
        std.debug.assert(ret == 1);
        const label_serialized = pubkeySerialize(ctx, &label);
        try label_cache.put(label_serialized, label_tweak);
    }
    std.debug.assert(label_cache.count() == LABEL_CACHE_ENTRIES);

    std.debug.print("  Scan public key: {x}\n", .{&scan_pubkey_bytes});
    std.debug.print(" Spend public key: {x}\n", .{&spend_pubkey_bytes});
    std.debug.print("Labeled spend key: {x}\n", .{&labeled_spend_pubkey_bytes});
    std.debug.print("Label cache is populated with {d} entries (only one being relevant)\n", .{LABEL_CACHE_ENTRIES});
    std.debug.print("\n", .{});

    var input_keymaterial: [N_INPUTS]KeyMaterial = undefined;
    for (0..N_INPUTS) |i| {
        input_keymaterial[i] = deterministicKeypair(ctx, 0x1337 * (i+1));
        const input_pubkey_bytes = xonlyPubkeySerialize(ctx, &input_keymaterial[i].xonly_pubkey);
        std.debug.print("Input pubkey[{d}]: {x}\n", .{i, &input_pubkey_bytes});
    }

    // send with one taproot input, K_max recipients (all having the same labeled addresss)
    const allocator = std.heap.page_allocator;
    var recipient_xpks = try allocator.alloc(s.secp256k1_xonly_pubkey, N_RECIPIENTS);
    defer allocator.free(recipient_xpks);
    var recipient_xpks_ptrs = try allocator.alloc(*s.secp256k1_xonly_pubkey, N_RECIPIENTS);
    defer allocator.free(recipient_xpks_ptrs);
    var recipients = try allocator.alloc(s.secp256k1_silentpayments_recipient, N_RECIPIENTS);
    defer allocator.free(recipients);
    var recipients_ptrs = try allocator.alloc(*s.secp256k1_silentpayments_recipient, N_RECIPIENTS);
    defer allocator.free(recipients_ptrs);
    for (0..N_RECIPIENTS) |i| {
        recipient_xpks_ptrs[i] = &recipient_xpks[i];
        recipients_ptrs[i] = &recipients[i];
        if (i < K_MAX) {
            recipients[i].scan_pubkey = scan_keymaterial.plain_pubkey;
        } else {
            const bogus_key = deterministicKeypair(ctx, 1000000 + i);
            recipients[i].scan_pubkey = bogus_key.plain_pubkey; // bogus scan pubkey, won't match
        }
        recipients[i].spend_pubkey = labeled_spend_pubkey;
        recipients[i].index = @intCast(i);
    }

    var seckey_ptrs: [N_INPUTS]*const s.secp256k1_keypair = undefined;
    for (0..N_INPUTS) |i| {
        seckey_ptrs[i] = &input_keymaterial[i].keypair;
    }
    var outpoint_smallest: [36]u8 = undefined;
    @memset(&outpoint_smallest, 0xcc);
    std.mem.writeInt(u32, outpoint_smallest[32..36], 0, .big);

    var ret = s.secp256k1_silentpayments_sender_create_outputs(ctx,
        @ptrCast(recipient_xpks_ptrs), @ptrCast(recipients_ptrs), N_RECIPIENTS,
        &outpoint_smallest, &seckey_ptrs, N_INPUTS, null, 0);
    std.debug.assert(ret == 1);
    std.debug.print("Sending ({d} inputs, {d} recipients), created output x-only pubkeys:\n",
        .{N_INPUTS, N_RECIPIENTS});
    for (recipient_xpks_ptrs) |generated_output| {
        const output_ser = xonlyPubkeySerialize(ctx, generated_output);
        //std.debug.print("-> {x}\n", .{&output_ser});
        _ = output_ser;
    }
    // var rng = std.Random.DefaultPrng.init(31337);
    // rng.random().shuffle(*s.secp256k1_xonly_pubkey, recipient_xpks_ptrs);
    std.mem.reverse(*s.secp256k1_xonly_pubkey, recipient_xpks_ptrs);

    std.debug.print("--- Outputs in worst-case order, for the sake of testing: ---\n", .{});
    for (recipient_xpks_ptrs) |generated_output| {
        const output_ser = xonlyPubkeySerialize(ctx, generated_output);
        //std.debug.print("-> {x}\n", .{&output_ser});
        _ = output_ser;
    }

    // create prevouts summary (the serialized variant would be created by an indexer
    // and provided to light clients, but it's not available yet in #1765)
    var prevouts_summary: s.secp256k1_silentpayments_prevouts_summary = undefined;
    var input_pks: [N_INPUTS]s.secp256k1_xonly_pubkey = undefined;
    var input_pks_ptrs: [N_INPUTS]*s.secp256k1_xonly_pubkey = undefined;
    for (0..N_INPUTS) |i| {
        input_pks[i] = input_keymaterial[i].xonly_pubkey;
        input_pks_ptrs[i] = &input_pks[i];
    }
    ret = s.secp256k1_silentpayments_recipient_prevouts_summary_create(ctx,
        &prevouts_summary, &outpoint_smallest, @ptrCast(&input_pks_ptrs), N_INPUTS, null, 0);
    std.debug.assert(ret == 1);

    // full scan (i.e. we do have access to the full transaction, including prevouts data)
    var found_outputs = try allocator.alloc(s.secp256k1_silentpayments_found_output, N_RECIPIENTS);
    defer allocator.free(found_outputs);
    var found_outputs_ptrs = try allocator.alloc(*s.secp256k1_silentpayments_found_output, N_RECIPIENTS);
    defer allocator.free(found_outputs_ptrs);
    var n_found_outputs: u32 = undefined;
    for (0..N_RECIPIENTS) |i| {
        found_outputs_ptrs[i] = &found_outputs[i];
    }
    const t_start = std.time.nanoTimestamp();
    ret = s.secp256k1_silentpayments_recipient_scan_outputs(ctx,
        @ptrCast(found_outputs_ptrs), &n_found_outputs, @ptrCast(recipient_xpks_ptrs), N_RECIPIENTS,
        &scan_keymaterial.seckey[0], &prevouts_summary, &spend_keymaterial.plain_pubkey, labelLookupFn, &label_cache);
    std.debug.assert(ret == 1);
    const t_end = std.time.nanoTimestamp();
    const elapsed_secs = @as(f64, @floatFromInt(t_end - t_start)) / @as(f64, std.time.ns_per_s);
    std.debug.print("***** Scanning took {d:.3} seconds *****\n", .{elapsed_secs});
    std.debug.print("full scanning found the following outputs:\n", .{});
    for (0..n_found_outputs) |i| {
        const found_output = &found_outputs[i];
        const output_ser = xonlyPubkeySerialize(ctx, &found_output.output);
        //std.debug.print("-> pubkey {x},\n   output tweak {x}\n", .{&output_ser, found_output.tweak});
        _ = output_ser;
    }

    if (n_found_outputs == K_MAX) {
        std.debug.print("Full scan SUCCEEDED, found all {d} outputs.\n", .{K_MAX});
    } else {
        std.debug.print("Full scan FAILED, found only {d}/{d} outputs.\n", .{n_found_outputs, K_MAX});
    }
}
