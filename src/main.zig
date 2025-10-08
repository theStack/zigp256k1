const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const s = @cImport({
    @cInclude("secp256k1.h");
    @cInclude("secp256k1_extrakeys.h");
    @cInclude("secp256k1_silentpayments.h");
});

const N_INPUTS = 5;
const N_RECIPIENTS = 10;

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
    var id_ser: [8]u8 = undefined;
    var seckey: [32]u8 = undefined;
    var plain_pubkey: s.secp256k1_pubkey = undefined;
    var xonly_pubkey: s.secp256k1_xonly_pubkey = undefined;
    var keypair: s.secp256k1_keypair = undefined;

    std.mem.writeInt(u64, &id_ser, id, .big);
    Sha256.hash(&id_ser, &seckey, .{});
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

pub fn main() !void {
    const ctx = s.secp256k1_context_create(s.SECP256K1_CONTEXT_NONE);
    defer s.secp256k1_context_destroy(ctx);

    // silent payments experiments
    const scan_keymaterial = deterministicKeypair(ctx, 23);
    const spend_keymaterial = deterministicKeypair(ctx, 42);
    const scan_pubkey_bytes = pubkeySerialize(ctx, &scan_keymaterial.plain_pubkey);
    const spend_pubkey_bytes = pubkeySerialize(ctx, &spend_keymaterial.plain_pubkey);
    std.debug.print(" Scan pubkey: {x}\n", .{&scan_pubkey_bytes});
    std.debug.print("Spend pubkey: {x}\n", .{&spend_pubkey_bytes});
    std.debug.print("\n", .{});

    var input_keymaterial: [N_INPUTS]KeyMaterial = undefined;
    for (0..N_INPUTS) |i| {
        input_keymaterial[i] = deterministicKeypair(ctx, 123 * (i+1));
        const input_pubkey_bytes = pubkeySerialize(ctx, &input_keymaterial[i].plain_pubkey);
        std.debug.print("Input pubkey[{d}]: {x}\n", .{i, &input_pubkey_bytes});
    }

    // simple send with five legacy inputs, 10 recipients (all having the same addresss)
    var recipient_xpks: [N_RECIPIENTS]s.secp256k1_xonly_pubkey = undefined;
    var recipient_xpks_ptrs: [N_RECIPIENTS]*s.secp256k1_xonly_pubkey = undefined;
    var recipients: [N_RECIPIENTS]s.secp256k1_silentpayments_recipient = undefined;
    var recipients_ptrs: [N_RECIPIENTS]*s.secp256k1_silentpayments_recipient = undefined;
    for (0..N_RECIPIENTS) |i| {
        recipient_xpks_ptrs[i] = &recipient_xpks[i];
        recipients_ptrs[i] = &recipients[i];
        recipients[i].scan_pubkey = scan_keymaterial.plain_pubkey;
        recipients[i].spend_pubkey = spend_keymaterial.plain_pubkey;
        recipients[i].index = i;
    }
    var seckey_ptrs: [N_INPUTS]*const u8 = undefined;
    for (0..N_INPUTS) |i| {
        seckey_ptrs[i] = &input_keymaterial[i].seckey[0];
    }
    var outpoint_smallest: [36]u8 = undefined;
    Sha256.hash("smallest outpoint", outpoint_smallest[0..32], .{});
    std.mem.writeInt(u32, outpoint_smallest[32..36], 31337, .big);

    var ret = s.secp256k1_silentpayments_sender_create_outputs(ctx,
        @ptrCast(&recipient_xpks_ptrs), @ptrCast(&recipients_ptrs), N_RECIPIENTS,
        &outpoint_smallest, null, 0, &seckey_ptrs, N_INPUTS);
    std.debug.assert(ret == 1);
    std.debug.print("Sending ({d} inputs, {d} recipients), created output x-only pubkeys:\n",
        .{N_INPUTS, N_RECIPIENTS});
    for (recipient_xpks_ptrs) |generated_output| {
        const output_ser = xonlyPubkeySerialize(ctx, generated_output);
        std.debug.print("-> {x}\n", .{&output_ser});
    }
    var rng = std.Random.DefaultPrng.init(31337);
    rng.random().shuffle(*s.secp256k1_xonly_pubkey, recipient_xpks_ptrs[0..]);

    std.debug.print("--- Shuffled outputs, for the sake of testing: ---\n", .{});
    for (recipient_xpks_ptrs) |generated_output| {
        const output_ser = xonlyPubkeySerialize(ctx, generated_output);
        std.debug.print("-> {x}\n", .{&output_ser});
    }

    // create prevouts summary (the serialized variant would be created by an indexer
    // and provided to light clients)
    var prevouts_summary: s.secp256k1_silentpayments_prevouts_summary = undefined;
    var prevouts_summary_ser: [33]u8 = undefined;
    var input_pks: [N_INPUTS]s.secp256k1_pubkey = undefined;
    var input_pks_ptrs: [N_INPUTS]*s.secp256k1_pubkey = undefined;
    for (0..N_INPUTS) |i| {
        input_pks[i] = input_keymaterial[i].plain_pubkey;
        input_pks_ptrs[i] = &input_pks[i];
    }
    ret = s.secp256k1_silentpayments_recipient_prevouts_summary_create(ctx,
        &prevouts_summary, &outpoint_smallest, null, 0, @ptrCast(&input_pks_ptrs), N_INPUTS);
    std.debug.assert(ret == 1);

    ret = s.secp256k1_silentpayments_recipient_prevouts_summary_serialize(ctx,
        &prevouts_summary_ser, 33, &prevouts_summary, s.SECP256K1_EC_COMPRESSED);
    std.debug.assert(ret == 1);

    // scan in light client mode (i.e. we don't have access to full transaction)
    var prevouts_summary_lc: s.secp256k1_silentpayments_prevouts_summary = undefined;
    ret = s.secp256k1_silentpayments_recipient_prevouts_summary_parse(ctx,
        &prevouts_summary_lc, &prevouts_summary_ser, 33);
    std.debug.assert(ret == 1);

    var lc_output_xpks: [1]s.secp256k1_xonly_pubkey = undefined;
    var lc_output_xpks_ptrs: [1]*s.secp256k1_xonly_pubkey = undefined;
    lc_output_xpks_ptrs[0] = &lc_output_xpks[0];
    var lc_spendkey_pk_ptrs: [1]*const s.secp256k1_pubkey = undefined;
    lc_spendkey_pk_ptrs[0] = &spend_keymaterial.plain_pubkey;
    ret = s.secp256k1_silentpayments_recipient_create_output_pubkeys(ctx,
        @ptrCast(&lc_output_xpks_ptrs), &scan_keymaterial.seckey, &prevouts_summary_lc,
        @ptrCast(&lc_spendkey_pk_ptrs), 1);
    std.debug.assert(ret == 1);

    var lc_found_output: bool = false;
    for (recipient_xpks_ptrs, 0..) |output_xpk_ptr, i| {
        if (s.secp256k1_xonly_pubkey_cmp(ctx, &lc_output_xpks[0], output_xpk_ptr) == 0) {
            const candidate_ser = xonlyPubkeySerialize(ctx, output_xpk_ptr);
            std.debug.print("light client scanning found pubkey {x} at index {d} (fixed for k=0)\n",
                .{&candidate_ser, i});
            lc_found_output = true;
            break;
        }
    }

    // full scan (i.e. we do have access to the full transaction, including prevouts data)
    var found_outputs: [N_RECIPIENTS]s.secp256k1_silentpayments_found_output = undefined;
    var found_outputs_ptrs: [N_RECIPIENTS]*s.secp256k1_silentpayments_found_output = undefined;
    var n_found_outputs: usize = undefined;
    for (0..N_RECIPIENTS) |i| {
        found_outputs_ptrs[i] = &found_outputs[i];
    }
    ret = s.secp256k1_silentpayments_recipient_scan_outputs(ctx,
        @ptrCast(&found_outputs_ptrs), &n_found_outputs, @ptrCast(&recipient_xpks_ptrs), N_RECIPIENTS,
        &scan_keymaterial.seckey[0], &prevouts_summary, &spend_keymaterial.plain_pubkey, null, null);
    std.debug.assert(ret == 1);
    std.debug.print("full scanning found the following outputs:\n", .{});
    for (0..n_found_outputs) |i| {
        const found_output = &found_outputs[i];
        const output_ser = xonlyPubkeySerialize(ctx, &found_output.output);
        std.debug.print("-> pubkey {x},\n   output tweak {x}\n",
            .{&output_ser, found_output.tweak});
    }

    if (lc_found_output) {
        std.debug.print("Light client scan SUCCEEDED, found output for k=0.\n", .{});
    } else {
        std.debug.print("Light client scan FAILED, did'nt find any output.\n", .{});
    }
    if (n_found_outputs == N_RECIPIENTS) {
        std.debug.print("Full scan SUCCEEDED, found all {d} outputs.\n", .{N_RECIPIENTS});
    } else {
        std.debug.print("Full scan FAILED, found only {d}/{d} outputs.\n", .{n_found_outputs, N_RECIPIENTS});
    }
    // TODO: if the outputs are shuffled, all of them should be found too
}
