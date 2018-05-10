#include "erl_nif.h"
#include "aes_ofb.h"

#define ATOM_OK enif_make_atom(env, "ok")
#define OK_TUPLE(a) enif_make_tuple2(env, ATOM_OK, a)
#define OK_TUPLE2(a, b) enif_make_tuple3(env, ATOM_OK, a, b)

uint8_t const ms_aeskey[32] = {
    0x13, 0x00, 0x00, 0x00,
    0x08, 0x00, 0x00, 0x00,
    0x06, 0x00, 0x00, 0x00,
    0xB4, 0x00, 0x00, 0x00,
    0x1B, 0x00, 0x00, 0x00,
    0x0F, 0x00, 0x00, 0x00,
    0x33, 0x00, 0x00, 0x00,
    0x52, 0x00, 0x00, 0x00,
};

void print_hex(uint8_t* hex, size_t length) {
  printf("hex: ");
  for (int i = 0; i < (int)length; i++) {
    printf("0x%x ", hex[i]);
  }
  printf("\n");
  return;
}

static ERL_NIF_TERM
encrypt_hdr(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    // Convert client_iv to unsigned char *
    ErlNifBinary send_iv;
    enif_inspect_binary(env, argv[0], &send_iv);

    // Convert hdr_size to int
    int nbytes;
    enif_get_int(env, argv[1], &nbytes);

    // Encrypt header
    uint32_t hdr = ms_encrypted_hdr(send_iv.data, nbytes);

    ERL_NIF_TERM hdr_term = enif_make_int(env, hdr);
    return OK_TUPLE(hdr_term);
}

static ERL_NIF_TERM
encrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    // Convert packet to unsigned char *
    ErlNifBinary packet;
    enif_inspect_binary(env, argv[0], &packet);

    // Convert send_iv to unsigned char *
    ErlNifBinary send_iv;
    enif_inspect_binary(env, argv[1], &send_iv);

    // Encrypt packet
    ms_encrypt(packet.data, packet.size);

    // Apply AES OFB mode to packet
    ms_aes_ofb(packet.data, send_iv.data, packet.size, ms_aeskey);

    ms_shuffle_iv(send_iv.data);

    ERL_NIF_TERM packet_term = enif_make_binary(env, &packet);
    ERL_NIF_TERM iv_term = enif_make_binary(env, &send_iv);
    return OK_TUPLE2(packet_term, iv_term);
}

static ERL_NIF_TERM
decrypt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    // Convert packet to unsigned char *
    ErlNifBinary packet;
    enif_inspect_binary(env, argv[0], &packet);

    // Convert client_iv to unsigned char *
    ErlNifBinary recv_iv;
    enif_inspect_binary(env, argv[1], &recv_iv);

    // Apply AES OFB mode to packet
    ms_aes_ofb(packet.data, recv_iv.data, packet.size, ms_aeskey);

    // Decrypt packet
    ms_decrypt(packet.data, packet.size);

    ms_shuffle_iv(recv_iv.data);

    ERL_NIF_TERM packet_term = enif_make_binary(env, &packet);
    ERL_NIF_TERM iv_term = enif_make_binary(env, &recv_iv);
    return OK_TUPLE2(packet_term, iv_term);
}

static ErlNifFunc nif_funcs[] = {
  {"encrypt_hdr", 2, encrypt_hdr},
  {"encrypt", 2, encrypt},
  {"decrypt", 2, decrypt}
};

ERL_NIF_INIT(Elixir.MsBot.Crypto.Nif, nif_funcs, NULL, NULL, NULL, NULL)
