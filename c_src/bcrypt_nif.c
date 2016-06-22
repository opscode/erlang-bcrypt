/*
 * Copyright (c) 2011-2012 Hunter Morris <hunter.morris@smarkets.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "erl_nif.h"
#include "erl_blf.h"
#include "bcrypt_nif.h"

static ERL_NIF_TERM hashpw(ErlNifEnv *env, ErlNifBinary bpass, ErlNifBinary bsalt);

static ERL_NIF_TERM bcrypt_encode_salt(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary csalt, bin;
    unsigned long log_rounds;

    if (!enif_inspect_binary(env, argv[0], &csalt) || 16 != csalt.size) {
        return enif_make_badarg(env);
    }

    if (!enif_get_ulong(env, argv[1], &log_rounds)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    if (!enif_alloc_binary(64, &bin)) {
        enif_release_binary(&csalt);
        return enif_make_badarg(env);
    }

    encode_salt((char *)bin.data, (u_int8_t*)csalt.data, csalt.size, log_rounds);
    enif_release_binary(&csalt);

    return enif_make_tuple2(
            env,
            enif_make_atom(env, "ok"),
            enif_make_string(env, (char *)bin.data, ERL_NIF_LATIN1));
}

static ERL_NIF_TERM bcrypt_hashpw(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary pass, salt;
    ERL_NIF_TERM result;

    if (!enif_inspect_iolist_as_binary(
                env,
                enif_make_copy(env, argv[0]),
                &pass)) {
        enif_release_binary(&pass);
        return enif_make_badarg(env);
    }

    if (!enif_inspect_iolist_as_binary(
                env,
                enif_make_copy(env, argv[1]),
                &salt)) {
        enif_release_binary(&pass);
        enif_release_binary(&salt);
        return enif_make_badarg(env);
    }

    result = hashpw(env, pass, salt);

    enif_release_binary(&pass);
    enif_release_binary(&salt);

    return result;
}

static ERL_NIF_TERM hashpw(ErlNifEnv *env, ErlNifBinary bpass, ErlNifBinary bsalt)
{
    char password[1024] = { 0 };
    char salt[1024] = { 0 };
    char encrypted[1024] = { 0 };

    size_t password_sz = 1024;
    if (password_sz > bpass.size)
        password_sz = bpass.size;
    (void)memcpy(&password, bpass.data, password_sz);

    size_t salt_sz = 1024;
    if (salt_sz > bsalt.size)
        salt_sz = bsalt.size;
    (void)memcpy(&salt, bsalt.data, salt_sz);

    if (bcrypt(encrypted, password, salt)) {
        return enif_make_tuple2(
            env,
            enif_make_atom(env, "error"),
            enif_make_string(env, "bcrypt failed", ERL_NIF_LATIN1));
    }

    return enif_make_tuple2(
        env,
        enif_make_atom(env, "ok"),
        enif_make_string(env, encrypted, ERL_NIF_LATIN1));
}

static ErlNifFunc bcrypt_nif_funcs[] =
{
    {"encode_salt", 2, bcrypt_encode_salt},
    {"hashpw", 2, bcrypt_hashpw}
};

ERL_NIF_INIT(bcrypt_nif, bcrypt_nif_funcs, NULL, NULL, NULL, NULL)
