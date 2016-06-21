#ifndef ERLANG_BCRYPT_BCRYPT_NIF_H
#define ERLANG_BCRYPT_BCRYPT_NIF_H

typedef unsigned char byte;

int bcrypt(char *, const char *, const char *);
void encode_salt(char *, u_int8_t *, u_int16_t, u_int8_t);

//typedef struct {
//    ErlNifResourceType *bcrypt_rt;
//} bcrypt_privdata_t;

#endif  // ERLANG_BCRYPT_BCRYPT_NIF_H
