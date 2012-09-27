compile:
	env
	$(CC) $(CFLAGS) $(ERL_CFLAGS) $(EXE_LDFLAGS) bcrypt_port.c bcrypt.o blowfish.o -o ../priv/bcrypt

clean:
	@rm -f ../priv/bcrypt
