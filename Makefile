# dogewallet - a minimal, security-conscious dogecoin light wallet.
#
# secp256k1 is the only submodule; everything in crypto/ is frozen, either
# vendored from a named upstream at a named commit or written here, and owned
# in-tree. See docs/PROVENANCE.md.

CC       ?= cc
CFLAGS   ?= -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter

# An implicit declaration links against the wrong prototype and returns the
# wrong type at the ABI, which is a bug at runtime rather than a warning. Stop
# the build on it. Overridden, not appended, so it survives a CFLAGS= override.
override CFLAGS += -Werror=implicit-function-declaration

SECP_DIR = depends/secp256k1
SECP_LIB = $(SECP_DIR)/.libs/libsecp256k1.a

# argon2 runs single-threaded (parallelism handled in one process), so its
# thread abstraction is compiled out and no pthread is pulled in.
CPPFLAGS += -Icrypto -Iinclude -I$(SECP_DIR)/include -Icrypto/vendor/poly1305-donna \
            -Icrypto/vendor/argon2 -DARGON2_NO_THREADS

CORE_SRC = crypto/rng.c crypto/mem.c crypto/hex.c crypto/sha2.c crypto/ripemd160.c crypto/hmac.c \
           crypto/pbkdf2.c crypto/base58.c crypto/ec.c crypto/bip32.c crypto/bip39.c \
           crypto/chainparams.c crypto/address.c crypto/bip44.c \
           crypto/chacha20.c crypto/aead.c crypto/kdf.c crypto/keystore.c crypto/tx.c \
           crypto/vendor/poly1305-donna/poly1305-donna.c \
           crypto/vendor/argon2/argon2.c crypto/vendor/argon2/core.c \
           crypto/vendor/argon2/encoding.c crypto/vendor/argon2/ref.c \
           crypto/vendor/argon2/thread.c crypto/vendor/argon2/blake2/blake2b.c
CORE_OBJ = $(CORE_SRC:.c=.o)

LIB   = libdogewallet.a
TESTS = test/test_rng test/test_sha2 test/test_ripemd160 test/test_hmac \
        test/test_pbkdf2 test/test_base58 test/test_ec test/test_bip32 test/test_bip39 \
        test/test_address test/test_aead test/test_argon2 test/test_keystore test/test_tx

all: $(LIB)

$(LIB): $(CORE_OBJ)
	$(AR) rcs $@ $^

# The one submodule, built via its own autotools into a static lib. Only objects
# that reference it (ec.o, pulled in by test_ec) need it at link time.
$(SECP_LIB):
	cd $(SECP_DIR) && ./autogen.sh && ./configure --enable-static --disable-shared \
	    --disable-tests --disable-exhaustive-tests --disable-benchmark && $(MAKE)

test/test_rng: test/test_rng.o $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

test/test_sha2: test/test_sha2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_sha2.o test/testutil.o $(LIB)

test/test_ripemd160: test/test_ripemd160.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_ripemd160.o test/testutil.o $(LIB)

test/test_hmac: test/test_hmac.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_hmac.o test/testutil.o $(LIB)

test/test_pbkdf2: test/test_pbkdf2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_pbkdf2.o test/testutil.o $(LIB)

test/test_base58: test/test_base58.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_base58.o test/testutil.o $(LIB)

test/test_ec: test/test_ec.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_ec.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_bip32: test/test_bip32.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_bip32.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_bip39: test/test_bip39.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_bip39.o test/testutil.o $(LIB)

test/test_address: test/test_address.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_address.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_aead: test/test_aead.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_aead.o test/testutil.o $(LIB)

test/test_argon2: test/test_argon2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_argon2.o test/testutil.o $(LIB)

test/test_keystore: test/test_keystore.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_keystore.o $(LIB)

test/test_tx: test/test_tx.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_tx.o $(LIB) $(SECP_LIB)

# Vendored code trips warnings we do not police in upstreams: leave the code as
# shipped and quiet only those objects.
crypto/vendor/poly1305-donna/poly1305-donna.o: CFLAGS += -Wno-expansion-to-defined
crypto/vendor/argon2/%.o: CFLAGS += -Wno-type-limits -Wno-sign-compare

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check: $(TESTS)
	./test/test_rng
	./test/test_sha2
	./test/test_ripemd160
	./test/test_hmac
	./test/test_pbkdf2
	./test/test_base58
	./test/test_ec
	./test/test_bip32
	./test/test_bip39
	./test/test_address
	./test/test_aead
	./test/test_argon2
	./test/test_keystore
	./test/test_tx

# The tests must also pass with address and undefined-behaviour sanitizers on.
asan:
	$(MAKE) clean
	$(MAKE) check CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -f $(LIB) $(CORE_OBJ) $(TESTS) test/*.o

# Also clean the submodule build. Left out of `clean` because rebuilding
# secp256k1 is slow and rarely what you want between edits.
distclean: clean
	-cd $(SECP_DIR) && $(MAKE) distclean

.PHONY: all check asan clean distclean
