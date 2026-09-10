# koinu.dog - a minimal, security-conscious dogecoin light wallet.
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
# thread abstraction is compiled out. pthread is for net/psync's parallel
# header download, nothing else.
override CFLAGS += -pthread
CPPFLAGS += -Icrypto -Inet -Iwallet -Iinclude -I$(SECP_DIR)/include -Icrypto/vendor/poly1305-donna \
            -Icrypto/vendor/argon2 -DARGON2_NO_THREADS

CORE_SRC = crypto/rng.c crypto/mem.c crypto/hex.c crypto/sha2.c crypto/ripemd160.c crypto/hmac.c crypto/siphash.c \
           crypto/pbkdf2.c crypto/scrypt.c crypto/scrypt_avx2.c crypto/base58.c crypto/ec.c crypto/bip32.c crypto/bip39.c \
           crypto/chainparams.c crypto/address.c crypto/bip44.c \
           crypto/chacha20.c crypto/aead.c crypto/kdf.c crypto/keystore.c crypto/tx.c crypto/psbt.c \
           net/proto.c net/msg.c net/peer.c net/socks5.c net/headers.c net/sync.c net/psync.c net/seed.c net/spv.c net/gcs.c net/cf.c net/cfstore.c \
           wallet/utxo.c \
           crypto/vendor/poly1305-donna/poly1305-donna.c \
           crypto/vendor/argon2/argon2.c crypto/vendor/argon2/core.c \
           crypto/vendor/argon2/encoding.c crypto/vendor/argon2/ref.c \
           crypto/vendor/argon2/thread.c crypto/vendor/argon2/blake2/blake2b.c
CORE_OBJ = $(CORE_SRC:.c=.o)

LIB   = libkw.a
TESTS = test/test_rng test/test_sha2 test/test_ripemd160 test/test_hmac test/test_siphash \
        test/test_pbkdf2 test/test_scrypt test/test_base58 test/test_ec test/test_bip32 test/test_bip39 \
        test/test_address test/test_aead test/test_argon2 test/test_keystore test/test_tx test/test_psbt \
        test/test_proto test/test_msg test/test_peer test/test_socks5 test/test_headers test/test_sync test/test_psync \
        test/test_utxo test/test_spv test/test_gcs test/test_cf test/test_cfstore

all: $(LIB) kw

$(LIB): $(CORE_OBJ)
	$(AR) rcs $@ $^

kw: cli/kw.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ cli/kw.o $(LIB) $(SECP_LIB)

# resident outpoint-confirmation daemon
kwd: cli/kwd.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ cli/kwd.o $(LIB) $(SECP_LIB)

# read-only terminal view of a wallet
kwui: cli/kwui.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ cli/kwui.o $(LIB) $(SECP_LIB)

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

test/test_siphash: test/test_siphash.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_siphash.o $(LIB)

test/test_pbkdf2: test/test_pbkdf2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_pbkdf2.o test/testutil.o $(LIB)

test/test_scrypt: test/test_scrypt.o test/scrypt_portable.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_scrypt.o test/scrypt_portable.o test/testutil.o $(LIB)

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

test/test_psbt: test/test_psbt.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_psbt.o $(LIB) $(SECP_LIB)

test/test_proto: test/test_proto.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_proto.o test/testutil.o $(LIB)

test/test_msg: test/test_msg.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_msg.o test/testutil.o $(LIB)

test/test_peer: test/test_peer.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_peer.o $(LIB)

test/test_socks5: test/test_socks5.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_socks5.o $(LIB)

test/test_headers: test/test_headers.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_headers.o test/testutil.o $(LIB)

test/test_sync: test/test_sync.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_sync.o test/testutil.o $(LIB)

test/test_psync: test/test_psync.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_psync.o $(LIB)

test/test_utxo: test/test_utxo.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_utxo.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_spv: test/test_spv.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_spv.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_gcs: test/test_gcs.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/test_gcs.o test/testutil.o $(LIB)

test/test_cf: test/test_cf.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_cf.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_cfstore: test/test_cfstore.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/test_cfstore.o test/testutil.o $(LIB) $(SECP_LIB)

net_sync: test/net_sync.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/net_sync.o $(LIB)

# live SPV balance tool, built on demand, not part of `make check`
net_spv: test/net_spv.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/net_spv.o $(LIB) $(SECP_LIB)

# live BIP157 compact-filter balance tool, needs a peer that serves filters
net_cf: test/net_cf.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/net_cf.o $(LIB) $(SECP_LIB)

# live p2sh 2-of-2 co-sign harness, built on demand
net_multisig: test/net_multisig.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -o $@ test/net_multisig.o $(LIB) $(SECP_LIB)

# live handshake tool, built on demand, not part of `make check`
net_handshake: test/net_handshake.o $(LIB)
	$(CC) $(CFLAGS) -o $@ test/net_handshake.o $(LIB)

# Fuzz targets over the parsers that read bytes a peer chose. `make fuzz` needs
# clang for libFuzzer; `make fuzz-run CORPUS=dir` replays a corpus with any
# compiler, so CI can check the known inputs without clang.
FUZZ_CC ?= clang
.PHONY: fuzz fuzz-run fuzz-asan
fuzz: fuzz/fuzz_parse.c $(SECP_LIB)
	$(FUZZ_CC) -std=gnu11 -O1 -g -fsanitize=fuzzer,address,undefined $(CPPFLAGS) \
	    -o fuzz_parse fuzz/fuzz_parse.c $(CORE_SRC) $(SECP_LIB)

fuzz-run: fuzz/fuzz_parse.c $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(CPPFLAGS) -DKW_FUZZ_STANDALONE -o fuzz_replay \
	    fuzz/fuzz_parse.c $(LIB) $(SECP_LIB)
	./fuzz_replay $(wildcard fuzz/corpus/*)

# Vendored code trips warnings we do not police in upstreams: leave the code as
# shipped and quiet only those objects.
crypto/vendor/poly1305-donna/poly1305-donna.o: CFLAGS += -Wno-expansion-to-defined
crypto/vendor/argon2/%.o: CFLAGS += -Wno-type-limits -Wno-sign-compare

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -MMD -MP -c -o $@ $<

# Rebuild an object when a header it includes changes. Without this a struct
# whose size changed leaves stale objects linking against a new library, which
# fails at runtime looking like a logic bug rather than at the build.
-include $(CORE_OBJ:.o=.d) $(TESTS:=.d) cli/kw.d cli/kwd.d cli/kwui.d test/testutil.d

check: $(TESTS) kw
	./test/test_rng
	./test/test_sha2
	./test/test_ripemd160
	./test/test_hmac
	./test/test_siphash
	./test/test_pbkdf2
	./test/test_scrypt
	./test/test_base58
	./test/test_ec
	./test/test_bip32
	./test/test_bip39
	./test/test_address
	./test/test_aead
	./test/test_argon2
	./test/test_keystore
	./test/test_tx
	./test/test_psbt
	./test/test_proto
	./test/test_msg
	./test/test_peer
	./test/test_socks5
	./test/test_headers
	./test/test_sync
	./test/test_psync
	./test/test_utxo
	./test/test_spv
	./test/test_gcs
	./test/test_cf
	./test/test_cfstore
	./test/test_cli.sh
	./test/test_sweep.sh

# The tests must also pass with address and undefined-behaviour sanitizers on.
asan:
	$(MAKE) clean
	$(MAKE) check CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-omit-frame-pointer"

# The fuzzers are only meaningful under the sanitizers: without them a stray
# read is silently harmless and the run reports success.
fuzz-asan:
	$(MAKE) clean
	$(MAKE) fuzz-run CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -f $(LIB) $(CORE_OBJ) $(TESTS) test/*.o test/*.d kw kwd kwui fuzz_parse fuzz_replay cli/*.o cli/*.d crypto/*.d net/*.d wallet/*.d crypto/vendor/*/*.d crypto/vendor/argon2/blake2/*.d net_handshake net_sync net_spv net_cf net_multisig

# Also clean the submodule build. Left out of `clean` because rebuilding
# secp256k1 is slow and rarely what you want between edits.
distclean: clean
	-cd $(SECP_DIR) && $(MAKE) distclean

.PHONY: all check asan clean distclean
