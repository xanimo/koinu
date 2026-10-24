# koinu.dog - a minimal, security-conscious dogecoin light wallet.
#
# secp256k1 is the only submodule; everything in crypto/ is frozen, either
# vendored from a named upstream at a named commit or written here, and owned
# in-tree. See docs/PROVENANCE.md.

CC       ?= cc
, := ,

# Every hardening flag is probed against this compiler and linker rather than
# assumed: the list is otherwise whatever the builder's toolchain happens to
# turn on by default, which is how -z now and full RELRO came to be present
# under Ubuntu's gcc and absent under clang on the same objects. A flag that
# does not probe is dropped rather than failing the build, since the macos
# linker takes none of the -z forms.
cc_ok  = $(shell $(CC) $(1) -x c /dev/null -c -o /dev/null >/dev/null 2>&1 && echo $(1))
ld_ok  = $(shell printf 'int main(void){return 0;}' > .hard$$$$.c; \
                 $(CC) $(1) .hard$$$$.c -o /dev/null >/dev/null 2>&1 && echo $(1); \
                 rm -f .hard$$$$.c)

# Hardening on the shipped binary. The sanitizer targets below override CFLAGS
# wholesale, so these apply to the artifact people actually run and nobody
# rebuilds. _FORTIFY_SOURCE needs an optimised build to do anything.
HARDEN   ?= -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fPIE \
            $(call cc_ok,-fstack-clash-protection) $(call cc_ok,-fcf-protection=full)
HARDLDFLAGS ?= $(call ld_ok,-Wl$(,)-z$(,)relro) $(call ld_ok,-Wl$(,)-z$(,)now) \
               $(call ld_ok,-Wl$(,)-z$(,)noexecstack) $(call ld_ok,-pie)

CFLAGS   ?= -std=gnu11 -O2 -g -Wall -Wextra -Wno-unused-parameter

# An implicit declaration links against the wrong prototype and returns the
# wrong type at the ABI, which is a bug at runtime rather than a warning. Stop
# the build on it. Overridden, not appended, so it survives a CFLAGS= override.
#
# A pointer-type mismatch is the same kind of thing, and the opaque handles
# invite it: &handle is kw_tx ** where kw_tx * is wanted, which compiles, runs,
# and hashes the wrong bytes. A warning in a build this size is a warning
# nobody reads.
override CFLAGS += -Werror=implicit-function-declaration \
                   -Werror=incompatible-pointer-types -Werror=int-conversion

SECP_DIR = depends/secp256k1
SECP_LIB = $(SECP_DIR)/.libs/libsecp256k1.a

# argon2 runs single-threaded (parallelism handled in one process), so its
# thread abstraction is compiled out. pthread is for net/psync's parallel
# header download, nothing else.
override CFLAGS += -pthread $(HARDEN)
override LDFLAGS += $(HARDLDFLAGS)
CPPFLAGS += -Icrypto -Inet -Iwallet -Iinclude -I$(SECP_DIR)/include -Icrypto/vendor/poly1305-donna \
            -Icrypto/vendor/argon2 -DARGON2_NO_THREADS \
            -include crypto/vendor/kw_symbols.h

CORE_SRC = crypto/cpu.c crypto/rng.c crypto/mem.c crypto/log.c crypto/hex.c crypto/sha2.c crypto/sha2_hw.c crypto/ripemd160.c crypto/hmac.c crypto/siphash.c \
           crypto/pbkdf2.c crypto/slip39.c crypto/codex32.c crypto/scrypt.c crypto/scrypt_avx2.c crypto/base58.c crypto/ec.c crypto/bip32.c crypto/bip39.c \
           crypto/chainparams.c crypto/address.c crypto/bip44.c \
           crypto/chacha20.c crypto/aead.c crypto/kdf.c crypto/keystore.c crypto/tx.c crypto/psbt.c \
           net/pow.c net/auxpow.c net/powq.c net/proto.c net/msg.c net/peer.c net/socks5.c net/headers.c net/sync.c net/chainsel.c net/psync.c net/seed.c net/spv.c net/gcs.c net/cf.c net/cfstore.c \
           wallet/utxo.c wallet/fee.c wallet/journal.c wallet/change.c \
           crypto/vendor/poly1305-donna/poly1305-donna.c \
           crypto/vendor/argon2/argon2.c crypto/vendor/argon2/core.c \
           crypto/vendor/argon2/encoding.c crypto/vendor/argon2/ref.c \
           crypto/vendor/argon2/thread.c crypto/vendor/argon2/blake2/blake2b.c
CORE_OBJ = $(CORE_SRC:.c=.o)

# The boundary the threat model describes, as two archives. crypto/ and wallet/
# reference no socket call and net/ is where every one of them lives, so a
# consumer that only signs can link the first and never have the p2p parsers in
# its process at all. libkw.a stays as both together, which is what kw, kwd and
# kwui link: the split is a property of the archives, not yet of the binaries.
SIGN_SRC  = $(filter crypto/% wallet/%,$(CORE_SRC))
CHAIN_SRC = $(filter net/%,$(CORE_SRC))
SIGN_LIB  = libkoinu-sign.a
CHAIN_LIB = libkoinu-chain.a

LIB   = libkw.a

# Defined here rather than beside install: a rule's target is expanded when the
# makefile is read, so libkoinu-sign.so.$(KW_VER) named below needs this first.
KW_VER = $(shell sed -n 's/.*KW_VERSION "\([^"]*\)".*/\1/p' include/kw_version.h)
TESTS = test/test_cpu test/test_rng test/test_sha2 test/test_ripemd160 test/test_hmac test/test_siphash \
        test/test_pbkdf2 test/test_slip39 test/test_codex32 test/test_scrypt test/test_base58 test/test_ec test/test_bip32 test/test_bip39 \
        test/test_change test/test_address test/test_aead test/test_argon2 test/test_keystore test/test_tx test/test_psbt \
        test/test_pow test/test_auxpow test/test_powq test/test_proto test/test_msg test/test_peer test/test_socks5 test/test_headers test/test_sync test/test_psync \
        test/test_chainsel test/test_sighash test/test_utxo test/test_fee test/test_journal test/test_spv test/test_gcs test/test_cf test/test_cfstore

all: $(LIB) kw kwd kwui

$(LIB): $(CORE_OBJ)
	$(AR) rcs $@ $^

$(SIGN_LIB): $(SIGN_SRC:.c=.o)
	$(AR) rcs $@ $^

$(CHAIN_LIB): $(CHAIN_SRC:.c=.o)
	$(AR) rcs $@ $^

# libkoinu-chain.a depends on libkoinu-sign.a, not the other way round: link
# them in that order.
split: $(SIGN_LIB) $(CHAIN_LIB)

# ── shared libraries ────────────────────────────────────────────
# One ABI number for both halves, bumped when a published entry point changes
# shape or goes away. It is not the release version: 0.4.1 and 0.5.0 both carry
# soname 0 unless something listed in docs/abi.md moves.
KW_ABI    = 0
SIGN_SO   = libkoinu-sign.so
CHAIN_SO  = libkoinu-chain.so
SIGN_SOV  = $(SIGN_SO).$(KW_VER)
CHAIN_SOV = $(CHAIN_SO).$(KW_VER)

# A separate object set: the archives are -fPIE, and a PIE object is not a PIC
# object on every target even where the two happen to agree here.
PIC_OBJ      = $(CORE_SRC:.c=.pic.o)
SIGN_PIC_OBJ = $(SIGN_SRC:.c=.pic.o)
CHAIN_PIC_OBJ = $(CHAIN_SRC:.c=.pic.o)

%.pic.o: %.c
	$(CC) $(CFLAGS) -fPIC $(CPPFLAGS) -MMD -MP -c -o $@ $<

# The exported set is the promise: everything else, including secp256k1 and the
# vendored code this links in, is hidden. Without this the .so would re-export
# secp256k1_ec_pubkey_create, and a consumer linking its own libsecp256k1 would
# get whichever the loader reached first.
#
# Probed, not assumed: ld64 takes none of these. A .so that quietly exported
# everything would be worse than not building one.
#
# Each probe writes its own script and links a real shared object: ld_ok above
# links an executable against a named file, and --version-script=koinu.map
# probed before that file is generated fails on a linker that supports it.
VERSCRIPT_OK = $(shell printf '{ global: f; local: *; };\n' > .vs$$$$.map; \
                       printf 'int f(void){return 0;}' > .vs$$$$.c; \
                       $(CC) -shared -fPIC -Wl,--version-script=.vs$$$$.map \
                           .vs$$$$.c -o .vs$$$$.so >/dev/null 2>&1 && echo yes; \
                       rm -f .vs$$$$.map .vs$$$$.c .vs$$$$.so)
SONAME_OK    = $(shell printf 'int f(void){return 0;}' > .sn$$$$.c; \
                       $(CC) -shared -fPIC -Wl,-soname,libprobe.so.0 \
                           .sn$$$$.c -o .sn$$$$.so >/dev/null 2>&1 && echo yes; \
                       rm -f .sn$$$$.c .sn$$$$.so)
VERSCRIPT_FLAG = -Wl$(,)--version-script=koinu.map
SONAME_FLAG    = -Wl$(,)-soname$(,)$(SIGN_SO).$(KW_ABI)

koinu.map:
	printf '{ global: kw_*; KW_*; local: *; };\n' > $@

# Both or nothing. A soname with no version script exports secp256k1; a version
# script with no soname produces a library a consumer cannot be linked against
# by its interface. Darwin wants .dylib, -install_name and
# -exported_symbols_list, and that is not written: docs/abi.md says so, and
# `make shared` says so too rather than failing in the middle of the link.
SHARED_OK = $(if $(VERSCRIPT_OK),$(if $(SONAME_OK),yes,),)

# $(SECP_LIB) is linked in rather than left undefined, so the .so is complete
# on its own; the version script keeps its names off the exported list.
$(SIGN_SOV): $(SIGN_PIC_OBJ) $(SECP_LIB) koinu.map
	$(CC) $(CFLAGS) -shared $(SONAME_FLAG) $(VERSCRIPT_FLAG) \
	    -o $@ $(SIGN_PIC_OBJ) $(SECP_LIB)
	ln -sf $@ $(SIGN_SO).$(KW_ABI)
	ln -sf $(SIGN_SO).$(KW_ABI) $(SIGN_SO)

$(CHAIN_SOV): $(CHAIN_PIC_OBJ) $(SIGN_SOV) koinu.map
	$(CC) $(CFLAGS) -shared -Wl$(,)-soname$(,)$(CHAIN_SO).$(KW_ABI) $(VERSCRIPT_FLAG) \
	    -o $@ $(CHAIN_PIC_OBJ) -L. -lkoinu-sign
	ln -sf $@ $(CHAIN_SO).$(KW_ABI)
	ln -sf $(CHAIN_SO).$(KW_ABI) $(CHAIN_SO)

ifeq ($(SHARED_OK),yes)
shared: $(SIGN_SOV) $(CHAIN_SOV)
else
shared:
	@echo "shared: not built here. This linker takes no --version-script or"
	@echo "  -soname, so the exported set and the interface name cannot be"
	@echo "  pinned. See the last section of docs/abi.md."
endif

# What test/test_abi.sh consults, so it skips for the same reason rather than
# by guessing from which tools happen to be installed.
shared-ok:
	@echo '$(if $(SHARED_OK),yes,no)'


# ── install ─────────────────────────────────────────────────────
# Static archives, shared libraries, headers and pkg-config. The soname is
# meaningful now that kw_tx, kw_psbt, kw_utxoset, kw_watchset and kw_journal are
# handles: what docs/abi.md promises is checkable, and test/test_abi.sh checks
# it. The records that are still spelled out in the headers are listed there.
#
# secp256k1 is not installed. This tree builds its own from a pinned submodule,
# and putting a second libsecp256k1 on a system is how a program ends up linking
# two of them with no warning; the .pc declares it as a private requirement for
# the consumer to satisfy.
PREFIX     ?= /usr/local
DESTDIR    ?=
bindir      = $(PREFIX)/bin
libdir      = $(PREFIX)/lib
includedir  = $(PREFIX)/include
pkgconfdir  = $(libdir)/pkgconfig

SIGN_HDRS = include/koinu-sign.h include/kw_version.h crypto/log.h \
            crypto/address.h crypto/aead.h crypto/base58.h crypto/bip32.h \
            crypto/bip39.h crypto/bip44.h crypto/chacha20.h crypto/chainparams.h \
            crypto/codex32.h crypto/ec.h crypto/hex.h crypto/hmac.h crypto/kdf.h \
            crypto/keystore.h crypto/mem.h crypto/pbkdf2.h crypto/psbt.h \
            crypto/ripemd160.h crypto/rng.h crypto/scrypt.h crypto/sha2.h \
            crypto/siphash.h crypto/slip39.h crypto/tx.h \
            wallet/change.h wallet/fee.h wallet/journal.h wallet/utxo.h

# The prefix is a prerequisite, through a stamp file, because it is not one of
# the inputs make can see: two installs with different PREFIX values used to put
# the first one's paths in the second one's .pc, which test/test_abi.sh ran into
# by installing to its own prefix before test_install.sh ran.
.PHONY: force
.pcprefix: force
	@printf '%s\n' '$(PREFIX)' | cmp -s - $@ 2>/dev/null || printf '%s\n' '$(PREFIX)' > $@

%.pc: %.pc.in include/kw_version.h .pcprefix
	sed -e 's|@PREFIX@|$(PREFIX)|g' -e 's|@VERSION@|$(KW_VER)|g' $< > $@

SHARED_INSTALL = $(if $(SHARED_OK),$(SIGN_SOV) $(CHAIN_SOV),)

install: $(SIGN_LIB) $(CHAIN_LIB) $(SHARED_INSTALL) koinu-sign.pc koinu-chain.pc kw kwd kwui
	install -d $(DESTDIR)$(includedir)/koinu $(DESTDIR)$(libdir) \
	           $(DESTDIR)$(pkgconfdir) $(DESTDIR)$(bindir)
	install -m 644 $(SIGN_HDRS) $(DESTDIR)$(includedir)/koinu/
	install -m 644 $(SIGN_LIB) $(CHAIN_LIB) $(DESTDIR)$(libdir)/
ifeq ($(SHARED_OK),yes)
	install -m 755 $(SIGN_SOV) $(CHAIN_SOV) $(DESTDIR)$(libdir)/
	ln -sf $(SIGN_SOV) $(DESTDIR)$(libdir)/$(SIGN_SO).$(KW_ABI)
	ln -sf $(SIGN_SO).$(KW_ABI) $(DESTDIR)$(libdir)/$(SIGN_SO)
	ln -sf $(CHAIN_SOV) $(DESTDIR)$(libdir)/$(CHAIN_SO).$(KW_ABI)
	ln -sf $(CHAIN_SO).$(KW_ABI) $(DESTDIR)$(libdir)/$(CHAIN_SO)
endif
	install -m 644 koinu-sign.pc koinu-chain.pc $(DESTDIR)$(pkgconfdir)/
	install -m 755 kw kwd kwui $(DESTDIR)$(bindir)/

uninstall:
	rm -rf $(DESTDIR)$(includedir)/koinu
	rm -f $(DESTDIR)$(libdir)/$(SIGN_LIB) $(DESTDIR)$(libdir)/$(CHAIN_LIB)
	rm -f $(DESTDIR)$(libdir)/$(SIGN_SO)* $(DESTDIR)$(libdir)/$(CHAIN_SO)*
	rm -f $(DESTDIR)$(pkgconfdir)/koinu-sign.pc $(DESTDIR)$(pkgconfdir)/koinu-chain.pc
	rm -f $(DESTDIR)$(bindir)/kw $(DESTDIR)$(bindir)/kwd $(DESTDIR)$(bindir)/kwui

# Linked against the signing half alone, so a dependency from crypto/ or
# wallet/ onto net/ becomes a link error here.
test/signonly: test/signonly.o $(SIGN_LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/signonly.o $(SIGN_LIB) $(SECP_LIB)

# Built without the prefix header, because the point of it is to use the names
# a host would: with -include in CPPFLAGS its own definitions would be renamed
# along with the library's and the collision would be hidden.
test/hostnames: test/hostnames.c $(SIGN_LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) -Icrypto -Inet -Iwallet -Iinclude -I$(SECP_DIR)/include \
	    $(LDFLAGS) -o $@ test/hostnames.c $(SIGN_LIB) $(SECP_LIB)

kw: cli/kw.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ cli/kw.o $(LIB) $(SECP_LIB)

# resident outpoint-confirmation daemon
kwd: cli/kwd.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ cli/kwd.o $(LIB) $(SECP_LIB)

# read-only terminal view of a wallet
kwui: cli/kwui.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ cli/kwui.o $(LIB) $(SECP_LIB)

# The one submodule, built via its own autotools into a static lib. Only objects
# that reference it (ec.o, pulled in by test_ec) need it at link time.
# crypto/ec.c is the only file that includes it, and it fails to compile long
# before anything tries to link, so the missing submodule is reported here rather
# than as a header not found.
$(SECP_DIR)/include/secp256k1.h:
	@echo "$(SECP_DIR) is empty. clone with --recursive, or run:" >&2
	@echo "    git submodule update --init --recursive" >&2
	@exit 1

crypto/ec.o: $(SECP_DIR)/include/secp256k1.h

# --with-pic on a static-only build: libtool otherwise compiles the archive
# non-PIC, and a non-PIC archive cannot go into libkoinu-sign.so at all
# ("relocation R_X86_64_PC32 ... recompile with -fPIC"). This keeps one
# secp256k1 in the process, which is the whole reason it is not installed.
$(SECP_LIB): $(SECP_DIR)/include/secp256k1.h
	cd $(SECP_DIR) && ./autogen.sh && ./configure --enable-static --disable-shared \
	    --with-pic --disable-tests --disable-exhaustive-tests --disable-benchmark && $(MAKE)

test/test_cpu: test/test_cpu.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_rng: test/test_rng.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_sha2: test/test_sha2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_sha2.o test/testutil.o $(LIB)

test/test_ripemd160: test/test_ripemd160.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_ripemd160.o test/testutil.o $(LIB)

test/test_hmac: test/test_hmac.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_hmac.o test/testutil.o $(LIB)

test/test_siphash: test/test_siphash.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_siphash.o $(LIB)

test/test_pbkdf2: test/test_pbkdf2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_pbkdf2.o test/testutil.o $(LIB)

test/test_scrypt: test/test_scrypt.o test/scrypt_portable.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_scrypt.o test/scrypt_portable.o test/testutil.o $(LIB)

test/test_base58: test/test_base58.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_base58.o test/testutil.o $(LIB)

test/test_ec: test/test_ec.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_ec.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_bip32: test/test_bip32.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_bip32.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_bip39: test/test_bip39.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_bip39.o test/testutil.o $(LIB)

test/mkutxos: test/mkutxos.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/mkutxos.o $(LIB) $(SECP_LIB)

test/test_slip39: test/test_slip39.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_slip39.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_codex32: test/test_codex32.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_codex32.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_address: test/test_address.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_address.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_aead: test/test_aead.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_aead.o test/testutil.o $(LIB)

test/test_argon2: test/test_argon2.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_argon2.o test/testutil.o $(LIB)

test/test_keystore: test/test_keystore.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_keystore.o $(LIB)

test/test_tx: test/test_tx.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_tx.o $(LIB) $(SECP_LIB)

test/test_psbt: test/test_psbt.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_psbt.o $(LIB) $(SECP_LIB)

test/test_pow: test/test_pow.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_pow.o test/testutil.o $(LIB)

test/test_auxpow: test/test_auxpow.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_powq: test/test_powq.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_proto: test/test_proto.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_proto.o test/testutil.o $(LIB)

test/test_msg: test/test_msg.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_msg.o test/testutil.o $(LIB)

test/test_peer: test/test_peer.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_peer.o $(LIB)

test/test_socks5: test/test_socks5.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_socks5.o $(LIB)

test/test_headers: test/test_headers.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_headers.o test/testutil.o $(LIB)

test/test_sync: test/test_sync.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_sync.o test/testutil.o $(LIB)

test/test_psync: test/test_psync.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_psync.o $(LIB)

test/test_sighash: test/test_sighash.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB) $(SECP_LIB)

test/test_utxo: test/test_utxo.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_utxo.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_fee: test/test_fee.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_chainsel: test/test_chainsel.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_chainsel.o $(LIB) $(SECP_LIB)

test/test_change: test/test_change.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_change.o $(LIB) $(SECP_LIB)

test/test_journal: test/test_journal.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

test/test_spv: test/test_spv.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_spv.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_gcs: test/test_gcs.o test/testutil.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_gcs.o test/testutil.o $(LIB)

test/test_cf: test/test_cf.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_cf.o test/testutil.o $(LIB) $(SECP_LIB)

test/test_cfstore: test/test_cfstore.o test/testutil.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/test_cfstore.o test/testutil.o $(LIB) $(SECP_LIB)

# writes sighash vectors from a run of mainnet blocks, over p2p
mkvectors_chain: test/mkvectors_chain.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB) $(SECP_LIB)

# regenerates the block-header anchor table from a synced header cache
gen_checkpoints: test/gen_checkpoints.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

# checks the retarget rule against a KWH2 header cache, built on demand: the
# cache is 700MB for mainnet and ships nowhere
pow_chain: test/pow_chain.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIB)

net_sync: test/net_sync.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_sync.o $(LIB)

# The hand-run diagnostics, built but not run: each needs a peer, so a change
# that breaks one is otherwise invisible until someone reaches for it. net_cf
# went five commits referencing a global that had been deleted.
TOOLS = net_handshake net_tor net_sync net_spv net_cf net_multisig net_auxpow \
        net_powtail net_services pow_chain gen_checkpoints mkvectors_chain
tools: $(TOOLS)

# live SPV balance tool, built on demand, not part of `make check`
net_spv: test/net_spv.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_spv.o $(LIB) $(SECP_LIB)

# live BIP157 compact-filter balance tool, needs a peer that serves filters
net_cf: test/net_cf.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_cf.o $(LIB) $(SECP_LIB)

# live p2sh 2-of-2 co-sign harness, built on demand
net_multisig: test/net_multisig.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_multisig.o $(LIB) $(SECP_LIB)

# fetches a block and checks its merged-mining proof against a real peer
net_services: test/net_services.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_services.o $(LIB) $(SECP_LIB)

net_powtail: test/net_powtail.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_powtail.o $(LIB) $(SECP_LIB)

net_auxpow: test/net_auxpow.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_auxpow.o $(LIB) $(SECP_LIB)

# live handshake tool, built on demand, not part of `make check`
test/fakenode: test/fakenode.o $(LIB) $(SECP_LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/fakenode.o $(LIB) $(SECP_LIB)

net_handshake: test/net_handshake.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_handshake.o $(LIB)

# asks a real tor which circuit each connection got
net_tor: test/net_tor.o $(LIB)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ test/net_tor.o $(LIB)

# Fuzz targets over the parsers that read bytes a peer chose. `make fuzz` needs
# clang for libFuzzer; `make fuzz-run CORPUS=dir` replays a corpus with any
# compiler, so CI can check the known inputs without clang.
FUZZ_CC ?= clang
.PHONY: split fuzz fuzz-net fuzz-run fuzz-syntax fuzz-asan

# The stateful harnesses: a fake peer on a socketpair writing a scripted byte
# stream in fuzzer-chosen chunks, so a whole exchange is the input rather than one
# message. These found the index-offset and feefilter-shift bugs that the
# single-buffer targets cannot reach. Threads and sockets per input, so they are
# libFuzzer only and out of the replay gate, like fuzz/fuzz_wire.c.
NETFUZZ = peer sync psync pfill cfsync spvsync outpoint kwdflow
fuzz-net: $(SECP_LIB)
	@for t in $(NETFUZZ); do \
	    echo "building fz_$$t"; \
	    $(FUZZ_CC) $(FUZZFLAGS) -pthread \
	        $(CPPFLAGS) -Ifuzz/net -Itest -o fz_$$t fuzz/net/fz_$$t.c $(CORE_SRC) $(SECP_LIB) || exit 1; \
	done
# -fno-sanitize-recover, as the stateful harnesses and the sanitizer gates carry:
# without it ubsan prints and the run carries on, so a release gate that lists
# `make fuzz` would have passed over every undefined operation it found.
FUZZFLAGS = -std=gnu11 -O1 -g -fsanitize=fuzzer,address,undefined \
            -fno-sanitize-recover=undefined -fno-omit-frame-pointer

fuzz: fuzz/fuzz_parse.c fuzz/fuzz_wire.c fuzz/fuzz_shares.c $(SECP_LIB)
	$(FUZZ_CC) $(FUZZFLAGS) $(CPPFLAGS) \
	    -o fuzz_parse fuzz/fuzz_parse.c $(CORE_SRC) $(SECP_LIB)
	$(FUZZ_CC) $(FUZZFLAGS) $(CPPFLAGS) \
	    -o fuzz_shares fuzz/fuzz_shares.c $(CORE_SRC) $(SECP_LIB)
	$(FUZZ_CC) $(FUZZFLAGS) -pthread $(CPPFLAGS) \
	    -DKW_FUZZ_SOCKS5 -o fuzz_socks5 fuzz/fuzz_wire.c $(CORE_SRC) $(SECP_LIB)
	$(FUZZ_CC) $(FUZZFLAGS) -pthread $(CPPFLAGS) \
	    -DKW_FUZZ_KWD -o fuzz_kwd fuzz/fuzz_wire.c $(CORE_SRC) $(SECP_LIB)

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

check: $(TESTS) kw kwd kwui test/fakenode test/mkutxos test/signonly test/hostnames
	./test/test_cpu
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
	./test/test_slip39
	./test/test_codex32
	./test/test_address
	./test/test_aead
	./test/test_argon2
	./test/test_keystore
	./test/test_tx
	./test/test_psbt
	./test/test_pow
	./test/test_auxpow
	./test/test_powq
	./test/test_proto
	./test/test_msg
	./test/test_peer
	./test/test_socks5
	./test/test_headers
	./test/test_sync
	./test/test_chainsel
	./test/test_psync
	./test/test_sighash
	./test/test_utxo
	./test/test_fee
	./test/test_change
	./test/test_journal
	./test/test_spv
	./test/test_gcs
	./test/test_cf
	./test/test_cfstore
	./test/test_split.sh
	./test/test_abi.sh "$(CFLAGS)" "$(if $(SHARED_OK),yes,no)"
	./test/test_install.sh "$(CFLAGS)"
	./test/test_cli.sh
	./test/test_sweep.sh
	./test/test_scan.sh
	./test/test_kwui.sh
	./test/test_kwd.sh
	$(MAKE) fuzz-syntax
	$(MAKE) fuzz-run

# The fuzz harnesses are not built by anything else in the fast loop, and the
# libFuzzer ones need a compiler the gate does not require. A header change that
# broke fuzz_parse and two netfuzz targets reached a push twice because only
# make fuzz-asan compiles them. fuzz-run builds and replays the corpus with the
# ordinary compiler; this checks the rest will at least still parse.
# -Wall is not applied: the harnesses are scratch code and fuzz-net does not
# police their warnings either. The three -Werror= flags are the point.
FUZZ_SYNTAX = -std=gnu11 -Werror=implicit-function-declaration \
              -Werror=incompatible-pointer-types -Werror=int-conversion
fuzz-syntax:
	@for t in $(NETFUZZ); do \
	    $(CC) $(FUZZ_SYNTAX) -fsyntax-only -pthread -Ifuzz/net -Itest $(CPPFLAGS) \
	        fuzz/net/fz_$$t.c || exit 1; \
	done
	@$(CC) $(FUZZ_SYNTAX) -fsyntax-only $(CPPFLAGS) fuzz/fuzz_wire.c -DKW_FUZZ_SOCKS5
	@$(CC) $(FUZZ_SYNTAX) -fsyntax-only $(CPPFLAGS) fuzz/fuzz_shares.c
	@echo "fuzz-syntax ok: $(words $(NETFUZZ)) netfuzz targets and 2 wire harnesses parse"

# The tests must also pass with address and undefined-behaviour sanitizers on.
#
# $(LIB) is a shared artifact: other trees link this one in place, and a sanitized
# archive left sitting there fails their link with undefined __asan symbols. So a run
# that passes puts the tree back into release shape. A run that fails leaves
# everything, because the sanitized binaries are the point of a failure, and says so
# loudly: the object files are sanitized too, so a plain make after a failed run
# relinks them into $(LIB).
# -fno-sanitize-recover=undefined is what makes this a gate: without it ubsan
# prints its report, the process exits 0, and signed overflow or a bad shift
# passes unless somebody reads the log. UBSAN_OPTIONS says the same thing to a
# runtime that was built elsewhere.
asan: export UBSAN_OPTIONS = halt_on_error=1:print_stacktrace=1
asan:
	$(MAKE) clean
	@if $(MAKE) check CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"; then \
	    $(MAKE) clean && $(MAKE) $(LIB); \
	else \
	    echo "" >&2; \
	    echo "asan failed: this tree now holds sanitized objects and a sanitized $(LIB)." >&2; \
	    echo "They are kept so the failure can be debugged. Run make clean before" >&2; \
	    echo "building anything that links $(LIB), here or in another tree." >&2; \
	    exit 1; \
	fi

# ThreadSanitizer over the threaded code: the validator pool and the parallel
# header download. It cannot be combined with address sanitizer, so it is its own
# target, and some kernels map it somewhere it will not tolerate, hence setarch.
.PHONY: split tsan
tsan:
	$(MAKE) clean
	$(MAKE) test/test_powq test/test_psync CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra \
	    -Wno-unused-parameter -fsanitize=thread -fno-omit-frame-pointer"
	@if command -v setarch >/dev/null 2>&1; then \
	    setarch `uname -m` -R ./test/test_powq && setarch `uname -m` -R ./test/test_psync; \
	else ./test/test_powq && ./test/test_psync; fi
	@echo ""
	@echo "restoring an unsanitized $(LIB): a thread-sanitized one links against"
	@echo "nothing without the tsan runtime, so the next target would fail."
	$(MAKE) clean && $(MAKE) $(LIB)

# The fuzzers are only meaningful under the sanitizers: without them a stray
# read is silently harmless and the run reports success.
fuzz-asan: export UBSAN_OPTIONS = halt_on_error=1:print_stacktrace=1
fuzz-asan:
	$(MAKE) clean
	@if $(MAKE) fuzz-run CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer"; then \
	    $(MAKE) clean && $(MAKE) $(LIB); \
	else \
	    echo "" >&2; \
	    echo "fuzz-asan failed: sanitized objects and $(LIB) are left in place to debug." >&2; \
	    echo "Run make clean before building anything that links $(LIB)." >&2; \
	    exit 1; \
	fi

clean:
	rm -f $(LIB) $(SIGN_LIB) $(CHAIN_LIB) $(SIGN_SO)* $(CHAIN_SO)* koinu.map .pcprefix koinu-sign.pc koinu-chain.pc $(CORE_OBJ) $(PIC_OBJ) $(PIC_OBJ:.o=.d) $(TESTS) test/mkutxos test/signonly test/hostnames test/*.o test/*.d kw kwd kwui fuzz_parse fuzz_shares fuzz_socks5 fuzz_kwd fuzz_replay $(NETFUZZ:%=fz_%) cli/*.o cli/*.d crypto/*.d net/*.d wallet/*.d crypto/vendor/*/*.d crypto/vendor/argon2/blake2/*.d net_handshake net_tor net_sync net_spv net_cf net_multisig net_auxpow net_powtail net_services pow_chain gen_checkpoints mkvectors_chain test/fakenode

# Also clean the submodule build. Left out of `clean` because rebuilding
# secp256k1 is slow and rarely what you want between edits.
distclean: clean
	-cd $(SECP_DIR) && $(MAKE) distclean

.PHONY: split shared shared-ok all check asan tools clean distclean
