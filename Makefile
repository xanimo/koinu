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
CPPFLAGS += -Icrypto -Iinclude

CORE_SRC = crypto/rng.c crypto/mem.c
CORE_OBJ = $(CORE_SRC:.c=.o)

LIB   = libdogewallet.a
TESTS = test/test_rng

all: $(LIB)

$(LIB): $(CORE_OBJ)
	$(AR) rcs $@ $^

test/test_rng: test/test_rng.o $(LIB)
	$(CC) $(CFLAGS) -o $@ $< $(LIB)

%.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $<

check: $(TESTS)
	./test/test_rng

# The tests must also pass with address and undefined-behaviour sanitizers on.
asan:
	$(MAKE) clean
	$(MAKE) check CFLAGS="-std=gnu11 -O1 -g -Wall -Wextra -Wno-unused-parameter \
	    -fsanitize=address,undefined -fno-omit-frame-pointer"

clean:
	rm -f $(LIB) $(CORE_OBJ) $(TESTS) test/*.o

.PHONY: all check asan clean
