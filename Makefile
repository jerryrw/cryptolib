# Beginner's build map:
#   .c + included .h -> compiler (-c) -> obj/*.o -> linker -> library/executable
# A rule is "target: prerequisites" followed by a TAB-indented shell recipe.
# Make rebuilds a file when a prerequisite is newer; .PHONY names always run.
# Variables use $(NAME). := expands now; = expands when used; ?= supplies a
# default only if unset. Command-line assignments such as CC=clang override =.
#
# Automatic recipe variables: $@ is the target, $< the first prerequisite,
# $^ all normal prerequisites, and $* the stem matched by a % pattern.
# $$ passes a literal dollar sign through Make to the shell or linker.
# -include below loads compiler-generated header dependencies; its leading -
# allows the very first build to work before any .d files exist.

OS := $(shell uname -s)
CC = cc
# -I searches include/ for quoted headers; CFLAGS controls C compilation.
# -std=c11 selects C11, -Wall enables warnings, and -O3 enables optimization.
# The native flags target this machine CPU; override CFLAGS for portability.
CPPFLAGS += -Iinclude
CFLAGS = -std=c11 -Wall -O3 -march=native -mtune=native

# Derive filenames from lists rather than repeating one recipe per algorithm.
# addprefix/addsuffix build lists; filter/filter-out select names from them.
ALGORITHMS := sha3 sha256 md5 aes256 arcfour
TESTS := $(addprefix test_nist_,$(ALGORITHMS)) test_regressions test_examples test_file_failures
OBJDIR := obj
OBJECTS := $(addprefix $(OBJDIR)/,$(addsuffix .o,$(ALGORITHMS) $(TESTS) example example-aes example_general_driver))

# Select platform-specific shared-library and runtime-search settings.
# Runtime search paths let executables find libraries beside themselves.
# $* must remain unexpanded until a particular library recipe is executing.
ifeq ($(OS),Darwin)
LIBEXT := dylib
SHARED_FLAGS = -dynamiclib -Wl,-install_name,@rpath/$(notdir $@) -exported_symbols_list symbols/lib$*.exp
RPATH := -Wl,-rpath,@loader_path
else ifeq ($(OS),Linux)
LIBEXT := so
SHARED_FLAGS := -shared
RPATH := -Wl,-rpath,'$$ORIGIN'
else
$(error Unsupported operating system: $(OS))
endif

LIBRARIES := $(addprefix lib,$(addsuffix .$(LIBEXT),$(ALGORITHMS)))

.PHONY: all clean test test_headers $(ALGORITHMS)
# The first target is the default when running just `make`.
all: $(LIBRARIES) example test

# Preserve convenient targets such as `make aes256`.
$(ALGORITHMS): %: lib%.$(LIBEXT)

# A pattern rule: libaes256.dylib, for example, needs obj/aes256.o.
# LDFLAGS/LDLIBS are conventional override hooks for link options/libraries.
lib%.$(LIBEXT): $(OBJDIR)/%.o
	$(CC) $(LDFLAGS) $(SHARED_FLAGS) $< -o $@ $(LDLIBS)

ifeq ($(OS),Darwin)
$(LIBRARIES): lib%.$(LIBEXT): symbols/lib%.exp
endif

# -fPIC produces position-independent code for a shared library.
# -MMD -MP writes .d header dependencies with harmless fallback header rules.
# A prerequisite after | is order-only: create obj/ first, but do not rebuild
# every object just because the directory timestamp changed.
$(OBJDIR)/sha3.o: src/sha3_256.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -MMD -MP -c $< -o $@

# A static pattern rule applies the src/%.c mapping to this explicit list.
# sha3 has its own rule above because its source is named sha3_256.c.
$(filter-out $(OBJDIR)/sha3.o,$(addprefix $(OBJDIR)/,$(addsuffix .o,$(ALGORITHMS) example example-aes))): $(OBJDIR)/%.o: src/%.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -fPIC -MMD -MP -c $< -o $@

$(addprefix $(OBJDIR)/,$(addsuffix .o,$(TESTS) example_general_driver)): $(OBJDIR)/%.o: tests/%.c | $(OBJDIR)
	$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

# Link each vector test to its matching shared library. -L. searches the
# project root; -laes256 means a library named libaes256 with the platform suffix.
$(filter test_nist_%,$(TESTS)): test_nist_%: $(OBJDIR)/test_nist_%.o lib%.$(LIBEXT)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -l$* $(RPATH) $(LDLIBS)

test_regressions: $(addprefix $(OBJDIR)/,test_regressions.o aes256.o arcfour.o sha3.o)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

test_examples: $(addprefix $(OBJDIR)/,test_examples.o example_general_driver.o aes256.o arcfour.o sha3.o sha256.o md5.o)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

# This test includes aes256.c with fault-injection wrappers.
test_file_failures: $(OBJDIR)/test_file_failures.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ $(LDLIBS)

example: $(OBJDIR)/example.o $(LIBRARIES)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. $(addprefix -l,$(ALGORITHMS)) $(RPATH) $(LDLIBS)

example-aes: $(OBJDIR)/example-aes.o libaes256.$(LIBEXT)
	$(CC) $(CFLAGS) $(LDFLAGS) $< -o $@ -L. -laes256 $(RPATH) $(LDLIBS)

# Run tests sequentially after building them (even when using make -j).
# set -e stops the shell loop on failure; @ hides only the recipe text.
test: $(TESTS) test_headers
	@set -e; for test in $(TESTS); do ./$$test; done

# Compile a tiny input that includes only one header, with no object output.
# This catches headers that accidentally rely on another header being included
# first. ${header#include/} is shell prefix removal, not a Make variable.
test_headers:
	@for header in include/*.h; do printf '#include "%s"\n' "$${header#include/}" | $(CC) $(CPPFLAGS) $(CFLAGS) -x c -fsyntax-only - || exit 1; done

$(OBJDIR):
	mkdir -p $@

# Remove known generated files only. Keep the fuzz corpus/crash artifacts
# so interesting inputs are not lost during normal cleanup.
clean:
	rm -f $(OBJECTS) $(OBJECTS:.o=.d) $(LIBRARIES) $(TESTS) example example-aes $(SAN_PROGRAMS) $(FUZZ_DIR)/aes_decrypt $(FUZZ_DIR)/seed

-include $(OBJECTS:.o=.d)

.PHONY: check sanitize fuzz fuzz-smoke
check: test example example-aes
	./example
	./example-aes

# Separate binaries keep sanitizer flags out of ordinary builds.
LIB_SOURCES := src/aes256.c src/arcfour.c src/md5.c src/sha256.c src/sha3_256.c
HEADERS := $(wildcard include/*.h)
SAN_DIR := $(OBJDIR)/sanitize
# ASan detects invalid memory access; UBSan checks undefined C behavior.
# -g and frame pointers aid diagnostics; non-recovering failures stop the test.
SAN_FLAGS := -std=c11 -Wall -Wextra -g -O1 -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all
SAN_PROGRAMS := $(addprefix $(SAN_DIR)/,$(TESTS) example example-aes)

$(SAN_DIR):
	mkdir -p $@

# Some tests intentionally include a .c implementation to substitute calls.
# Their special recipes avoid linking a second copy of the same functions.
$(SAN_DIR)/test_examples: tests/test_examples.c tests/example_general_driver.c src/example.c src/example-aes.c $(LIB_SOURCES) $(HEADERS) | $(SAN_DIR)
	$(CC) $(CPPFLAGS) $(SAN_FLAGS) tests/test_examples.c tests/example_general_driver.c $(LIB_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(SAN_DIR)/test_file_failures: tests/test_file_failures.c src/aes256.c $(HEADERS) | $(SAN_DIR)
	$(CC) $(CPPFLAGS) $(SAN_FLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(SAN_DIR)/test_%: tests/test_%.c $(LIB_SOURCES) $(HEADERS) | $(SAN_DIR)
	$(CC) $(CPPFLAGS) $(SAN_FLAGS) $< $(LIB_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(SAN_DIR)/example: src/example.c $(LIB_SOURCES) $(HEADERS) | $(SAN_DIR)
	$(CC) $(CPPFLAGS) $(SAN_FLAGS) $< $(LIB_SOURCES) -o $@ $(LDFLAGS) $(LDLIBS)

$(SAN_DIR)/example-aes: src/example-aes.c src/aes256.c $(HEADERS) | $(SAN_DIR)
	$(CC) $(CPPFLAGS) $(SAN_FLAGS) $< src/aes256.c -o $@ $(LDFLAGS) $(LDLIBS)

sanitize: $(SAN_PROGRAMS) test_headers
	@set -e; for program in $(SAN_PROGRAMS); do ./$$program; done

# Requires a Clang distribution that includes libFuzzer.
FUZZ_CC ?= clang
FUZZ_DIR := $(OBJDIR)/fuzz
FUZZ_FLAGS := -std=c11 -g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all
FUZZ_RUNS ?= 2000

$(FUZZ_DIR) $(FUZZ_DIR)/corpus:
	mkdir -p $@

$(FUZZ_DIR)/aes_decrypt: tests/fuzz_aes_decrypt.c src/aes256.c $(HEADERS) | $(FUZZ_DIR)
	$(FUZZ_CC) $(CPPFLAGS) $(FUZZ_FLAGS) tests/fuzz_aes_decrypt.c src/aes256.c -o $@

$(FUZZ_DIR)/seed: tests/fuzz_seed.c src/aes256.c $(HEADERS) | $(FUZZ_DIR)
	$(CC) $(CPPFLAGS) -std=c11 -O1 tests/fuzz_seed.c src/aes256.c -o $@

# The seed helper creates valid ciphertext inputs before mutations begin.
# libFuzzer provides main, mutates inputs, and keeps interesting corpus entries.
fuzz: $(FUZZ_DIR)/aes_decrypt $(FUZZ_DIR)/seed $(FUZZ_DIR)/corpus
	$(FUZZ_DIR)/seed $(FUZZ_DIR)/corpus

fuzz-smoke: fuzz
	$(FUZZ_DIR)/aes_decrypt -runs=$(FUZZ_RUNS) -max_len=4096 -artifact_prefix=$(FUZZ_DIR)/ $(FUZZ_DIR)/corpus
