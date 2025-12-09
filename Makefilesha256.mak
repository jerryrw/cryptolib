# Makefile for AES-256 Implementation
# Compatible with macOS ARM (Apple Silicon)

# Compiler settings
CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = 

# Source files
SOURCES = aes256.c
HEADERS = aes256.h
OBJECTS = aes256.o

# Test and example executables
TEST_EXEC = test_vectors
EXAMPLE_EXEC = exampleaes

# Default target
all: $(TEST_EXEC) $(EXAMPLE_EXEC)

# Compile object files
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# Build test vectors executable
$(TEST_EXEC): test_vectors.c $(OBJECTS)
	$(CC) $(CFLAGS) test_vectors.c $(OBJECTS) -o $(TEST_EXEC) $(LDFLAGS)

# Build examples executable
$(EXAMPLE_EXEC): exampleaes.c $(OBJECTS)
	$(CC) $(CFLAGS) exampleaes.c $(OBJECTS) -o $(EXAMPLE_EXEC) $(LDFLAGS)

# Run tests
test: $(TEST_EXEC)
	./$(TEST_EXEC)

# Run examples
run: $(EXAMPLE_EXEC)
	./$(EXAMPLE_EXEC)

# Clean build artifacts
clean:
	rm -f $(OBJECTS) $(TEST_EXEC) $(EXAMPLE_EXEC)
	rm -f *.bin

# Install (optional - copies to /usr/local)
install: $(HEADERS) $(OBJECTS)
	@echo "Installing AES-256 library..."
	@mkdir -p /usr/local/include
	@mkdir -p /usr/local/lib
	@cp $(HEADERS) /usr/local/include/
	@ar rcs libaes256.a $(OBJECTS)
	@cp libaes256.a /usr/local/lib/
	@echo "Installation complete!"

# Uninstall
uninstall:
	@echo "Uninstalling AES-256 library..."
	@rm -f /usr/local/include/aes256.h
	@rm -f /usr/local/lib/libaes256.a
	@echo "Uninstall complete!"

# Check for memory leaks (requires valgrind on Intel Mac or use leaks on ARM)
memcheck: $(TEST_EXEC)
	@echo "Running memory check (using leaks command for macOS ARM)..."
	@leaks -atExit -- ./$(TEST_EXEC)

# Benchmark (runs examples with timing)
benchmark: $(EXAMPLE_EXEC)
	@echo "Running performance benchmark..."
	@time ./$(EXAMPLE_EXEC)

# Help
help:
	@echo "AES-256 Implementation Makefile"
	@echo "==============================="
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build all executables (default)"
	@echo "  test       - Build and run test vectors"
	@echo "  run        - Build and run examples"
	@echo "  clean      - Remove build artifacts"
	@echo "  install    - Install library to /usr/local (requires sudo)"
	@echo "  uninstall  - Remove installed library"
	@echo "  memcheck   - Check for memory leaks"
	@echo "  benchmark  - Run performance benchmark"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Examples:"
	@echo "  make              # Build everything"
	@echo "  make test         # Run tests"
	@echo "  make run          # Run examples"
	@echo "  make clean        # Clean up"

.PHONY: all test run clean install uninstall memcheck benchmark help