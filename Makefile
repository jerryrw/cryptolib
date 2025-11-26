.PHONY: all nist clean sha3 sha256 md5 example test test_nist_md5 test_nist_sha256 test_nist_sha3

all: sha3 sha256 md5 aes256 example nist

# Test programs (NIST-like tests for MD5, SHA256, SHA3)
nist: test_nist_md5 test_nist_sha256 test_nist_sha3
	./test_nist_md5 || exit 2
	./test_nist_sha256 || exit 2
	./test_nist_sha3 || exit 2

# Build rules for tests
test_nist_md5: test_nist_md5.o md5.o
	gcc test_nist_md5.o md5.o -o test_nist_md5 -Wall -O3

test_nist_sha256: test_nist_sha256.o sha256.o
	gcc test_nist_sha256.o sha256.o -o test_nist_sha256 -Wall -O3

test_nist_sha3: test_nist_sha3.o sha3.o
	gcc test_nist_sha3.o sha3.o -o test_nist_sha3 -Wall -O3

test_nist_md5.o: test_nist_md5.c
	gcc -std=c99 -O3 -Wall -c test_nist_md5.c -o test_nist_md5.o

test_nist_sha256.o: test_nist_sha256.c
	gcc -std=c99 -O3 -Wall -c test_nist_sha256.c -o test_nist_sha256.o

test_nist_sha3.o: test_nist_sha3.c
	gcc -std=c99 -O3 -Wall -c test_nist_sha3.c -o test_nist_sha3.o


example: example.o
	gcc example.o -o example -Wall -O3 -L./ -lsha3
#	gcc example.o -o example -Wall -O2

example.o: example.c
	gcc -c -O3 -Wall -std=c99 -O3 -march=native -mtune=native example.c -o example.o

sha3: sha3.o
# Linux shared library - uncomment this next line for Linux leave comented for macOS
#	gcc -D_GNU_SOURCE arcfour.o -o arcfour.so -fPIC -shared -ldl

# macOS dynamic library- uncoment this next line for macOS leave commented for Linux
	gcc -dynamiclib -exported_symbols_list libsha3.exp sha3.o -o libsha3.dylib 

sha256: sha256.o
# Linux shared library - uncomment this next line for Linux leave comented for macOS
#	gcc -D_GNU_SOURCE sha256.o -o sha256.so -fPIC -shared -ldl

# macOS dynamic library- uncoment this next line for macOS leave commented for Linux
	gcc -dynamiclib -exported_symbols_list libsha256.exp sha256.o -o libsha256.dylib

md5: md5.o
# Linux shared library - uncomment this next line for Linux leave comented for macOS
#	gcc -D_GNU_SOURCE md5.o -o md5.so -fPIC -shared -ldl	
# macOS dynamic library- uncoment this next line for macOS leave commented for Linux
	gcc -dynamiclib -exported_symbols_list libmd5.exp md5.o -o libmd5.dylib

aes256: aes256.o
# Linux shared library - uncomment this next line for Linux leave comented for macOS
#	gcc -D_GNU_SOURCE aes256.o -o aes256.so -fPIC -shared -ldl	
# macOS dynamic library- uncoment this next line for macOS leave commented for Linux
	gcc -dynamiclib -exported_symbols_list libaes256.exp aes256.o -o libaes256.dylib
	
sha3.o: sha3_256.c
	gcc -std=c99 -O3 -march=native -mtune=native -c sha3_256.c -o sha3.o 

sha256.o: sha256.c
	gcc -std=c99 -O3 -march=native -mtune=native -c sha256.c -o sha256.o

md5.o: md5.c
	gcc -std=c99 -O3 -march=native -mtune=native -c md5.c -o md5.o

aes256.o: aes256.c
	gcc -std=c99 -O3 -march=native -mtune=native -c aes256.c -o aes256.o

clean:
	rm -f *.o *.so example *.dylib test_nist_md5 test_nist_sha256 test_nist_sha3 test_vectors

#gcc -std=c99 -O3 -march=native -mtune=native -c sha3grok.c -o sha3.o 