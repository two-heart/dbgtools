# written compiler specific to match offsets
# do not reexecute this as different versions might
# change offsets


all: basic types asan traceheap

basic:
	gcc -o ../bin/basic basic.c

types:
	gcc -o ../bin/types types.c

asan:
	clang -o ../bin/asan -fsanitize=address -Wno-array-bounds asan.c

traceheap:
	gcc -o ../bin/traceheap traceheap.c
