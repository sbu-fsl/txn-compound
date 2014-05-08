main: dix

AIO_FLAGS = -laio -L/usr/lib

dix: dix.c
	gcc -o dix dix.c $(AIO_FLAGS)

dixio_test: dixio.c dixio.h dixio_test.c
	gcc -o $@ $+ $(AIO_FLAGS)
