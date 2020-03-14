#
# Makefile for mars2muc
#
# Copyright (c) 2019 Hirokuni Yano
#
# Released under the MIT license.
# see https://opensource.org/licenses/MIT
#
CC	= gcc
CFLAGS	= -g -Wall -Wextra

all: mars2muc

clean:
	rm -f mars2muc mars2muc.o

mars2muc.o: mars2muc.c

mars2muc: mars2muc.o
	$(CC) mars2muc.o -o mars2muc
