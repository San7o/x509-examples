# SPDX-License-Identifier: MIT
# Author:  Giovanni Santini
# Mail:    giovanni.santini@proton.me
# Github:  @San7o

#
# C
#
OUT     = generate
OBJ     = generate.o
CFLAGS  = -Wall -Wextra -Wpedantic -Werror -std=c99
LDFLAGS = -lssl -lcrypto
CC     ?= gcc

#
# Go
#
GO_MAIN       = generate.go
GO_MAIN_ECDSA = generate_ecdsa.go

all: main

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -o $(OUT)

run: $(OUT)
	chmod +x $(OUT)
	./$(OUT)

clean:
	rm -f public.pem private.key cert.crt $(OUT) $(OBJ)

info:
	openssl x509 -in cert.crt -noout -text

go: $(GO_MAIN)
	go run $(GO_MAIN)

go-ecdsa: $(GO_MAIN_ECDSA)
	go run $(GO_MAIN_ECDSA)

.PHONY: clean info run

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

