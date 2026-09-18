#!/bin/sh
# Writes the inputs of the himorime suite in bench/. Both revisions of a
# comparison run the working tree's copy (${head_root}/gen.sh).
#
#   sh gen.sh payload N FILE   a JSON payload of exactly N bytes (N >= 64);
#                              deterministic, the same N always writes the
#                              same bytes
#   sh gen.sh keys JOSE DIR    one key of each type, written by the jose
#                              binary JOSE: ec.jwk and other-ec.jwk (P-256),
#                              rsa.jwk (2048 bits), okp.jwk (Ed25519) and
#                              oct.jwk (256 bits). Keys are random; their cost
#                              depends on the type and size only.
set -eu

case "$1" in
payload)
	mkdir -p "$(dirname "$3")"
	awk -v n="$2" 'BEGIN {
		head = "{\"sub\":\"alice\",\"iss\":\"https://issuer.example.com\",\"data\":\""
		tail = "\"}\n"
		fill = n - length(head) - length(tail)
		if (fill < 0) {
			print "gen.sh: payload must be at least " (length(head) + length(tail)) " bytes" > "/dev/stderr"
			exit 2
		}
		line = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_"
		printf "%s", head
		while (fill >= length(line)) {
			printf "%s", line
			fill -= length(line)
		}
		printf "%s%s", substr(line, 1, fill), tail
	}' > "$3"
	;;
keys)
	mkdir -p "$3"
	"$2" jwk generate --type EC --curve P-256 --output "$3/ec.jwk"
	"$2" jwk generate --type EC --curve P-256 --output "$3/other-ec.jwk"
	"$2" jwk generate --type RSA --size 2048 --output "$3/rsa.jwk"
	"$2" jwk generate --type OKP --curve Ed25519 --output "$3/okp.jwk"
	"$2" jwk generate --type oct --size 256 --output "$3/oct.jwk"
	;;
*)
	echo "gen.sh: unknown kind $1" >&2
	exit 2
	;;
esac
