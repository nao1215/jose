#!/usr/bin/env python3
"""Generate atago matrix specs for jose's crypto contracts (JWE/JWS/JWK).

Emits three *.atago.yaml files exercising the full, real compatibility matrix as
end-to-end round-trip contracts. Shell-free and portable (Linux/macOS/Windows):
input is a fixture, keys are generated with jose or fixtured (for oct sizes jose
will not generate), output goes through jose's own --output.
"""
import os

OUT = os.environ.get("JOSE_E2E_DIR", "/home/nao/ghq/github.com/nao1215/jose/e2e/atago")
PAYLOAD = '{"sub":"alice"}'

# 128- and 192-bit oct keys jose cannot generate (min oct size is 256) but can
# still use when imported. Fixed material keeps the specs deterministic.
K128 = '{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODw"}'      # 16 bytes
K192 = '{"kty":"oct","k":"AAECAwQFBgcICQoLDA0ODxAREhMUFRYX"}'  # 24 bytes

CENCS = ["A128CBC-HS256", "A128GCM", "A192CBC-HS384", "A192GCM", "A256CBC-HS512", "A256GCM"]


def header(name):
    return f'''version: "1"

suite:
  name: {name}

scenarios:
'''


# ---------------------------------------------------------------------------
# JWE: key-encryption x content-encryption round trips, grouped by the key the
# family needs. Each group is a matrix scenario (one concrete scenario per row).
# ---------------------------------------------------------------------------

def jwe_family(title, keyencs, keygen_steps, compress=False):
    """Return YAML for one matrix scenario covering keyencs x CENCS."""
    z = " --compress" if compress else ""
    label = "compressed " if compress else ""
    rows = []
    for ke in keyencs:
        for c in CENCS:
            rows.append(f"      - {{ke: {yaml_scalar(ke)}, cenc: {c}}}")
    rows = "\n".join(rows)
    steps = keygen_steps
    return f'''  - name: "{label}jwe ${{ke}} + ${{cenc}} round-trips ({title})"
    matrix:
{rows}
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{steps}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption ${{ke}} --content-encryption ${{cenc}}{z} --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk --key-encryption ${{ke}} c.jwe
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
'''


def yaml_scalar(s):
    # Single-quoted YAML scalar: safe for values that themselves contain double
    # quotes (e.g. '"kty"'); embedded single quotes are doubled per YAML.
    return "'" + s.replace("'", "''") + "'"


GEN_RSA = "      - run:\n          command: jose jwk generate --type RSA --size 2048 --output key.jwk"
GEN_EC = "      - run:\n          command: jose jwk generate --type EC --curve P-256 --output key.jwk"
GEN_OCT256 = "      - run:\n          command: jose jwk generate --type oct --size 256 --output key.jwk"
FIX_K128 = f"      - fixture:\n          file: key.jwk\n          content: '{K128}'"
FIX_K192 = f"      - fixture:\n          file: key.jwk\n          content: '{K192}'"


def gen_jwe():
    out = [header("jose jwe algorithm matrix")]
    families = [
        ("RSA key", ["RSA-OAEP", "RSA-OAEP-256", "RSA1_5"], GEN_RSA),
        ("EC key", ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"], GEN_EC),
        ("256-bit oct key", ["A256KW", "A256GCMKW", "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"], GEN_OCT256),
        ("128-bit oct key", ["A128KW", "A128GCMKW"], FIX_K128),
        ("192-bit oct key", ["A192KW", "A192GCMKW"], FIX_K192),
    ]
    for title, kes, keygen in families:
        out.append(jwe_family(title, kes, keygen, compress=False))
    for title, kes, keygen in families:
        out.append(jwe_family(title, kes, keygen, compress=True))

    # dir: the oct key size must equal the content-encryption CEK size.
    dir_rows = [
        ("A128CBC-HS256", GEN_OCT256, "256"),
        ("A256GCM", GEN_OCT256, "256"),
        ("A192CBC-HS384", "      - run:\n          command: jose jwk generate --type oct --size 384 --output key.jwk", "384"),
        ("A256CBC-HS512", "      - run:\n          command: jose jwk generate --type oct --size 512 --output key.jwk", "512"),
        ("A128GCM", FIX_K128, "128"),
        ("A192GCM", FIX_K192, "192"),
    ]
    for cenc, keygen, size in dir_rows:
        out.append(f'''  - name: "jwe dir + {cenc} round-trips ({size}-bit key)"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption dir --content-encryption {cenc} --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk --key-encryption dir c.jwe
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')

    # Header-inferred decrypt: omit --key-encryption on decrypt; jose reads alg
    # from the JWE header. One representative content-encryption per keyenc.
    inferred = [
        ("RSA-OAEP", GEN_RSA, "A256GCM"),
        ("RSA-OAEP-256", GEN_RSA, "A256GCM"),
        ("RSA1_5", GEN_RSA, "A128CBC-HS256"),
        ("ECDH-ES", GEN_EC, "A256GCM"),
        ("ECDH-ES+A128KW", GEN_EC, "A128GCM"),
        ("ECDH-ES+A192KW", GEN_EC, "A192GCM"),
        ("ECDH-ES+A256KW", GEN_EC, "A256GCM"),
        ("A256KW", GEN_OCT256, "A256GCM"),
        ("A256GCMKW", GEN_OCT256, "A256GCM"),
        ("PBES2-HS256+A128KW", GEN_OCT256, "A128GCM"),
        ("PBES2-HS384+A192KW", GEN_OCT256, "A192GCM"),
        ("PBES2-HS512+A256KW", GEN_OCT256, "A256GCM"),
        ("A128KW", FIX_K128, "A128GCM"),
        ("A128GCMKW", FIX_K128, "A128GCM"),
        ("A192KW", FIX_K192, "A192GCM"),
        ("A192GCMKW", FIX_K192, "A192GCM"),
    ]
    for ke, keygen, cenc in inferred:
        out.append(f'''  - name: "jwe {ke} decrypts with the algorithm read from the header"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption {ke} --content-encryption {cenc} --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk c.jwe
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')

    # dir with compression, per content-encryption CEK size.
    for cenc, keygen, size in dir_rows:
        out.append(f'''  - name: "compressed jwe dir + {cenc} round-trips ({size}-bit key)"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption dir --content-encryption {cenc} --compress --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk --key-encryption dir c.jwe
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')

    # Wrong-key negatives: a ciphertext must not decrypt under a freshly minted
    # key of the same type.
    wrongkey = [
        ("RSA-OAEP", GEN_RSA, "jose jwk generate --type RSA --size 2048 --output other.jwk"),
        ("ECDH-ES", GEN_EC, "jose jwk generate --type EC --curve P-256 --output other.jwk"),
        ("A256KW", GEN_OCT256, "jose jwk generate --type oct --size 256 --output other.jwk"),
    ]
    for ke, keygen, othergen in wrongkey:
        out.append(f'''  - name: "jwe {ke} does not decrypt under a different key"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption {ke} --content-encryption A256GCM --output c.jwe payload.json
      - run:
          command: {othergen}
      - run:
          command: jose jwe decrypt --key other.jwk --key-encryption {ke} c.jwe
      - assert:
          exit_code: {{ not: 0 }}
          stderr:
            contains: "decrypt"
''')

    # Decrypt reading the ciphertext from piped stdin, per key family.
    stdin_families = [
        ("RSA-OAEP", GEN_RSA),
        ("ECDH-ES", GEN_EC),
        ("A256KW", GEN_OCT256),
        ("A128KW", FIX_K128),
        ("A192KW", FIX_K192),
    ]
    for ke, keygen in stdin_families:
        out.append(f'''  - name: "jwe {ke} decrypts a ciphertext piped through stdin"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption {ke} --content-encryption A256GCM --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk --key-encryption {ke}
          stdin:
            file: c.jwe
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')

    # State-change contracts: encrypt writes exactly the ciphertext, decrypt
    # writes exactly the plaintext, and neither pollutes HOME.
    io_families = [
        ("RSA-OAEP", GEN_RSA),
        ("ECDH-ES", GEN_EC),
        ("A256KW", GEN_OCT256),
    ]
    for ke, keygen in io_families:
        out.append(f'''  - name: "jwe {ke} encrypt writes only the ciphertext file"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          sandbox_home: true
          command: jose jwe encrypt --key key.jwk --key-encryption {ke} --content-encryption A256GCM --output c.jwe payload.json
      - assert:
          exit_code: 0
          changes:
            created: [c.jwe]
            modified: []
            deleted: []
''')
        out.append(f'''  - name: "jwe {ke} decrypt writes the plaintext to a file"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{keygen}
      - run:
          command: jose jwe encrypt --key key.jwk --key-encryption {ke} --content-encryption A256GCM --output c.jwe payload.json
      - run:
          command: jose jwe decrypt --key key.jwk --key-encryption {ke} --output out.txt c.jwe
      - assert:
          exit_code: 0
          file:
            path: out.txt
            contains: '{PAYLOAD}'
''')

    with open(os.path.join(OUT, "jwe_matrix.atago.yaml"), "w") as f:
        f.write("# GENERATED by scripts/gen_e2e.py — do not edit by hand.\n"
                "# jose jwe: every valid (key-encryption, content-encryption) pair, encrypted\n"
                "# and decrypted back, plain and --compress, plus header-inferred decrypt.\n"
                "# Shell-free/portable. Regenerate: python3 scripts/gen_e2e.py\n"
                + "".join(out))


# ---------------------------------------------------------------------------
# JWS: signature-algorithm matrix, each via file / stdin / "-" / inline arg /
# parse, plus a wrong-key negative.
# ---------------------------------------------------------------------------

# alg -> (keygen command flags, key file)
JWS_ALGS = [
    ("ES256", "--type EC --curve P-256"),
    ("ES384", "--type EC --curve P-384"),
    ("ES512", "--type EC --curve P-521"),
    ("RS256", "--type RSA --size 2048"),
    ("RS384", "--type RSA --size 2048"),
    ("RS512", "--type RSA --size 2048"),
    ("PS256", "--type RSA --size 2048"),
    ("PS384", "--type RSA --size 2048"),
    ("PS512", "--type RSA --size 2048"),
    ("HS256", "--type oct --size 256"),
    ("HS384", "--type oct --size 384"),
    ("HS512", "--type oct --size 512"),
    ("EdDSA", "--type OKP --curve Ed25519"),
]


def gen_jws():
    out = [header("jose jws algorithm matrix")]
    for alg, flags in JWS_ALGS:
        gen = f"      - run:\n          command: jose jwk generate {flags} --output key.jwk"
        gen2 = f"      - run:\n          command: jose jwk generate {flags} --output other.jwk"
        # round trip from a file
        out.append(f'''  - name: "jws {alg} signs and verifies from a file"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key key.jwk token.jws
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')
        # sign from piped stdin, verify from file
        out.append(f'''  - name: "jws {alg} signs from piped stdin"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws
          stdin:
            file: payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key key.jwk token.jws
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')
        # verify from piped stdin
        out.append(f'''  - name: "jws {alg} verifies from piped stdin"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key key.jwk
          stdin:
            file: token.jws
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')
        # inline token argument via store
        out.append(f'''  - name: "jws {alg} verifies an inline token argument"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk payload.json
      - store:
          name: token
          from:
            stdout:
              matches: "[A-Za-z0-9_-]+\\\\.[A-Za-z0-9_-]+\\\\.[A-Za-z0-9_-]+"
      - run:
          command: jose jws verify --algorithm {alg} --key key.jwk ${{token}}
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')
        # parse prints the payload
        out.append(f'''  - name: "jws {alg} parse prints the payload"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws parse token.jws
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')
        # wrong key fails
        out.append(f'''  - name: "jws {alg} verify fails with the wrong key"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
{gen2}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key other.jwk token.jws
      - assert:
          exit_code: {{ not: 0 }}
          stderr:
            contains: "verify"
''')
        # sign writes only the token file, and never pollutes HOME
        out.append(f'''  - name: "jws {alg} sign writes only the token file"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          sandbox_home: true
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - assert:
          exit_code: 0
          changes:
            created: [token.jws]
            modified: []
            deleted: []
''')
        # parse --all shows the algorithm in the header
        out.append(f'''  - name: "jws {alg} parse --all shows the protected header"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws parse --all token.jws
      - assert:
          exit_code: 0
          stdout:
            contains:
              - "Payload:"
              - "Signature 0:"
              - "{alg}"
''')
        # verify writes the payload to a file with --output, and touches nothing else
        out.append(f'''  - name: "jws {alg} verify writes the payload to a file"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
{gen}
      - run:
          command: jose jws sign --algorithm {alg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key key.jwk --output out.txt token.jws
      - assert:
          exit_code: 0
          file:
            path: out.txt
            contains: '{PAYLOAD}'
''')

    # PEM round trips for the key types that have an X.509 PEM form (EC, RSA, OKP
    # Ed25519); oct/HS keys are symmetric and json-only.
    pem_algs = [
        ("ES256", "--type EC --curve P-256"),
        ("ES384", "--type EC --curve P-384"),
        ("ES512", "--type EC --curve P-521"),
        ("RS256", "--type RSA --size 2048"),
        ("RS384", "--type RSA --size 2048"),
        ("RS512", "--type RSA --size 2048"),
        ("PS256", "--type RSA --size 2048"),
        ("PS384", "--type RSA --size 2048"),
        ("PS512", "--type RSA --size 2048"),
        ("EdDSA", "--type OKP --curve Ed25519"),
    ]
    for alg, flags in pem_algs:
        out.append(f'''  - name: "jws {alg} round-trips with a PEM key"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
      - run:
          command: jose jwk generate {flags} --output-format pem --output key.pem
      - run:
          command: jose jws sign --algorithm {alg} --key key.pem --key-format pem --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {alg} --key key.pem --key-format pem token.jws
      - assert:
          exit_code: 0
          stdout:
            equals: '{PAYLOAD}'
''')

    # Algorithm-mismatch negatives: a token signed with one algorithm must not
    # verify when a different algorithm is demanded, even with the same key.
    mismatches = [
        ("ES256", "ES384", "--type EC --curve P-256"),
        ("ES384", "ES512", "--type EC --curve P-384"),
        ("RS256", "RS384", "--type RSA --size 2048"),
        ("RS256", "PS256", "--type RSA --size 2048"),
        ("PS256", "PS384", "--type RSA --size 2048"),
        ("HS256", "HS384", "--type oct --size 256"),
    ]
    for signalg, verifyalg, flags in mismatches:
        out.append(f'''  - name: "jws {signalg} token does not verify as {verifyalg}"
    steps:
      - fixture:
          file: payload.json
          content: '{PAYLOAD}'
      - run:
          command: jose jwk generate {flags} --output key.jwk
      - run:
          command: jose jws sign --algorithm {signalg} --key key.jwk --output token.jws payload.json
      - run:
          command: jose jws verify --algorithm {verifyalg} --key key.jwk token.jws
      - assert:
          exit_code: {{ not: 0 }}
          stderr:
            contains: "verify"
''')
    with open(os.path.join(OUT, "jws_matrix.atago.yaml"), "w") as f:
        f.write("# GENERATED by scripts/gen_e2e.py — do not edit by hand.\n"
                "# jose jws: every signature algorithm signed and verified via file, piped\n"
                "# stdin, inline token argument, and parse, plus a wrong-key negative.\n"
                "# Shell-free/portable. Regenerate: python3 scripts/gen_e2e.py\n"
                + "".join(out))


# ---------------------------------------------------------------------------
# JWK: generate matrix across type / curve / size / format / public.
# ---------------------------------------------------------------------------

def jwk_case(name, cmd, contains, notcontains=None):
    s = f'''  - name: "{name}"
    steps:
      - run:
          command: {cmd}
      - assert:
          exit_code: 0
          stdout:
            contains:
'''
    for c in contains:
        s += f"              - {yaml_scalar(c)}\n"
    if notcontains:
        s += "      - assert:\n          stdout:\n            not_contains:\n"
        for c in notcontains:
            s += f"              - {yaml_scalar(c)}\n"
    return s


def gen_jwk():
    out = [header("jose jwk generate matrix")]
    # EC curves x format x public
    for curve in ["P-256", "P-384", "P-521"]:
        out.append(jwk_case(f"jwk EC {curve} json private", f"jose jwk generate --type EC --curve {curve}", ['"kty"', '"EC"', '"d"']))
        out.append(jwk_case(f"jwk EC {curve} json public", f"jose jwk generate --type EC --curve {curve} --public-key", ['"kty"', '"EC"'], ['"d"']))
        out.append(jwk_case(f"jwk EC {curve} pem private", f"jose jwk generate --type EC --curve {curve} --output-format pem", ["BEGIN", "PRIVATE KEY"]))
        out.append(jwk_case(f"jwk EC {curve} pem public", f"jose jwk generate --type EC --curve {curve} --public-key --output-format pem", ["BEGIN", "PUBLIC KEY"]))
    # OKP
    out.append(jwk_case("jwk OKP Ed25519 json private", "jose jwk generate --type OKP --curve Ed25519", ['"OKP"', '"d"']))
    out.append(jwk_case("jwk OKP Ed25519 json public", "jose jwk generate --type OKP --curve Ed25519 --public-key", ['"OKP"'], ['"d"']))
    out.append(jwk_case("jwk OKP Ed25519 pem private", "jose jwk generate --type OKP --curve Ed25519 --output-format pem", ["BEGIN", "PRIVATE KEY"]))
    out.append(jwk_case("jwk OKP Ed25519 pem public", "jose jwk generate --type OKP --curve Ed25519 --public-key --output-format pem", ["BEGIN", "PUBLIC KEY"]))
    out.append(jwk_case("jwk OKP X25519 json private", "jose jwk generate --type OKP --curve X25519", ['"OKP"', '"d"']))
    out.append(jwk_case("jwk OKP X25519 json public", "jose jwk generate --type OKP --curve X25519 --public-key", ['"OKP"'], ['"d"']))
    # RSA sizes x format x public. jwx requires >= 2048-bit modulus (Go rejects
    # < 1024 outright), so the generatable range starts at 2048.
    for size in [2048, 3072, 4096]:
        out.append(jwk_case(f"jwk RSA {size} json private", f"jose jwk generate --type RSA --size {size}", ['"kty"', '"RSA"', '"d"']))
        out.append(jwk_case(f"jwk RSA {size} json public", f"jose jwk generate --type RSA --size {size} --public-key", ['"kty"', '"RSA"'], ['"d"']))
    for size in [2048, 3072, 4096]:
        out.append(jwk_case(f"jwk RSA {size} pem private", f"jose jwk generate --type RSA --size {size} --output-format pem", ["BEGIN", "PRIVATE KEY"]))
        out.append(jwk_case(f"jwk RSA {size} pem public", f"jose jwk generate --type RSA --size {size} --public-key --output-format pem", ["BEGIN", "PUBLIC KEY"]))
    # oct sizes
    for size in [256, 384, 512, 1024, 2048]:
        out.append(jwk_case(f"jwk oct {size} json", f"jose jwk generate --type oct --size {size}", ['"oct"', '"k"']))
    # Generate straight to a file and assert the created delta and content; the
    # sandbox_home guard proves jose never writes outside the workdir.
    tofile = [
        ("EC P-256 json", "jose jwk generate --type EC --curve P-256 --output key.jwk", ['"kty"', '"crv"']),
        ("EC P-256 pem", "jose jwk generate --type EC --curve P-256 --output-format pem --output key.pem", ["BEGIN", "PRIVATE KEY"], "key.pem"),
        ("RSA 2048 json", "jose jwk generate --type RSA --size 2048 --output key.jwk", ['"kty"', '"RSA"']),
        ("OKP Ed25519 json", "jose jwk generate --type OKP --curve Ed25519 --output key.jwk", ['"OKP"']),
        ("OKP X25519 json", "jose jwk generate --type OKP --curve X25519 --output key.jwk", ['"OKP"']),
        ("oct 256 json", "jose jwk generate --type oct --size 256 --output key.jwk", ['"oct"']),
    ]
    for entry in tofile:
        name, cmd, contains = entry[0], entry[1], entry[2]
        path = entry[3] if len(entry) > 3 else "key.jwk"
        cont = "\n".join(f"              - {yaml_scalar(c)}" for c in contains)
        out.append(f'''  - name: "jwk {name} writes only the key file"
    steps:
      - run:
          sandbox_home: true
          command: {cmd}
      - assert:
          exit_code: 0
          changes:
            created: [{path}]
            modified: []
            deleted: []
      - assert:
          file:
            path: {path}
            contains:
{cont}
''')
    with open(os.path.join(OUT, "jwk_matrix.atago.yaml"), "w") as f:
        f.write("# GENERATED by scripts/gen_e2e.py — do not edit by hand.\n"
                "# jose jwk generate: type / curve / size / format / public-key matrix.\n"
                "# Regenerate: python3 scripts/gen_e2e.py\n"
                + "".join(out))


if __name__ == "__main__":
    gen_jwe()
    gen_jws()
    gen_jwk()
    print("generated jwe_matrix, jws_matrix, jwk_matrix in", OUT)
