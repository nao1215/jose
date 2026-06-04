# jose demo tape (https://github.com/charmbracelet/vhs)
#
# Regenerate with `make demo`, which builds the CLI, copies it to /tmp, seeds a
# throwaway directory under /tmp/jose-demo, runs this tape, and moves demo.gif
# into doc/img/.
#
# vhs v0.11 parses absolute Output paths oddly, so the tape writes a relative
# demo.gif into the current directory and `make demo` moves it into doc/img/.

Output demo.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 820
Set Padding 24
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=/tmp:$PATH; cd /tmp/jose-demo; clear" Enter
Show

Type "# 1. Generate an EC private key (P-256)" Enter
Type "jose jwk generate --type EC --curve P-256 --output ec.jwk" Enter
Sleep 800ms

Type "# 2. Sign payload.json with ES256" Enter
Type "cat payload.json" Enter
Sleep 600ms
Type "jose jws sign --algorithm ES256 --key ec.jwk payload.json > token.jws" Enter
Sleep 800ms
Type "cat token.jws" Enter
Sleep 1500ms

Type "# 3. Verify the signature and recover the payload" Enter
Type "jose jws verify --algorithm ES256 --key ec.jwk token.jws" Enter
Sleep 2000ms

Type "# 4. Encrypt the payload, then decrypt it back" Enter
Type "jose jwe encrypt --key ec.jwk --key-encryption ECDH-ES --content-encryption A256GCM payload.json > secret.jwe" Enter
Sleep 800ms
Type "jose jwe decrypt --key ec.jwk secret.jwe" Enter
Sleep 2500ms
