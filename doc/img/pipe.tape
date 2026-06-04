# jose pipe demo tape (https://github.com/charmbracelet/vhs)
#
# Regenerate with `make demo-pipe`, which builds the CLI, copies it to /tmp,
# seeds a throwaway directory under /tmp/jose-pipe-demo, runs this tape, and
# moves pipe.gif into doc/img/.
#
# vhs v0.11 parses absolute Output paths oddly, so the tape writes a relative
# pipe.gif into the current directory and `make demo-pipe` moves it into
# doc/img/.

Output pipe.gif

Set Shell bash
Set FontSize 18
Set Width 1200
Set Height 700
Set Padding 24
Set Theme "Catppuccin Mocha"

Hide
Type "export PATH=/tmp:$PATH; cd /tmp/jose-pipe-demo; clear" Enter
Show

Type "# Generate an EC private key (P-256)" Enter
Type "jose jwk generate --type EC --curve P-256 --output ec.jwk" Enter
Sleep 800ms

Type "# Pipe a payload into sign, then pipe the token into verify" Enter
Type "cat payload.json | jose jws sign --algorithm ES256 --key ec.jwk > token.jws" Enter
Sleep 800ms
Type "cat token.jws | jose jws verify --algorithm ES256 --key ec.jwk" Enter
Sleep 2000ms

Type "# Or pass the token directly as an argument" Enter
Type "token=$(cat token.jws)" Enter
Type "jose jws verify --algorithm ES256 --key ec.jwk $token" Enter
Sleep 2500ms
