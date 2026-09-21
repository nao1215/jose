---
title: Install
description: Install jose with Homebrew, go install, a prebuilt binary, or a .deb/.rpm/.apk package.
---

jose runs on Linux (the main target), macOS, and Windows. Unit tests and the
end-to-end suite run on all three in CI.

## Homebrew

```shell
brew install nao1215/tap/jose
```

The formula installs the prebuilt release binary.

## go install

```shell
GOEXPERIMENT=jsonv2 go install github.com/nao1215/jose@latest
```

Building from source needs Go 1.26 or newer. jose depends on jwx v4, which uses
`encoding/json/v2`; on Go 1.26 that package is still behind
`GOEXPERIMENT=jsonv2`, so the experiment must be set when building. The prebuilt
binaries and packages need no such flag.

## Prebuilt binaries and packages

The [release page](https://github.com/nao1215/jose/releases) has archives for
Linux, macOS, and Windows on amd64 and arm64, and .deb, .rpm, and .apk packages
for Linux. `checksums.txt` on the same page lists the SHA-256 of every file:

```shell
sha256sum --ignore-missing -c checksums.txt
```

Where `sha256sum` is missing, print the hash of the file you downloaded and
compare it with its line in `checksums.txt`: `shasum -a 256 FILE` on macOS, or
`Get-FileHash FILE` in PowerShell on Windows.

## Check the installation

```shell
jose version
```

## Shell completion

jose writes the completion script to standard output and never edits your shell
configuration. Redirect it to wherever your shell loads completions from:

```shell
jose completion bash > ~/.local/share/bash-completion/completions/jose
jose completion zsh > "${fpath[1]}/_jose"
jose completion fish > ~/.config/fish/completions/jose.fish
```

## Man pages

```shell
sudo jose man
```

This installs the man pages under `/usr/share/man/man1`.
