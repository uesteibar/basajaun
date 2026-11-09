# basajaun: developer tasks. Run `just` to list them.
#
# Rust and `just` come from mise (see mise.toml). Every recipe that needs Rust runs it
# through `mise exec`, so nobody has to put ~/.cargo/bin on PATH.

set shell := ["bash", "-euo", "pipefail", "-c"]
set positional-arguments

# Rust through mise: works from a shell where ~/.cargo/bin is not on PATH.
cargo := "mise exec -- cargo"
# Install root for `install` and `uninstall`; the binary goes to <prefix>/bin.
prefix := env_var_or_default("PREFIX", home_directory() / ".local")

# List the recipes.
[private]
default:
    @just --list

# Install the developer tools (Rust, rustfmt, clippy, just). Safe to repeat.
[group('setup')]
setup:
    mise install
    mise exec -- rustup component add rustfmt clippy

# Build the debug binary.
[group('build')]
build:
    {{cargo}} build

# Run bsjn from the source tree, e.g. `just run ls`.
[group('build')]
run *args:
    {{cargo}} run --quiet -- "$@"

# Remove build output.
[group('build')]
clean:
    {{cargo}} clean

# Run the tests.
[group('check')]
test:
    {{cargo}} test

# Format the code.
[group('check')]
fmt:
    {{cargo}} fmt

# Fail if the code is not formatted.
[group('check')]
fmt-check:
    {{cargo}} fmt --check

# Run clippy; warnings are errors.
[group('check')]
lint:
    {{cargo}} clippy --all-targets -- -D warnings

# Formatting, clippy and tests: what must pass before a commit.
[group('check')]
check: fmt-check lint test

# Same as check; the CI entry point.
[group('check')]
ci: check

# Build in release mode and install bsjn to <prefix>/bin (default ~/.local/bin).
[group('install')]
install:
    #!/usr/bin/env bash
    set -euo pipefail
    mise exec -- cargo install --path . --locked --root "{{prefix}}" --force
    echo
    echo "Installed: {{prefix}}/bin/bsjn"
    "{{prefix}}/bin/bsjn" --version
    case ":$PATH:" in
      *":{{prefix}}/bin:"*) ;;
      *)
        echo
        echo "WARNING: {{prefix}}/bin is not on your PATH, so \`bsjn\` will not be found." >&2
        echo "         Add it to your shell profile: export PATH=\"{{prefix}}/bin:\$PATH\"" >&2
        ;;
    esac

# Remove <prefix>/bin/bsjn (and cargo's record of it). Nothing else.
[group('install')]
uninstall:
    #!/usr/bin/env bash
    set -euo pipefail
    mise exec -- cargo uninstall --root "{{prefix}}" bsjn 2>/dev/null || true
    rm -f "{{prefix}}/bin/bsjn"
    echo "Removed {{prefix}}/bin/bsjn"
