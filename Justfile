set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

default:
    @just --list

# Install frontend deps (run once)
setup:
    cd web && npm ci

# Build frontend bundle into web/dist
web-build:
    cd web && npm run build

# Run the Vite dev server (separate terminal: just dev-server)
dev-web:
    cd web && npm run dev

# Run the Rust server (debug build); requires web-build for embedded assets
dev-server:
    cargo run -p fleet-server

# Full release build: frontend + binary
build: web-build
    cargo build --release

# Run the release binary
run: build
    cargo run --release -p fleet-server

# Test
test:
    cargo test --workspace

# Lint
lint:
    cargo clippy --workspace --all-targets -- -D warnings
    cargo fmt --check

# Format
fmt:
    cargo fmt
