# gums3

Elegant S3 Storage Viewer — a minimalist S3/MinIO client with both web and terminal interfaces.

## Features

- **Dark Mode Web UI**: Always-on dark theme with clean, legible styling
- **Interactive TUI**: Keyboard-driven terminal UI (arrow keys, Enter, D, Esc, Q)
- **Dates and Sizes**: Last Modified and human-readable sizes in UI and TUI
- **Default Bucket**: Optional bucket field on login to skip bucket listing
- **Cross-Platform**: Linux, macOS (Intel/ARM), Windows binaries
- **Flexible Auth**: Config file, environment variables, or interactive prompts
- **Core Ops**: List, download, and delete S3 objects quickly

## Quick Start

### Download Binaries (Recommended)

If you don't want to build from source, you can download the pre-built binaries:

```bash
# Download the latest release for your platform
# Linux (x86_64)
wget https://github.com/mn288/gums3/commits/v0.1.0/gums3-linux_amd64
chmod +x gums3-linux_amd64

# macOS (Intel)
wget https://github.com/mn288/gums3/commits/v0.1.0/gums3-darwin_amd64
chmod +x gums3-darwin_amd64

# macOS (Apple Silicon)
wget https://github.com/mn288/gums3/commits/v0.1.0/gums3-darwin_arm64
chmod +x gums3-darwin_arm64

# Windows
wget https://github.com/mn288/gums3/commits/v0.1.0/gums3-windows_amd64.exe
```

### Build from Source

```bash
# Clone and build
git clone https://github.com/mnabaa/gums3.git
cd gums3

# Local build (host platform)
make build

# Cross-compile binaries (bin/)
make cross

# Or manual build
go mod tidy && go build -o bin/gums3 .
```

## Usage

### Web Interface

Start the web server:

```bash
./gums3-linux_amd64 server -p 8080 --insecure
```

Navigate to `http://localhost:8080` and login. Optionally provide a Default Bucket to skip listing.

### Terminal Interface (TUI)

#### With config file:

```bash
./gums3-linux_amd64 cli --config /path/to/credentials.json
```

#### With default config:

```bash
./gums3-linux_amd64 cli
```

The CLI will look for config at `~/.gums3/credentials.json`

#### Environment variables (AWS SDK v2 conventions)

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_REGION=us-east-1
# For MinIO or custom S3 endpoints:
export AWS_ENDPOINT_URL_S3=http://localhost:9000
./gums3-linux_amd64 cli
```

#### Interactive mode:

If no config is found, you'll be prompted for credentials.

### TUI Controls

- **Arrow Keys** - Navigate
- **Enter** - Download file or enter folder
- **D** - Delete file
- **Esc** - Go back
- **Q** - Quit

## Configuration

### Credentials File

Create `~/.gums3/credentials.json` (keys are case-insensitive; variants like `access_key` are accepted):

```json
{
  "Endpoint": "https://minio.example.com:9000",
  "AccessKey": "your-access-key",
  "SecretKey": "your-secret-key",
  "Region": "us-east-1"
}
```

Also supported via environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION`, `AWS_ENDPOINT_URL_S3`.

### Supported S3 Services

- **MinIO** - Self-hosted S3-compatible storage
- **AWS S3** - Amazon Web Services S3
- **DigitalOcean Spaces** - S3-compatible object storage
- **Any S3-compatible service**

## Design Philosophy

**Minimalist** - Clean, distraction-free interface
**Fast** - Optimized for quick operations
**Reliable** - Graceful error handling
**Cross-platform** - Works everywhere Go runs

## Architecture

```
gums3/
├── Web Interface    # HTTP server with HTML templates
├── TUI Interface    # Terminal UI with tview
├── S3 Client        # AWS SDK v2 for S3 operations
└── Configuration    # JSON-based credential management
```

## Requirements

- Go 1.21+ (for building from source)
- S3-compatible storage service
- Valid access credentials

## Security

- Credentials stored locally only; no telemetry
- Session-based web authentication (HTTPOnly cookies, SameSite=Lax)
- Secure cookies by default; use `--insecure` for local HTTP
- CSRF protection for DELETE actions
- Security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)

## Troubleshooting

### Connection Issues

1. Verify endpoint URL format: `https://host:port`
2. Check access key and secret key
3. Ensure credentials have required permissions:
   - `s3:ListBuckets`
   - `s3:ListObjects`
   - `s3:GetObject`
   - `s3:DeleteObject`

### TUI Issues

- **Blank screen**: Check terminal compatibility
- **Garbled text**: Ensure UTF-8 support
- **No response**: Press Q to quit safely

### Web Interface Issues

- **Login fails**: Check browser console for errors
- **Session expires**: Re-login from `/login`

### Permission Issues

If you get permission errors with credentials file:

```bash
sudo chown $USER:$USER ~/.gums3/credentials.json
chmod 600 ~/.gums3/credentials.json
```

## Development

### Building from source

```bash
git clone https://github.com/mnabaa/gums3.git
cd gums3
make build          # local build to bin/
make cross          # cross-compile to bin/
make dist           # cross-compile to dist/ with SHA256SUMS.txt
```

### Releasing

GitHub Actions builds and publishes binaries on tags (`v*`).

```bash
git tag v0.1.0
git push origin v0.1.0
```
Artifacts will appear in the GitHub Release with checksums.

### Cross-compilation

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o gums3-linux .

# macOS
GOOS=darwin GOARCH=amd64 go build -o gums3-darwin .

# Windows
GOOS=windows GOARCH=amd64 go build -o gums3-windows.exe .
```

## Dependencies

- `github.com/aws/aws-sdk-go-v2` - S3 client
- `github.com/rivo/tview` - Terminal UI framework
- `github.com/spf13/cobra` - CLI framework
- `github.com/dustin/go-humanize` - Human-readable file sizes

## License

MIT License - see LICENSE file for details

## Contributing

1. Fork the repository
2. Create feature branch
3. Add tests for new functionality
4. Submit pull request

---

**gums3** - Making S3 viewing simple and elegant.
