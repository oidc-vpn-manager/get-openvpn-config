# Get OpenVPN Config Tool

This file provides LLMs with guidance for working with the Get OpenVPN Config Tool component of OpenVPN Manager.

## Tool Overview

The Get OpenVPN Config Tools are a collection of specialized command-line clients for retrieving OpenVPN profiles and server bundles from OpenVPN Manager. The tools have been split into three focused scripts:

- **`get_openvpn_profile.py`** - End-user profile retrieval via OIDC authentication
- **`get_openvpn_server_config.py`** - Server configuration bundles via PSK authentication
- **`get_openvpn_computer_config.py`** - Computer/device profiles via PSK authentication (single OVPN file like user profiles)

**Note**: The original monolithic `get_openvpn_config.py` script has been removed and replaced with these three specialized scripts for better maintainability and clearer separation of concerns.

## Architecture

### File Structure
- `get_openvpn_profile.py` - User profile retrieval script
- `get_openvpn_server_config.py` - Server configuration script
- `get_openvpn_computer_config.py` - Computer profile script
- `tests/` - Comprehensive test suite
  - `test_get_openvpn_profile.py` - User profile functionality tests
  - `test_get_openvpn_server_config.py` - Server configuration functionality tests
  - `test_get_openvpn_computer_config.py` - Computer profile functionality tests
  - `test_get_server_bundle.py` - Server bundle functionality tests
  - `requirements.txt` - Test dependencies
- `requirements.txt` - Runtime dependencies
- `README.md` - Comprehensive usage documentation

### Core Components
- **OIDC Authentication**: Browser-based authentication flow (user profiles)
- **PSK Authentication**: Pre-shared key authentication for servers and computers
- **Profile Download**: User certificate and configuration retrieval
- **Server Bundles**: Complete server configuration deployment with file extraction
- **Computer Profiles**: Computer identity certificates for managed devices (admin only)
- **Configuration Management**: Multiple configuration sources and precedence

## Dependencies

### Runtime Requirements
- **requests**: HTTP client for API communication
- **PyYAML**: Configuration file parsing
- **cryptography**: Certificate validation and processing
- **Python 3.8+**: Required for modern features

### Testing Dependencies
- **pytest**: Test framework and runner
- **pytest-cov**: Coverage reporting
- **requests-mock**: HTTP request mocking
- **Additional utilities**: As specified in `tests/requirements.txt`

## Development Workflow

### Local Development
```bash
cd tools/get_openvpn_config

# Install runtime dependencies
pip install -r requirements.txt

# Install test dependencies
pip install -r tests/requirements.txt

# Make scripts executable
chmod +x get_openvpn_profile.py get_openvpn_server_config.py get_openvpn_computer_config.py

# Test basic functionality
./get_openvpn_profile.py --help
./get_openvpn_server_config.py --help
./get_openvpn_computer_config.py --help
```

### Testing
```bash
# Run all tests
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ --cov=get_openvpn_config --cov-report=html

# Run specific test modules
python -m pytest tests/test_get_openvpn_profile.py -v
python -m pytest tests/test_get_openvpn_server_config.py -v
python -m pytest tests/test_get_openvpn_computer_config.py -v
python -m pytest tests/test_get_server_bundle.py -v

# Integration tests (requires running OpenVPN Manager)
export TEST_SERVER_URL=https://test-vpn.company.com
export TEST_PSK=test-psk-secret
python -m pytest tests/ -v --integration
```

## Command-Line Interface

### User Profile Commands (`get_openvpn_profile.py`)
```bash
# Basic OIDC authentication
./get_openvpn_profile.py \
  --server-url https://vpn.company.com

# Specify output file and protocol
./get_openvpn_profile.py \
  --server-url https://vpn.company.com \
  --output ~/config.ovpn \
  --options tcp \
  --force

# Use combined UDP/TCP configuration
./get_openvpn_profile.py \
  --server-url https://vpn.company.com \
  --options udp,tcp
```

### Server Bundle Commands (`get_openvpn_server_config.py`)
```bash
# Basic PSK authentication for server bundles
./get_openvpn_server_config.py \
  --server-url https://vpn.company.com \
  --psk your-server-psk-secret \
  --target-dir /etc/openvpn

# Force overwrite existing files
./get_openvpn_server_config.py \
  --server-url https://vpn.company.com \
  --psk your-server-psk-secret \
  --target-dir /opt/openvpn-config \
  --force
```

### Computer Profile Commands (`get_openvpn_computer_config.py`)
```bash
# Administrative computer profile retrieval (returns single OVPN file like user profiles)
./get_openvpn_computer_config.py \
  --server-url https://vpn.company.com \
  --psk your-computer-psk-secret \
  --output ~/computer-config.ovpn

# Force overwrite existing file
./get_openvpn_computer_config.py \
  --server-url https://vpn.company.com \
  --psk your-computer-psk-secret \
  --output /etc/openvpn/client/computer.ovpn \
  --force
```

### Configuration Options
- `--server-url` - OpenVPN Manager base URL (required)
- `--output` - Output file path for user profiles
- `--options` - Protocol options: udp, tcp, or udp,tcp
- `--force` - Overwrite existing files
- `--hostname` - Server hostname for PSK requests
- `--psk` - Pre-shared key for server authentication
- `--target-dir` - Target directory for server bundles

## Configuration Management

### Configuration File Support
```yaml
# ~/.config/ovpn-manager/config.yaml
server_url: https://vpn.company.com
output: ~/Downloads/config.ovpn
overwrite: false
options: udp
```

### Environment Variables
```bash
# Core settings
export OVPN_MANAGER_URL=https://vpn.company.com
export OVPN_MANAGER_OUTPUT=~/config.ovpn
export OVPN_MANAGER_OPTIONS=tcp
export OVPN_MANAGER_OVERWRITE=true

# Server bundle settings
export OVPN_PSK=server-psk-secret
export OVPN_HOSTNAME=vpn-server.company.com
```

### Configuration Precedence
1. Command-line arguments (highest)
2. Environment variables
3. User configuration file (`~/.config/ovpn-manager/config.yaml`)
4. System configuration file (`/etc/ovpn-manager/config.yaml`)
5. Default values (lowest)

## Authentication Methods

### OIDC Authentication (User Profiles)
- **Browser Flow**: Automatic browser opening for authentication
- **Token Handling**: Secure token exchange and validation
- **Session Management**: Authentication state handling
- **Error Handling**: Clear error messages for auth failures

### PSK Authentication (Server Bundles)
- **Shared Secret**: Pre-configured authentication keys
- **Secure Storage**: Best practices for PSK management
- **API Integration**: Direct API authentication
- **Automated Deployment**: Suitable for scripting and automation

## Output Formats

### User Profile Structure
```
config.ovpn                 # Complete OpenVPN client configuration
├── client certificate      # Embedded in configuration
├── private key             # Embedded in configuration
├── CA certificate chain    # Embedded in configuration
└── OpenVPN directives      # Protocol, server, routing
```

### Server Bundle Structure
```
target-dir/
├── ca-chain.crt           # Complete CA certificate chain
├── server.crt             # Server certificate
├── server.key             # Server private key
├── Default.0100.ovpn       # Server configuration template (priority 100)
├── Default.0200.ovpn       # Server configuration template (priority 200)
└── tls-auth.pem            # TLS authentication key (if used)
```

## Security Features

### Network Security
- **HTTPS Only**: All communication over TLS
- **Certificate Validation**: Server certificate verification
- **Secure Downloads**: Tamper-evident file transfers
- **Request Validation**: Input sanitization and validation

### Credential Management
- **PSK Security**: Secure handling of pre-shared keys
- **Token Protection**: Secure storage of authentication tokens
- **Memory Safety**: Credential cleanup after use
- **File Permissions**: Appropriate permissions on output files

### Error Handling
- **Secure Error Messages**: No credential exposure in errors
- **Network Resilience**: Retry logic for network failures
- **Validation**: Input validation and sanitization
- **Logging**: Security-conscious logging practices

## Testing Standards

### Test Coverage Requirements
- **100% code coverage**: All functions and branches tested
- **Authentication Testing**: Both OIDC and PSK authentication flows
- **Error Handling**: Network failures and authentication errors
- **Integration Testing**: Real service integration tests

### Test Categories
- **Unit Tests**: Individual function and class testing
- **Integration Tests**: API communication and authentication
- **Functional Tests**: Complete user and server workflows
- **Security Tests**: Credential handling and secure communication

## Common Operations

### Adding New Authentication Methods
1. Implement authentication flow in main script
2. Add command-line argument support
3. Update configuration file parsing
4. Add comprehensive test coverage
5. Update documentation and examples

### Extending Configuration Options
1. Add new configuration parameters
2. Update command-line argument parsing
3. Extend configuration file format
4. Implement environment variable support
5. Update precedence handling

### API Integration Changes
1. Modify API communication logic
2. Update request/response handling
3. Add new endpoint support
4. Implement proper error handling
5. Add integration tests

## Automation & Scripting

### User Profile Automation
```bash
#!/bin/bash
# Automated profile retrieval

export OVPN_MANAGER_URL=https://vpn.company.com
export OVPN_MANAGER_OUTPUT=/tmp/vpn-profile.ovpn
export OVPN_MANAGER_OVERWRITE=true

if ./get_openvpn_profile.py --server-url "$OVPN_MANAGER_URL" --output "$OVPN_MANAGER_OUTPUT" --force; then
    echo "Profile downloaded successfully"
    install -m 600 /tmp/vpn-profile.ovpn ~/config.ovpn
else
    echo "Failed to retrieve profile"
    exit 1
fi
```

### Server Deployment Scripts
```bash
#!/bin/bash
# Server configuration deployment

HOSTNAME="vpn-$(hostname -f)"
PSK_FILE="/etc/openvpn-manager/server.psk"
TARGET_DIR="/etc/openvpn"

if [ ! -f "$PSK_FILE" ]; then
    echo "PSK file not found: $PSK_FILE"
    exit 1
fi

./get_openvpn_server_config.py \
    --server-url https://vpn.company.com \
    --hostname "$HOSTNAME" \
    --psk "$(cat "$PSK_FILE")" \
    --target-dir "$TARGET_DIR" \
    --force

if [ $? -eq 0 ]; then
    systemctl restart openvpn-server@udp-1194
    systemctl restart openvpn-server@tcp-443
fi
```

## Container Integration

### Docker Usage
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt get_openvpn_profile.py get_openvpn_server_config.py get_openvpn_computer_config.py ./
RUN pip install -r requirements.txt

# Configure for headless operation (specify which script as argument)
ENTRYPOINT ["python"]
```

### Kubernetes Init Container
```yaml
apiVersion: v1
kind: Pod
spec:
  initContainers:
  - name: fetch-openvpn-config
    image: openvpn-config-fetcher:latest
    command:
    - python
    - get_openvpn_server_config.py
    - --server-url
    - $(SERVER_URL)
    - --hostname
    - $(HOSTNAME)
    - --psk
    - $(PSK_SECRET)
    - --target-dir
    - /shared/config
    env:
    - name: SERVER_URL
      value: https://vpn.company.com
    - name: HOSTNAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
    - name: PSK_SECRET
      valueFrom:
        secretKeyRef:
          name: openvpn-psk
          key: psk
```

## Debugging & Troubleshooting

### Common Issues
- **Authentication Failures**: OIDC provider configuration
- **Network Errors**: Connectivity and firewall issues
- **File Permissions**: Write access and ownership
- **PSK Authentication**: Key validity and format

### Debug Features
- **Verbose Logging**: Detailed operation logging
- **Network Debugging**: HTTP request/response logging
- **Authentication Debugging**: Token and PSK validation
- **File Operation Debugging**: Download and extraction logging

### Troubleshooting Commands
```bash
# Test connectivity
curl -I https://vpn.company.com/health

# Validate PSK
./get_openvpn_server_config.py --server-url https://vpn.company.com --hostname test --psk your-psk --target-dir /tmp/test --force

# Check file permissions
ls -la /path/to/output/
```

## Performance Considerations

### Network Performance
- **Connection Reuse**: HTTP connection pooling
- **Timeout Handling**: Appropriate timeout values
- **Retry Logic**: Exponential backoff for failures
- **Bandwidth Usage**: Efficient file transfer

### Resource Usage
- **Memory Management**: Efficient handling of large files
- **Temporary Files**: Proper cleanup of temporary resources
- **Concurrent Operations**: Safe handling of multiple requests
- **System Resources**: Minimal system impact during operation