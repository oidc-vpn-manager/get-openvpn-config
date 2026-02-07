# OpenVPN Config Tools

A collection of command-line clients for retrieving OpenVPN profiles and server bundles from OIDC VPN Manager. The tools have been split into three specialized scripts for different use cases:

- **`get_openvpn_profile.py`** - User profile retrieval via OIDC authentication
- **`get_openvpn_server_config.py`** - Server configuration bundles via PSK authentication
- **`get_openvpn_computer_config.py`** - Computer/device profiles via PSK authentication

## 🚀 Features

### User Profile Retrieval (`get_openvpn_profile.py`)
- **OIDC Authentication**: Seamless integration with enterprise identity providers
- **Browser-based Flow**: Automatic browser opening for authentication
- **Secure Download**: Time-limited tokens for secure profile delivery
- **Configuration Options**: Support for UDP, TCP, or combined configurations

### Server Bundle Retrieval (`get_openvpn_server_config.py`)
- **PSK Authentication**: Pre-shared key authentication for automated server deployment
- **Complete Bundle**: Server certificates, CA chain, and OpenVPN configurations
- **Automated Extraction**: Organized file structure for easy deployment
- **Multiple Protocols**: Both UDP and TCP server configurations included

### Computer Profile Retrieval (`get_openvpn_computer_config.py`)
- **Administrative Tool**: For server administrators managing computer identities
- **PSK Authentication**: Pre-shared key authentication for computer/device identities
- **Site-to-Site VPN**: Designed for computer-to-computer VPN connections
- **Managed Assets**: Perfect for automated deployment to managed devices by administrators
- **Single Profile**: Returns a complete OpenVPN profile file

## 📦 Installation

### Prerequisites
- Python 3.8+
- Modern web browser (for OIDC authentication)
- Network access to OIDC VPN Manager service

### Install Dependencies
```bash
pip install -r requirements.txt
```

### Make Scripts Executable
```bash
chmod +x get_openvpn_profile.py get_openvpn_server_config.py get_openvpn_computer_config.py
```

## 💻 Usage

### User Profile Commands (`get_openvpn_profile.py`)

#### Interactive Profile Retrieval
```bash
# Basic usage with interactive authentication
./get_openvpn_profile.py --server-url https://vpn.company.com

# Specify output location
./get_openvpn_profile.py \
  --server-url https://vpn.company.com \
  --output ~/my-vpn-profile.ovpn

# Select TCP protocol instead of default UDP
./get_openvpn_profile.py \
  --server-url https://vpn.company.com \
  --options tcp

# Force overwrite existing file
./get_openvpn_profile.py \
  --server-url https://vpn.company.com \
  --output ~/config.ovpn \
  --force
```

### Server Bundle Commands (`get_openvpn_server_config.py`)

#### Automated Server Configuration
```bash
# Retrieve server bundle with PSK authentication
./get_openvpn_server_config.py \
  --server-url https://vpn.company.com \
  --psk your-server-psk-secret-here \
  --target-dir /etc/openvpn

# Custom target directory
./get_openvpn_server_config.py \
  --server-url https://vpn.company.com \
  --psk your-server-psk-secret-here \
  --target-dir /opt/openvpn-config \
  --force
```

### Computer Profile Commands (`get_openvpn_computer_config.py`)

#### Administrative Computer Configuration
```bash
# Retrieve computer profile with PSK authentication (admin only)
./get_openvpn_computer_config.py \
  --server-url https://vpn.company.com \
  --psk your-computer-psk-secret-here \
  --output ~/computer-config.ovpn

# Force overwrite existing file
./get_openvpn_computer_config.py \
  --server-url https://vpn.company.com \
  --psk your-computer-psk-secret-here \
  --output /etc/openvpn/client/computer.ovpn \
  --force
```

## ⚙️ Configuration

### Configuration File

Create `~/.config/ovpn-manager/config.yaml` for persistent settings:

```yaml
# OIDC VPN Manager Configuration
server_url: https://vpn.company.com
output: ~/Downloads/config.ovpn
overwrite: false
options: udp  # udp, tcp, or udp,tcp for combined
```

### Environment Variables

Configure via environment variables:

```bash
# Server URL
export OVPN_MANAGER_URL=https://vpn.company.com

# Output file location  
export OVPN_MANAGER_OUTPUT=~/my-config.ovpn

# Protocol options
export OVPN_MANAGER_OPTIONS=tcp

# Overwrite existing files
export OVPN_MANAGER_OVERWRITE=true

# PSK for server authentication (keep secure!)
export OVPN_PSK=your-server-psk-here
```

### Configuration Precedence

Settings are resolved in this order (highest precedence first):
1. **Command-line arguments**
2. **Environment variables**
3. **User configuration file** (`~/.config/ovpn-manager/config.yaml`)
4. **System configuration file** (`/etc/ovpn-manager/config.yaml`)
5. **Default values**

## 🔧 Advanced Usage

### Automation and Scripting

#### User Profile Automation
```bash
#!/bin/bash
# Automated profile retrieval script

export OVPN_MANAGER_URL=https://vpn.company.com
export OVPN_MANAGER_OUTPUT=/tmp/vpn-profile.ovpn
export OVPN_MANAGER_OVERWRITE=true

./get_openvpn_profile.py

if [ $? -eq 0 ]; then
    echo "Profile downloaded successfully"
    # Deploy or process the profile
    install -m 600 /tmp/vpn-profile.ovpn ~/config.ovpn
else
    echo "Failed to retrieve profile"
    exit 1
fi
```

#### Server Deployment Integration
```bash
#!/bin/bash
# Server configuration deployment script

HOSTNAME="vpn-$(hostname -f)"
PSK_FILE="/etc/oidc-vpn-manager/server.psk"
TARGET_DIR="/etc/openvpn"

if [ ! -f "$PSK_FILE" ]; then
    echo "PSK file not found: $PSK_FILE"
    exit 1
fi

PSK=$(cat "$PSK_FILE")

./get_openvpn_server_config.py \
    --server-url https://vpn.company.com \
    --psk "$PSK" \
    --target-dir "$TARGET_DIR" \
    --force

if [ $? -eq 0 ]; then
    echo "Server configuration deployed successfully"
    systemctl restart openvpn-server@udp-1194
    systemctl restart openvpn-server@tcp-443
else
    echo "Failed to deploy server configuration"
    exit 1
fi
```

#### Computer Profile Deployment (Admin Only)
```bash
#!/bin/bash
# Administrative script for deploying computer profiles

COMPUTER_NAME="workstation-$(hostname)"
PSK_FILE="/etc/oidc-vpn-manager/computer.psk"
OUTPUT_FILE="/etc/openvpn/client/${COMPUTER_NAME}.ovpn"

if [ ! -f "$PSK_FILE" ]; then
    echo "Computer PSK file not found: $PSK_FILE"
    exit 1
fi

PSK=$(cat "$PSK_FILE")

./get_openvpn_computer_config.py \
    --server-url https://vpn.company.com \
    --psk "$PSK" \
    --output "$OUTPUT_FILE" \
    --force

if [ $? -eq 0 ]; then
    echo "Computer profile deployed successfully: $OUTPUT_FILE"
    # Set appropriate permissions for computer profile
    chmod 600 "$OUTPUT_FILE"
    systemctl restart openvpn-client@${COMPUTER_NAME}
else
    echo "Failed to deploy computer profile"
    exit 1
fi
```

### Docker Integration

#### User Profile Container
```dockerfile
FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt get_openvpn_profile.py ./
RUN pip install -r requirements.txt

# For headless authentication in containers, you may need
# to implement service account or API key authentication
ENTRYPOINT ["python", "get_openvpn_profile.py"]
```

#### Server Configuration Init Container
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
    - https://vpn.company.com
    - --psk
    - $(PSK_SECRET)
    - --target-dir
    - /shared/config
    - --force
    env:
    - name: HOSTNAME
      valueFrom:
        fieldRef:
          fieldPath: metadata.name
    - name: PSK_SECRET
      valueFrom:
        secretKeyRef:
          name: openvpn-psk
          key: psk
    volumeMounts:
    - name: config-volume
      mountPath: /shared/config
```

## 📁 Server Bundle Structure

When retrieving server bundles, files are organized as follows:

```
/etc/openvpn/
├── cert/
│   ├── ca-chain.crt          # Complete CA certificate chain
│   ├── server.crt            # Server certificate
│   └── tls-auth.key          # TLS authentication key (optional)
├── key/
│   └── server.key            # Server private key
├── udp-1194/
│   └── server.ovpn           # UDP server configuration
└── tcp-443/
    └── server.ovpn           # TCP server configuration
```

## 🧪 Testing

### Unit Tests
```bash
python -m pytest tests/ -v
```

### Integration Testing
```bash
# Test against running OIDC VPN Manager instance
export TEST_SERVER_URL=https://test-vpn.company.com
export TEST_PSK=test-psk-secret
python -m pytest tests/ -v --integration
```

## 🛡️ Security Considerations

### PSK Management
- **Secure Storage**: Store PSKs in secure secret management systems
- **Access Control**: Limit access to PSK files and environment variables
- **Regular Rotation**: Rotate PSKs as part of security maintenance
- **Audit Logging**: Monitor PSK usage through server logs

### Profile Security
- **Secure Download**: Use HTTPS for all communications
- **File Permissions**: Set appropriate file permissions (600) on profiles
- **Clean Up**: Remove temporary files and clear sensitive environment variables
- **Certificate Validation**: Verify server certificates during download

### Network Security
- **TLS Verification**: Always verify TLS certificates
- **Network Isolation**: Use secure networks for profile retrieval
- **Firewall Configuration**: Allow only necessary network access

## ❓ Troubleshooting

### Common Issues

**Authentication Failures**:
- Verify server URL is correct and accessible
- Check browser pop-up blockers during OIDC flow
- Ensure OIDC provider configuration is correct
- Verify network connectivity to authentication server

**PSK Authentication Errors**:
- Confirm PSK is valid and not expired
- Check hostname matches server certificate requirements
- Verify network connectivity to OIDC VPN Manager
- Review server logs for authentication attempts

**Download Failures**:
- Check available disk space in target directory
- Verify write permissions for output location
- Ensure stable network connection during download
- Try again if download token has expired

**File Permission Issues**:
- Run with appropriate user permissions
- Check target directory ownership and permissions
- Use `--force` flag to overwrite existing files
- Verify no conflicting processes are using target files

### Debug Mode

Enable verbose logging for debugging:
```bash
# For user profile issues
python -v get_openvpn_profile.py --server-url https://vpn.company.com

# For server config issues
python -v get_openvpn_server_config.py --server-url https://vpn.company.com --psk your-psk

# For computer profile issues
python -v get_openvpn_computer_config.py --server-url https://vpn.company.com --psk your-psk
```

## 🤝 Contributing

Contributions are welcome! Since this is Free Software:

- No copyright assignment needed, but will be gratefully received
- **Feature requests and improvements are gratefully received**, however they may not be implemented due to time constraints or if they don't align with the developer's vision for the project
- Please ensure all tests pass and maintain code coverage
- Follow existing security practices and coding standards

### Development Standards
- Comprehensive test coverage for all functionality
- Security-first design for credential handling
- Clear documentation for new features
- Compatibility with existing configuration methods

## 📄 License

This software is released under the [GNU Affero General Public License version 3](LICENSE).

## 🤖 AI Assistance Disclosure

This code was developed with assistance from AI tools. While released under a permissive license that allows unrestricted reuse, we acknowledge that portions of the implementation may have been influenced by AI training data. Should any copyright assertions or claims arise regarding uncredited imported code, the affected portions will be rewritten to remove or properly credit any unlicensed or uncredited work.