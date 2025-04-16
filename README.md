# Secure Protocol Gateway

A high-performance aerospace protocol translation gateway with robust security features implemented in Rust.

## What It Does

This gateway bridges critical aerospace communication systems, specifically:

- Translates between legacy MIL-STD-1553 avionics bus and modern Ethernet/IP networks
- Secures all communications with industry-standard encryption and authentication
- Provides configurable routing and transformation rules
- Manages cryptographic keys with automated rotation

## How It Works

1. **Protocol Parsing**: Converts raw binary data from source protocol format
2. **Security Layer**: Applies ChaCha20Poly1305 encryption and Ed25519 signatures
3. **Translation Engine**: Maps between protocol-specific fields and message formats
4. **Routing**: Delivers messages to appropriate destinations based on configuration

## Architecture

![Architecture](https://github.com/romeoazizian/secure-gateway/raw/main/docs/architecture.png)

The system uses a modular design with these components:
- **Protocol Handlers**: Parse and format protocol-specific messages
- **Security Module**: Provides encryption, signing, and key management
- **Gateway Core**: Handles message routing and transformation
- **Configuration System**: Enables customization via YAML files

## Why I Built This

I developed similar systems while working at Lockheed Martin on the latest Mission Computer software for F-16 aircraft (the "brain" of the jet) in C++. This project is my exploration of implementing critical aerospace systems in Rust, which offers significant advantages for safety-critical applications.

## Rust vs C++ for Aerospace Systems

### Advantages of Rust
- **Memory Safety**: No segfaults, buffer overflows, or dangling pointers without runtime cost
- **Concurrency Safety**: Thread safety guaranteed at compile time
- **Error Handling**: Forces explicit handling of all error conditions
- **Zero-Cost Abstractions**: High-level features with no runtime penalty
- **Modern Tooling**: Built-in package management, testing, and documentation

### Challenges
- **Learning Curve**: Less familiar to aerospace engineers than C++
- **Ecosystem Maturity**: Fewer domain-specific libraries for aerospace applications
- **Certification**: Less established path for DO-178C certification
- **Legacy Integration**: More complex interoperability with existing C/C++ codebases

## Demo

Run our visual demo to see the gateway in action:

```bash
RUST_LOG=info cargo run --example visual_demo
```

## Building and Testing

```bash
# Build the gateway
cargo build --release

# Run all tests
cargo test

# Run the simulation
cargo run --example simulation
```

## License

MIT License 