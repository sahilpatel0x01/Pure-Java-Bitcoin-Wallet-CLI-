# Pure Java Bitcoin Wallet (CLI) 🪙

![Java](https://img.shields.io/badge/Java-ED8B00?style=for-the-badge&logo=java&logoColor=white)
![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen?style=for-the-badge)
![License](https://img.shields.io/badge/license-MIT-blue?style=for-the-badge)

A fully functional, **zero-dependency** Bitcoin wallet implementation written in pure Java.

**No Bouncy Castle. No BitcoinJ. No external libraries.**

This project implements core cryptographic primitives (SHA-256, RIPEMD-160, Secp256k1) and wallet standards (WIF, P2PKH, Base58Check) entirely from scratch using the standard JDK.

## 🚀 Features

*   **Zero Dependencies**: Runs on any standard JVM (Java 11+).
*   **Custom Cryptography**:
    *   `Secp256k1` Elliptic Curve implementation (using `BigInteger`).
    *   `RIPEMD-160` hashing.
    *   `Base58` and `Base58Check` encoding/decoding.
*   **Wallet Functions**:
    *   Generate random Private/Public Key pairs.
    *   Import/Export Keys in **WIF** (Wallet Import Format).
    *   Generate **P2PKH** (Pay to Public Key Hash) Mainnet/Testnet addresses.
    *   Watch-only wallet support (Import Address).

## ⚠️ verification & Security Disclaimer

> **EDUCATIONAL PURPOSE ONLY**: This software implements cryptographic primitives from scratch. While functionally correct against standard test vectors, it has **not** been hardened against side-channel attacks (timing attacks, power analysis, etc.).
>
> **DO NOT USE WITH LARGE AMOUNTS OF REAL MONEY.**

## 🛠️ Build & Run

You don't need Maven or Gradle. Just the JDK.

### Prerequisites
*   Java Development Kit (JDK) 11 or higher.

### Compile
Navigate to the project root and compile the source code:

```bash
javac -d bin -sourcepath src src/cli/WalletCLI.java
```

### Run
Launch the CLI:

```bash
java -cp bin cli.WalletCLI
```

## 📂 Project Structure

```
src/
├── cli/
│   └── WalletCLI.java       # Main entry point and user interface
├── crypto/
│   ├── Base58.java          # Base58 encoding/decoding
│   ├── HashUtils.java       # SHA-256 and helper wrappers
│   ├── Ripemd160.java       # Pure Java RIPEMD-160 implementation
│   └── Secp256k1.java       # Elliptic Curve mathematics
└── wallet/
    ├── KeyManager.java      # Key generation and derivation logic
    └── Wallet.java          # Wallet state model
```

## 🧪 Verification

This wallet has been verified against standard Bitcoin vectors:
*   **Addresses**: Generates valid addresses starting with `1` (Mainnet P2PKH).
*   **WIF**: Generates valid WIF keys starting with `L` or `K` (Compressed Mainnet).
