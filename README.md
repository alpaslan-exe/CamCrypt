# CamCrypt 📷

**CamCrypt** is a Python library and command-line tool that harnesses multiple physical noise sources such as webcam sensor noise and ambient microphone audio to generate high-entropy encryption keys. Inspired by Cloudflare’s LavaLamp project, CamCrypt combines unpredictable real-world randomness with proven cryptographic primitives to mitigate the risk of key prediction or reverse engineering.

## Table of Contents

- [Currently Supported Platforms](#currently-supported-platforms)
- [Why CamCrypt?](#why-camcrypt)
- [How It Works](#how-it-works)
- [Library Status & Roadmap](#library-status--roadmap)
- [License](#license)

---

## Currently Supported Platforms

| Language   | Status             |
| ---------- | ------------------ |
| Python     | ✔️ Fully supported |
| C++        | 🔶 In progress     |
| C          | 🔶 In progress     |
| Swift      | 🔶 In progress     |
| Java       | 🔶 In progress     |
| JavaScript | 🔶 In progress     |

> 🔶 In progress  |  ✔️ Fully supported  |  ❌ Unsupported/unplanned

*Any environment using CamCrypt must provide access to both a webcam and microphone.* To request additional language or platform support, please open an issue on GitHub.

---

## Why CamCrypt?

Traditional key generation methods often rely on time-based seeds or a single PRNG, which can:

- Produce **predictable seeds** when timers are spoofed or estimated by attackers.
- Fall into **low-entropy states** in virtualized or headless environments.
- Rely on **security by obscurity**, violating Kerckhoffs’s principle in zero-trust architectures.

CamCrypt addresses these limitations by mixing **multiple independent entropy channels** into a unified, one-way seed. Even if one channel is weak, the combined seed remains unpredictable.

---

## How It Works

1. **Entropy Collection**

   - **Video LSB Noise**: Extract least significant bits from webcam frames.
   - **Audio LSB Noise**: Sample least significant bits of raw PCM microphone input.
   - **Timestamp Jitter**: Use high-resolution timing differences for hardware-level randomness.

2. **Random Sampling & Mixing**

   - Capture a fixed duration of audio and video (default 20 seconds).
   - Randomly pick sample points to avoid static or predictable data.
   - Hash each combined sample (SHA-512) to fold in all sources securely.

3. **Seed & DRBG Initialization**

   - Condense hashed samples into a 256-bit seed.
   - Seed an HMAC-based DRBG for forward security and non-invertibility.
   - Derive keys (AES-128, AES-256, RSA-2048/4096, self-signed SSL) from DRBG output.

4. **Zero-Trust Ready**

   - **Open Source**: All algorithms and code are public.
   - **Ephemeral State**: Raw entropy and DRBG state exist only in memory and are zeroed after use.
   - **Cross-Platform**: Simple API methods, callable from any language that supports shared libraries.

By blending multiple physical noise sources, CamCrypt ensures that reconstructing the seed and any generated keys requires replicating the exact environmental conditions, which is computationally infeasible.

---

## Library Status & Roadmap

**Proof of Concept** available now:

- Standalone Python script for audio/video capture.
- Core modules for entropy extraction and DRBG seeding.
- Hardcoded methods to generate:
  - AES-128 and AES-256 symmetric keys
  - RSA-2048 and RSA-4096 key pairs
  - Self-signed X.509 certificates

**Next Steps:**

- Refactor into a pip-installable package (`camcrypt`).
- Implement support for major languages and systems. 
---

## License

This project is released under the MIT License. See the [LICENSE](LICENSE) file for details.

