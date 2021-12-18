# YBCrypto_Module

This code is provided along with KCMVP (Korea Cryptographic Module. Validation Program) assignment for “Security Implementation Development Methodology”, a first-year graduate course.

If you have any examples that you can add or anything you think should be improved, please send an email to <darania@kookmin.ac.kr>. I'm planning to expand this collection with the various cryptographic algorithms that can be implemented into KCMVP. Ultimately, I'm planning to unify implementations for multiple OS in batches. If you have input about what should be covered, I'd be grateful for any input.

## what my code is trying to achieve

- It aims to organically design the cryptographic module in a broad framework without focusing on the cryptographic algorithm itself. This code is written in a way that is easy to read and understand.

- In addition to passing the CAVP (Cryptographic Algorithm Validation Program) test, it is implemented to be safe for vulnerability analysis techniques such as metamorphic-testing and fuzzing methods.

- We consider all environments, including embedded devices and various operating systems. In addition, a public key-based cryptographic system including PQC (Post-Quantum Cryptography) will be added in the future.


## Structure

|Chapter|Algorithm|Security|
|-----|:---:|:---:|
|Block Cipher|ARIA/AES|128/192/256|
|HashFunction|SHA/SHA3|256|
|Message Authentication |HMAC|SHA256/SHA3_256|
|Deterministic Random Bit Generator |CTR_DRBG|ARIA|

There are 4 folders (genLibrary, genMAC, test_YBCrypto, cavp_YBCrypto) for each operating system. This code can be basically run in macOS, Linux, and Windows environments. In the case of macOS, it works not only on intel-core but also on apple-silicon based M1 chips. Code for Linux environment works on Debian buster version and Ubuntu (18/20.04). In particular, it can be built on the ARM Cortex-A 50-/70- series and can also be run on NVIDIA's Jetson board with ARMv8.2. For windows, this code provides the VS (Visual Studio) version.

- genLibrary is all about this little project. Create a dynamic library of YBCrypto.so/dylib/dll.
