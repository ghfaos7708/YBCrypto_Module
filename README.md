# YBCrypto_Module

This code is provided along with KCMVP (Korea Cryptographic Module. Validation Program) assignment for “Security Implementation Development Methodology”, a first-year graduate course.

If you have any examples that you can add or anything you think should be improved, please send an email to apple. I'm planning to expand this collection with the various cryptographic algorithms that can be implemented into KCMVP. Ultimately, I'm planning to unify implementations for multiple OS in batches. If you have input about what should be covered, I'd be grateful for any input.

-what my code is trying to achieve

It aims to organically design the cryptographic module in a broad framework without focusing on the cryptographic algorithm itself. This code is written in a way that is easy to read and understand.

In addition to passing the CAVP (Cryptographic Algorithm Validation Program) test, it is implemented to be safe for vulnerability analysis techniques such as metamorphic-testing and fuzzing methods.

We consider all environments, including embedded devices and various operating systems. In addition, a public key-based cryptographic system including PQC (Post-Quantum Cryptography) will be added in the future.
