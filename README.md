
Features:
 * Safe, fast defaults. 
    * Same file encoded with same password will produce different bytes every time.
    * Authenticated encryption all the way through
    * No nonce problems.
    * Uses recommended primitives from libsodium with managed nonces.
 * Very fast: reading, writing and encoding in separate threads; some codecs allow multithreaded encoding.
 * Command line friendly
 * Convenient command line interface: works with streams
 * Forward-compatible: All encoding parameters are explicitly saved to header.
 * Small, no dependencies.
 * Low storage overhead (~50 bytes + 16 bytes every 1 Mb)
 * Practically unlimited file size (which?)
 * 
 
 
License: MIT.

Dependency Licenses:
 * Prost (Apache 2)
 * Libsodium (ISC)
 * What else? 
 