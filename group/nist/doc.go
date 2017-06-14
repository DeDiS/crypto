// Package nist implements cryptographic groups and ciphersuites
// based on the NIST standards, using Go's built-in crypto library.
// Since that package does not implements constant time arithmetic operations
// yet, it must be compiled with the "vartime" compilation flag.

// +build vartime

package nist
