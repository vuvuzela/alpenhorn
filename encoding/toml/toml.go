//go:generate -command yacc goyacc
//go:generate yacc -o parser.go parser.y

/*
Package toml implements Tom's Obvious Minimal Language.

This package implements a subset of the TOML specification that's useful
for Alpenhorn config files.  We built our own TOML package so that we
could have control over how certain types are encoded.  For example,
[]byte can be encoded as a base32 string.

This package does not yet provide an encoder since most configs in Alpenhorn
can be generated using a template.
*/
package toml
