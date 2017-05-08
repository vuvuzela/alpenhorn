// Copyright 2016 David Lazar. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toml

// Parts of this code were inspired by:
// https://github.com/pelletier/go-toml and https://github.com/BurntSushi/toml

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// item represents a token or text string returned from the scanner.
type item struct {
	typ itemType // The type of this item.
	pos pos      // The starting position, in bytes, of this item in the input string.
	val string   // The value of this item.
}

// itemType identifies the type of lex items.
type itemType int

func (itype itemType) String() string {
	switch itype {
	case itemError:
		return "Error"
	case itemBool:
		return "Bool"
	case itemKey:
		return "Key"
	case itemLeftBracket:
		return "LeftBracket"
	case itemRightBracket:
		return "RightBracket"
	case itemLeftDoubleBracket:
		return "LeftDoubleBracket"
	case itemRightDoubleBracket:
		return "RightDoubleBracket"
	case itemEqual:
		return "Equal"
	case itemComma:
		return "Comma"
	case itemNumber:
		return "Number"
	case itemString:
		return "String"
	case eof:
		return "EOF"
	}
	panic(fmt.Sprintf("BUG: Unknown type '%d'.", int(itype)))
}

func (item item) String() string {
	return fmt.Sprintf("(%d, %s, %q)", item.pos, item.typ, item.val)
}

const eof = 0

// stateFn represents the state of the scanner as a function that returns the next state.
type stateFn func(*lexer) stateFn

type pos int

// lexer holds the state of the scanner.
type lexer struct {
	name    string    // the name of the input; used only for error reports
	input   string    // the string being scanned
	state   stateFn   // the next lexing function to enter
	pos     pos       // current position in the input
	start   pos       // start position of this item
	width   pos       // width of last rune read from input
	lastPos pos       // position of most recent item returned by nextItem
	items   chan item // channel of scanned items

	arrayDepth          int
	expectDoubleBracket bool

	err    error
	result map[string]interface{}
}

// next returns the next rune in the input.
func (l *lexer) next() rune {
	if int(l.pos) >= len(l.input) {
		l.width = 0
		return eof
	}
	r, w := utf8.DecodeRuneInString(l.input[l.pos:])
	l.width = pos(w)
	l.pos += l.width
	return r
}

// peek returns but does not consume the next rune in the input.
func (l *lexer) peek() rune {
	r := l.next()
	l.backup()
	return r
}

// backup steps back one rune. Can only be called once per call of next.
func (l *lexer) backup() {
	l.pos -= l.width
}

// emit passes an item back to the client.
func (l *lexer) emit(t itemType) {
	l.items <- item{t, l.start, l.input[l.start:l.pos]}
	l.start = l.pos
}

// ignore skips over the pending input before this point.
func (l *lexer) ignore() {
	l.start = l.pos
}

// accept consumes the next rune if it's from the valid set.
func (l *lexer) accept(valid string) bool {
	if strings.ContainsRune(valid, l.next()) {
		return true
	}
	l.backup()
	return false
}

// acceptRun consumes a run of runes from the valid set.
func (l *lexer) acceptRun(valid string) {
	for strings.ContainsRune(valid, l.next()) {
	}
	l.backup()
}

// lineNumber reports which line we're on, based on the position of
// the previous item returned by nextItem. Doing it this way
// means we don't have to worry about peek double counting.
func (l *lexer) lineNumber() int {
	return 1 + strings.Count(l.input[:l.lastPos], "\n")
}

// errorf returns an error token and terminates the scan by passing
// back a nil pointer that will be the next state, terminating l.nextItem.
func (l *lexer) errorf(format string, args ...interface{}) stateFn {
	l.items <- item{itemError, l.start, fmt.Sprintf(format, args...)}
	return nil
}

// nextItem returns the next item from the input.
// Called by the parser, not in the lexing goroutine.
func (l *lexer) nextItem() item {
	item := <-l.items
	l.lastPos = item.pos
	return item
}

// lex creates a new scanner for the input string.
func lex(name, input string, start stateFn) *lexer {
	l := &lexer{
		name:  name,
		input: input,
		items: make(chan item),
	}
	go l.run(start)
	return l
}

// run runs the state machine for the lexer.
func (l *lexer) run(start stateFn) {
	for l.state = start; l.state != nil; {
		l.state = l.state(l)
	}
	close(l.items)
}

// state functions

func (l *lexer) skipWhitespace(skipNewlines bool) {
	for {
		r := l.next()
		if r == ' ' || r == '\t' || (skipNewlines && r == '\n') {
			l.ignore()
		} else {
			l.backup()
			return
		}
	}
}

func lexTableBody(l *lexer) stateFn {
	l.skipWhitespace(true)
	for {
		r := l.next()
		switch {
		case r == '#':
			return lexComment
		case r == '[':
			if l.peek() == '[' {
				// array [[
				l.next()
				l.emit(itemLeftDoubleBracket)
				l.expectDoubleBracket = true
			} else {
				l.emit(itemLeftBracket)
				l.expectDoubleBracket = false
			}
			return lexTableNameStart
		case r == eof:
			if l.pos > l.start {
				return l.errorf("unexpected EOF")
			}
			l.emit(eof)
			return nil
		default:
			l.backup()
			return lexKeyStart
		}
	}
}

func lexComment(l *lexer) stateFn {
	for {
		r := l.next()
		l.ignore()
		if r == '\n' || r == eof {
			return lexTableBody(l)
		}
	}
}

func isAlphaNumeric(r rune) bool {
	return (r >= 'a' && r <= 'z') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= '0' && r <= '9') ||
		r == '-' || r == '_'

}

func lexTableNameStart(l *lexer) stateFn {
	l.skipWhitespace(false)
	r := l.peek()
	switch {
	case isAlphaNumeric(r):
		l.lexBareKey()
		return lexTableNameEnd
	default:
		return l.errorf("unexpected character in table name: %q", r)
	}
}

func (l *lexer) lexBareKey() {
	for {
		r := l.next()
		if !isAlphaNumeric(r) {
			l.backup()
			break
		}
	}
	l.emit(itemKey)
}

func lexTableNameEnd(l *lexer) stateFn {
	l.skipWhitespace(false)
	r := l.next()
	switch r {
	case '.':
		l.ignore()
		return lexTableNameStart
	case ']':
		if l.expectDoubleBracket {
			if rr := l.next(); rr == ']' {
				l.emit(itemRightDoubleBracket)
			} else {
				return l.errorf("expecting ']' got %q", rr)
			}
		} else {
			l.emit(itemRightBracket)
		}
		return lexTableBody
	default:
		return l.errorf("unexpected character in table name: %q", r)
	}
}

func lexKeyStart(l *lexer) stateFn {
	r := l.peek()
	switch {
	case isAlphaNumeric(r):
		l.lexBareKey()
		return lexKeyEnd
	default:
		return l.errorf("unexpected character in key name start: %#U", r)
	}
}

func lexKeyEnd(l *lexer) stateFn {
	l.skipWhitespace(false)
	r := l.next()
	switch r {
	case '=':
		l.emit(itemEqual)
		return lexValue
	case eof:
		return l.errorf("unexpected EOF: expected '=' character")
	default:
		return l.errorf("expected '=' character but got: %#U", r)
	}
}

func isDigit(r rune) bool {
	return r >= '0' && r <= '9'
}

func (l *lexer) tryString(s string) bool {
	if strings.HasPrefix(l.input[l.pos:], s) {
		l.pos += pos(len(s))
		l.width = pos(len(s))
		return true
	}
	return false
}

func lexValue(l *lexer) stateFn {
	for {
		r := l.next()
		switch r {
		case ' ', '\t':
			l.ignore()
			continue
		case '[':
			l.arrayDepth++
			l.emit(itemLeftBracket)
			continue
		case ']':
			l.arrayDepth--
			l.emit(itemRightBracket)
			continue
		case ',':
			l.emit(itemComma)
			continue
		case '=':
			l.emit(itemEqual)
			continue
		case '"':
			return lexQuote
		case '#':
			return lexComment
		case '\n':
			// TODO check array depth
			l.ignore()
			return lexTableBody
		case eof:
			l.emit(eof)
			return nil
		}

		l.backup()
		if r == '+' || r == '-' || isDigit(r) {
			return lexNumber
		}

		if l.tryString("true") || l.tryString("false") {
			l.emit(itemBool)
			continue
		}

		if isAlphaNumeric(r) {
			return lexKeyStart
		}

		return l.errorf("unexpected character when trying to lex value: %#U", r)
	}
}

// copied from text/template/parse/lex.go
// lexQuote scans a quoted string.
func lexQuote(l *lexer) stateFn {
Loop:
	for {
		switch l.next() {
		case '\\':
			if r := l.next(); r != eof && r != '\n' {
				break
			}
			fallthrough
		case eof, '\n':
			return l.errorf("unterminated quoted string")
		case '"':
			break Loop
		}
	}
	l.emit(itemString)
	return lexValue
}

func lexNumber(l *lexer) stateFn {
	if !l.scanNumber() {
		return l.errorf("bad number syntax: %q", l.input[l.start:l.pos])
	}
	l.emit(itemNumber)
	return lexValue
}

// copied from text/template/parse/lex.go
func (l *lexer) scanNumber() bool {
	// Optional leading sign.
	l.accept("+-")
	digits := "0123456789"
	l.acceptRun(digits)
	if l.accept(".") {
		l.acceptRun(digits)
	}
	if l.accept("eE") {
		l.accept("+-")
		l.acceptRun("0123456789")
	}
	// Next thing mustn't be alphanumeric.
	if isAlphaNumeric(l.peek()) {
		l.next()
		return false
	}
	return true
}

func (l *lexer) Error(e string) {
	l.err = fmt.Errorf("toml parse error at line %d: %s", l.lineNumber(), e)
}

// Lex is used by the yacc-generated parser to fetch the next Lexeme.
func (l *lexer) Lex(lval *yySymType) int {
	i := l.nextItem()
	if i.typ == itemError {
		l.err = fmt.Errorf("toml lexical error at line %d: %s", l.lineNumber(), i.val)
		return 0
	}
	*lval = yySymType{str: i.val, line: l.lineNumber()}
	return int(i.typ)
}
