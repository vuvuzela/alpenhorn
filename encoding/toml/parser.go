//line parser.y:2
package toml

import __yyfmt__ "fmt"

//line parser.y:2
import (
	"fmt"
	"strconv"
	"strings"
)

type entry struct {
	key string
	val interface{}
}

type table struct {
	isArray bool
	keys    []string
	entries map[string]interface{}
}

//line parser.y:22
type yySymType struct {
	yys     int
	str     string
	line    int
	entries map[string]interface{}
	entry   entry
	value   interface{}
	values  []interface{}
	table   table
	tables  map[string]interface{}
	keys    []string
}

const itemError = 57346
const itemBool = 57347
const itemKey = 57348
const itemLeftBracket = 57349
const itemLeftDoubleBracket = 57350
const itemRightBracket = 57351
const itemRightDoubleBracket = 57352
const itemComma = 57353
const itemEqual = 57354
const itemNumber = 57355
const itemString = 57356

var yyToknames = [...]string{
	"$end",
	"error",
	"$unk",
	"itemError",
	"itemBool",
	"itemKey",
	"itemLeftBracket",
	"itemLeftDoubleBracket",
	"itemRightBracket",
	"itemRightDoubleBracket",
	"itemComma",
	"itemEqual",
	"itemNumber",
	"itemString",
}
var yyStatenames = [...]string{}

const yyEofCode = 1
const yyErrCode = 2
const yyInitialStackSize = 16

//line yacctab:1
var yyExca = [...]int{
	-1, 1,
	1, -1,
	-2, 0,
}

const yyPrivate = 57344

const yyLast = 28

var yyAct = [...]int{

	13, 2, 14, 25, 17, 26, 19, 9, 19, 18,
	15, 16, 20, 7, 8, 10, 5, 11, 22, 1,
	23, 6, 24, 3, 12, 21, 4, 27,
}
var yyPact = [...]int{

	-1000, -1000, 10, 6, -1000, -5, -1000, 11, 11, -3,
	0, -1000, 2, -1000, -1000, -1000, -1000, -3, -1000, -1000,
	-1000, -6, -1000, 10, 10, -1000, -3, -1000,
}
var yyPgo = [...]int{

	0, 26, 1, 0, 25, 23, 21, 15, 19,
}
var yyR1 = [...]int{

	0, 8, 5, 5, 6, 6, 7, 7, 2, 2,
	1, 3, 3, 3, 3, 4, 4,
}
var yyR2 = [...]int{

	0, 2, 0, 2, 4, 4, 1, 2, 0, 2,
	3, 1, 1, 1, 3, 1, 3,
}
var yyChk = [...]int{

	-1000, -8, -2, -5, -1, 6, -6, 7, 8, 12,
	-7, 6, -7, -3, 5, 13, 14, 7, 9, 6,
	10, -4, -3, -2, -2, 9, 11, -3,
}
var yyDef = [...]int{

	8, -2, 2, 1, 9, 0, 3, 0, 0, 0,
	0, 6, 0, 10, 11, 12, 13, 0, 8, 7,
	8, 0, 15, 4, 5, 14, 0, 16,
}
var yyTok1 = [...]int{

	1,
}
var yyTok2 = [...]int{

	2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
	12, 13, 14,
}
var yyTok3 = [...]int{
	0,
}

var yyErrorMessages = [...]struct {
	state int
	token int
	msg   string
}{}

//line yaccpar:1

/*	parser for yacc output	*/

var (
	yyDebug        = 0
	yyErrorVerbose = false
)

type yyLexer interface {
	Lex(lval *yySymType) int
	Error(s string)
}

type yyParser interface {
	Parse(yyLexer) int
	Lookahead() int
}

type yyParserImpl struct {
	lval  yySymType
	stack [yyInitialStackSize]yySymType
	char  int
}

func (p *yyParserImpl) Lookahead() int {
	return p.char
}

func yyNewParser() yyParser {
	return &yyParserImpl{}
}

const yyFlag = -1000

func yyTokname(c int) string {
	if c >= 1 && c-1 < len(yyToknames) {
		if yyToknames[c-1] != "" {
			return yyToknames[c-1]
		}
	}
	return __yyfmt__.Sprintf("tok-%v", c)
}

func yyStatname(s int) string {
	if s >= 0 && s < len(yyStatenames) {
		if yyStatenames[s] != "" {
			return yyStatenames[s]
		}
	}
	return __yyfmt__.Sprintf("state-%v", s)
}

func yyErrorMessage(state, lookAhead int) string {
	const TOKSTART = 4

	if !yyErrorVerbose {
		return "syntax error"
	}

	for _, e := range yyErrorMessages {
		if e.state == state && e.token == lookAhead {
			return "syntax error: " + e.msg
		}
	}

	res := "syntax error: unexpected " + yyTokname(lookAhead)

	// To match Bison, suggest at most four expected tokens.
	expected := make([]int, 0, 4)

	// Look for shiftable tokens.
	base := yyPact[state]
	for tok := TOKSTART; tok-1 < len(yyToknames); tok++ {
		if n := base + tok; n >= 0 && n < yyLast && yyChk[yyAct[n]] == tok {
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}
	}

	if yyDef[state] == -2 {
		i := 0
		for yyExca[i] != -1 || yyExca[i+1] != state {
			i += 2
		}

		// Look for tokens that we accept or reduce.
		for i += 2; yyExca[i] >= 0; i += 2 {
			tok := yyExca[i]
			if tok < TOKSTART || yyExca[i+1] == 0 {
				continue
			}
			if len(expected) == cap(expected) {
				return res
			}
			expected = append(expected, tok)
		}

		// If the default action is to accept or reduce, give up.
		if yyExca[i+1] != 0 {
			return res
		}
	}

	for i, tok := range expected {
		if i == 0 {
			res += ", expecting "
		} else {
			res += " or "
		}
		res += yyTokname(tok)
	}
	return res
}

func yylex1(lex yyLexer, lval *yySymType) (char, token int) {
	token = 0
	char = lex.Lex(lval)
	if char <= 0 {
		token = yyTok1[0]
		goto out
	}
	if char < len(yyTok1) {
		token = yyTok1[char]
		goto out
	}
	if char >= yyPrivate {
		if char < yyPrivate+len(yyTok2) {
			token = yyTok2[char-yyPrivate]
			goto out
		}
	}
	for i := 0; i < len(yyTok3); i += 2 {
		token = yyTok3[i+0]
		if token == char {
			token = yyTok3[i+1]
			goto out
		}
	}

out:
	if token == 0 {
		token = yyTok2[1] /* unknown char */
	}
	if yyDebug >= 3 {
		__yyfmt__.Printf("lex %s(%d)\n", yyTokname(token), uint(char))
	}
	return char, token
}

func yyParse(yylex yyLexer) int {
	return yyNewParser().Parse(yylex)
}

func (yyrcvr *yyParserImpl) Parse(yylex yyLexer) int {
	var yyn int
	var yyVAL yySymType
	var yyDollar []yySymType
	_ = yyDollar // silence set and not used
	yyS := yyrcvr.stack[:]

	Nerrs := 0   /* number of errors */
	Errflag := 0 /* error recovery flag */
	yystate := 0
	yyrcvr.char = -1
	yytoken := -1 // yyrcvr.char translated into internal numbering
	defer func() {
		// Make sure we report no lookahead when not parsing.
		yystate = -1
		yyrcvr.char = -1
		yytoken = -1
	}()
	yyp := -1
	goto yystack

ret0:
	return 0

ret1:
	return 1

yystack:
	/* put a state and value onto the stack */
	if yyDebug >= 4 {
		__yyfmt__.Printf("char %v in %v\n", yyTokname(yytoken), yyStatname(yystate))
	}

	yyp++
	if yyp >= len(yyS) {
		nyys := make([]yySymType, len(yyS)*2)
		copy(nyys, yyS)
		yyS = nyys
	}
	yyS[yyp] = yyVAL
	yyS[yyp].yys = yystate

yynewstate:
	yyn = yyPact[yystate]
	if yyn <= yyFlag {
		goto yydefault /* simple state */
	}
	if yyrcvr.char < 0 {
		yyrcvr.char, yytoken = yylex1(yylex, &yyrcvr.lval)
	}
	yyn += yytoken
	if yyn < 0 || yyn >= yyLast {
		goto yydefault
	}
	yyn = yyAct[yyn]
	if yyChk[yyn] == yytoken { /* valid shift */
		yyrcvr.char = -1
		yytoken = -1
		yyVAL = yyrcvr.lval
		yystate = yyn
		if Errflag > 0 {
			Errflag--
		}
		goto yystack
	}

yydefault:
	/* default state action */
	yyn = yyDef[yystate]
	if yyn == -2 {
		if yyrcvr.char < 0 {
			yyrcvr.char, yytoken = yylex1(yylex, &yyrcvr.lval)
		}

		/* look through exception table */
		xi := 0
		for {
			if yyExca[xi+0] == -1 && yyExca[xi+1] == yystate {
				break
			}
			xi += 2
		}
		for xi += 2; ; xi += 2 {
			yyn = yyExca[xi+0]
			if yyn < 0 || yyn == yytoken {
				break
			}
		}
		yyn = yyExca[xi+1]
		if yyn < 0 {
			goto ret0
		}
	}
	if yyn == 0 {
		/* error ... attempt to resume parsing */
		switch Errflag {
		case 0: /* brand new error */
			yylex.Error(yyErrorMessage(yystate, yytoken))
			Nerrs++
			if yyDebug >= 1 {
				__yyfmt__.Printf("%s", yyStatname(yystate))
				__yyfmt__.Printf(" saw %s\n", yyTokname(yytoken))
			}
			fallthrough

		case 1, 2: /* incompletely recovered error ... try again */
			Errflag = 3

			/* find a state where "error" is a legal shift action */
			for yyp >= 0 {
				yyn = yyPact[yyS[yyp].yys] + yyErrCode
				if yyn >= 0 && yyn < yyLast {
					yystate = yyAct[yyn] /* simulate a shift of "error" */
					if yyChk[yystate] == yyErrCode {
						goto yystack
					}
				}

				/* the current p has no shift on "error", pop stack */
				if yyDebug >= 2 {
					__yyfmt__.Printf("error recovery pops state %d\n", yyS[yyp].yys)
				}
				yyp--
			}
			/* there is no state on the stack with an error shift ... abort */
			goto ret1

		case 3: /* no shift yet; clobber input char */
			if yyDebug >= 2 {
				__yyfmt__.Printf("error recovery discards %s\n", yyTokname(yytoken))
			}
			if yytoken == yyEofCode {
				goto ret1
			}
			yyrcvr.char = -1
			yytoken = -1
			goto yynewstate /* try again in the same state */
		}
	}

	/* reduction by production yyn */
	if yyDebug >= 2 {
		__yyfmt__.Printf("reduce %v in:\n\t%v\n", yyn, yyStatname(yystate))
	}

	yynt := yyn
	yypt := yyp
	_ = yypt // guard against "declared and not used"

	yyp -= yyR2[yyn]
	// yyp is now the index of $0. Perform the default action. Iff the
	// reduced production is ε, $1 is possibly out of range.
	if yyp+1 >= len(yyS) {
		nyys := make([]yySymType, len(yyS)*2)
		copy(nyys, yyS)
		yyS = nyys
	}
	yyVAL = yyS[yyp+1]

	/* consult goto table to find next state */
	yyn = yyR1[yyn]
	yyg := yyPgo[yyn]
	yyj := yyg + yyS[yyp].yys + 1

	if yyj >= yyLast {
		yystate = yyAct[yyg]
	} else {
		yystate = yyAct[yyj]
		if yyChk[yystate] != -yyn {
			yystate = yyAct[yyg]
		}
	}
	// dummy call; replaced with literal code
	switch yynt {

	case 1:
		yyDollar = yyS[yypt-2 : yypt+1]
		//line parser.y:57
		{
			for k, v := range yyDollar[1].entries {
				yyDollar[2].tables[k] = v
			}
			yylex.(*lexer).result = yyDollar[2].tables
		}
	case 2:
		yyDollar = yyS[yypt-0 : yypt+1]
		//line parser.y:65
		{
			yyVAL.tables = make(map[string]interface{})
		}
	case 3:
		yyDollar = yyS[yypt-2 : yypt+1]
		//line parser.y:66
		{
			m := yyDollar[1].tables
			for i, key := range yyDollar[2].table.keys {
				v, ok := m[key]
				if !ok {
					if yyDollar[2].table.isArray && i == len(yyDollar[2].table.keys)-1 {
						array := make([]map[string]interface{}, 1)
						array[0] = make(map[string]interface{})
						m[key] = array
						m = array[0]
						continue
					}
					nestedMap := make(map[string]interface{})
					m[key] = nestedMap
					m = nestedMap
					continue
				}
				switch t := v.(type) {
				case map[string]interface{}:
					if yyDollar[2].table.isArray && i == len(yyDollar[2].table.keys)-1 {
						yylex.Error(fmt.Sprintf("key %q used as array but previously defined as map", key))
						return 1
					}
					m = t
				case []map[string]interface{}:
					if yyDollar[2].table.isArray && i == len(yyDollar[2].table.keys)-1 {
						arrayElement := make(map[string]interface{})
						t = append(t, arrayElement)
						m[key] = t
						m = arrayElement
					} else if !yyDollar[2].table.isArray && i == len(yyDollar[2].table.keys)-1 {
						yylex.Error(fmt.Sprintf("key %q used as map but previously defined as array", key))
						return 1
					} else {
						m = t[len(t)-1]
					}
				default:
					yylex.Error(fmt.Sprintf("key %q already defined as non-map value", key))
					return 1
				}
			}
			for k, v := range yyDollar[2].table.entries {
				m[k] = v
			}
		}
	case 4:
		yyDollar = yyS[yypt-4 : yypt+1]
		//line parser.y:113
		{
			yyVAL.table = table{
				isArray: false,
				keys:    yyDollar[2].keys,
				entries: yyDollar[4].entries,
			}
		}
	case 5:
		yyDollar = yyS[yypt-4 : yypt+1]
		//line parser.y:120
		{
			yyVAL.table = table{
				isArray: true,
				keys:    yyDollar[2].keys,
				entries: yyDollar[4].entries,
			}
		}
	case 6:
		yyDollar = yyS[yypt-1 : yypt+1]
		//line parser.y:129
		{
			yyVAL.keys = []string{yyDollar[1].str}
		}
	case 7:
		yyDollar = yyS[yypt-2 : yypt+1]
		//line parser.y:130
		{
			yyVAL.keys = append(yyDollar[1].keys, yyDollar[2].str)
		}
	case 8:
		yyDollar = yyS[yypt-0 : yypt+1]
		//line parser.y:133
		{
			yyVAL.entries = map[string]interface{}{}
		}
	case 9:
		yyDollar = yyS[yypt-2 : yypt+1]
		//line parser.y:134
		{
			yyDollar[1].entries[yyDollar[2].entry.key] = yyDollar[2].entry.val
			yyVAL.entries = yyDollar[1].entries
		}
	case 10:
		yyDollar = yyS[yypt-3 : yypt+1]
		//line parser.y:137
		{
			yyVAL.entry = entry{yyDollar[1].str, yyDollar[3].value}
		}
	case 11:
		yyDollar = yyS[yypt-1 : yypt+1]
		//line parser.y:140
		{
			if yyDollar[1].str == "true" {
				yyVAL.value = true
			} else {
				yyVAL.value = false
			}
		}
	case 12:
		yyDollar = yyS[yypt-1 : yypt+1]
		//line parser.y:141
		{
			if strings.Contains(yyDollar[1].str, ".") {
				n, err := strconv.ParseFloat(yyDollar[1].str, 64)
				if err != nil {
					yylex.Error(fmt.Sprintf("error parsing float: %s", err))
					return 1
				}
				yyVAL.value = n
			} else {
				n, err := strconv.ParseInt(yyDollar[1].str, 10, 64)
				if err != nil {
					yylex.Error(fmt.Sprintf("error parsing int: %s", err))
					return 1
				}
				yyVAL.value = n
			}
		}
	case 13:
		yyDollar = yyS[yypt-1 : yypt+1]
		//line parser.y:158
		{
			s, err := strconv.Unquote(yyDollar[1].str)
			if err != nil {
				yylex.Error(fmt.Sprintf("error parsing string: %s", err))
				return 1
			}
			yyVAL.value = s
		}
	case 14:
		yyDollar = yyS[yypt-3 : yypt+1]
		//line parser.y:166
		{
			yyVAL.value = yyDollar[2].values
		}
	case 15:
		yyDollar = yyS[yypt-1 : yypt+1]
		//line parser.y:169
		{
			yyVAL.values = []interface{}{yyDollar[1].value}
		}
	case 16:
		yyDollar = yyS[yypt-3 : yypt+1]
		//line parser.y:170
		{
			yyVAL.values = append(yyDollar[1].values, yyDollar[3].value)
		}
	}
	goto yystack /* stack new state and value */
}
