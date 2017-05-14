%{
package toml

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
%}

%union {
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

%token <str> itemError
%token <str> itemBool
%token <str> itemKey
%token <str> itemLeftBracket
%token <str> itemLeftDoubleBracket
%token <str> itemRightBracket
%token <str> itemRightDoubleBracket
%token <str> itemComma
%token <str> itemEqual
%token <str> itemNumber
%token <str> itemString

%type <entry>   entry
%type <entries> entries
%type <value>   value
%type <values>  values
%type <tables>  tables
%type <table>   table
%type <keys>    keys

%%

top
	: entries tables {
		for k, v := range $1 {
			$2[k] = v
		}
		yylex.(*lexer).result = $2
	}

tables
	: /**/ { $$ = make(map[string]interface{}) }
	| tables table {
		m := $1
		for i, key := range $2.keys {
			v, ok := m[key]
			if !ok {
				if $2.isArray && i == len($2.keys)-1 {
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
				if $2.isArray && i == len($2.keys)-1 {
					yylex.Error(fmt.Sprintf("key %q used as array but previously defined as map", key))
					return 1
				}
				m = t
			case []map[string]interface{}:
				if $2.isArray && i == len($2.keys)-1 {
					arrayElement := make(map[string]interface{})
					t = append(t, arrayElement)
					m[key] = t
					m = arrayElement
				} else if !$2.isArray && i == len($2.keys)-1 {
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
		for k, v := range $2.entries {
			m[k] = v
		}
	}

table
	: itemLeftBracket keys itemRightBracket entries {
		$$ = table{
			isArray: false,
			keys: $2,
			entries: $4,
		}
	}
	| itemLeftDoubleBracket keys itemRightDoubleBracket entries {
		$$ = table{
			isArray: true,
			keys: $2,
			entries: $4,
		}
	}

keys
	: itemKey { $$ = []string{$1} }
	| keys itemKey { $$ = append($1, $2) }

entries
	: /**/ { $$ = map[string]interface{}{} }
	| entries entry { $1[$2.key] = $2.val; $$ = $1 }

entry
	: itemKey itemEqual value { $$ = entry{$1, $3} }

value
	: itemBool { if $1 == "true" { $$ = true } else { $$ = false } }
	| itemNumber {
		if strings.Contains($1, ".") {
			n, err := strconv.ParseFloat($1, 64)
			if err != nil {
				yylex.Error(fmt.Sprintf("error parsing float: %s", err))
				return 1
			}
			$$ = n
		} else {
			n, err := strconv.ParseInt($1, 10, 64)
			if err != nil {
				yylex.Error(fmt.Sprintf("error parsing int: %s", err))
				return 1
			}
			$$ = n
		}
	}
	| itemString {
		s, err := strconv.Unquote($1)
		if err != nil {
			yylex.Error(fmt.Sprintf("error parsing string: %s", err))
			return 1
		}
		$$ = s
	}
	| itemLeftBracket values itemRightBracket { $$ = $2 }

values
	: value { $$ = []interface{}{$1} }
	| values itemComma value { $$ = append($1, $3) }
