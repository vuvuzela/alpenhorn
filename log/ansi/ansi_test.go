package ansi

import (
	"fmt"
	"testing"
)

func TestColors(t *testing.T) {
	for _, color := range AllColors {
		fmt.Printf("%s\t%s\n", Colorf(color, color), Colorf(color, color, Bold))
	}
}
