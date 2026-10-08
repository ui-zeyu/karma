// chroma lexical surface: bash and powershell through alecthomas/chroma.

package syntax

import (
	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/lexers"
)

// chromaLexers is fetched once at package level: Tokenise builds fresh state per
// call, so nothing is shared across calls or goroutines.
var chromaLexers = map[string]chroma.Lexer{
	"bash":       lexers.Get("bash"),
	"powershell": lexers.Get("powershell"),
}

// chromaLineStyler is the chroma lexical surface: Comment dimmed, Keyword dark
// magenta, String and Number blue. Syntax colors stay low-saturation so they do
// not compete with the severity colors.
func chromaLineStyler(lexer chroma.Lexer) lineStyler {
	return func(line string) []paintSpan {
		if lexer == nil {
			return nil
		}
		iterator, err := lexer.Tokenise(nil, line)
		if err != nil {
			return nil
		}
		var spans []paintSpan
		offset := 0
		for _, token := range iterator.Tokens() {
			if st, ok := chromaTokenStyle(token.Type); ok && token.Value != "" {
				spans = append(spans, paintSpan{Start: offset, End: offset + len(token.Value), Style: st})
			}
			offset += len(token.Value)
		}
		return spans
	}
}

func chromaTokenStyle(t chroma.TokenType) (style, bool) {
	switch {
	case t.InCategory(chroma.Comment) || t == chroma.Comment:
		return commentColor, true
	case t.InCategory(chroma.Keyword) || t == chroma.Keyword || t == chroma.NameBuiltin:
		// A cmdlet (Invoke-Expression and friends) is a key verb in a history
		// command, so it shares the keyword color
		return keywordColor, true
	case t.InCategory(chroma.LiteralString) || t.InCategory(chroma.LiteralNumber):
		return stringColor, true
	}
	return style{}, false
}
