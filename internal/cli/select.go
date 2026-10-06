// Selector parsing: platform names, aspect names, or check ids, with commas and
// spaces equivalent; a leading ! on a word excludes it instead. local, ssh, and
// list share this parser.

package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/samber/lo"

	"karma/internal/model"
)

// SelectorTokens expands one command-line word into individual selector words,
// with commas and spaces equivalent.
func SelectorTokens(raw []string) []string {
	var words []string
	for _, item := range raw {
		words = append(words, strings.Fields(strings.ReplaceAll(item, ",", " "))...)
	}
	return words
}

// SelectChecks returns the selected checks in catalog order; a platform name
// expands to every check of that platform and an aspect name to every check of
// that aspect. A leading ! on a word removes those checks instead — from what
// the other words selected, or from the whole catalog when every word is an
// exclusion.
//
// The word order does not affect the output order; no words at all means all
// of them. A platform or aspect word counts only if this catalog carries it
// (selecting windows on the Linux catalog reports it as unknown), and an
// unknown word returns an error carrying close names for the caller to show.
// Exclusion wins over selection, and a word list that would leave no checks
// is an error rather than a silent empty report.
func SelectChecks(tokens []string, catalog []*model.Check) ([]*model.Check, error) {
	words := SelectorTokens(tokens)
	if len(words) == 0 {
		return catalog, nil
	}
	var include, exclude []string
	for _, word := range words {
		name, excluded := strings.CutPrefix(word, "!")
		if excluded {
			if name == "" {
				return nil, fmt.Errorf(`an exclusion needs a word after "!": %q`, word)
			}
			exclude = append(exclude, name)
		} else {
			include = append(include, word)
		}
	}
	base := catalog
	if len(include) > 0 {
		wanted, err := resolveWords(include, catalog, "selector")
		if err != nil {
			return nil, err
		}
		base = lo.Filter(catalog, func(c *model.Check, _ int) bool { return wanted.matches(c) })
	}
	if len(exclude) == 0 {
		return base, nil
	}
	dropped, err := resolveWords(exclude, catalog, "exclusion")
	if err != nil {
		return nil, err
	}
	kept := lo.Filter(base, func(c *model.Check, _ int) bool { return !dropped.matches(c) })
	if len(kept) == 0 {
		return nil, fmt.Errorf("the words left no checks: every one was excluded")
	}
	return kept, nil
}

// resolved is one parsed word list: the check ids, aspects, and platforms the
// words name, all validated against one catalog.
type resolved struct {
	ids       map[string]bool
	aspects   map[model.Aspect]bool
	platforms map[model.Platform]bool
}

// matches reports whether the check is named by the resolved words.
func (r resolved) matches(c *model.Check) bool {
	return r.ids[c.ID] || r.aspects[c.Aspect] || r.platforms[c.Platform]
}

// resolveWords parses selector or exclusion words against the catalog, with
// the same comma/space equivalence and the same unknown-word error (labeled
// with what, so a typo says which list it came from).
func resolveWords(tokens []string, catalog []*model.Check, what string) (resolved, error) {
	knownIDs := lo.SliceToMap(catalog, func(c *model.Check) (string, bool) { return c.ID, true })
	catalogAspects := lo.SliceToMap(catalog, func(c *model.Check) (model.Aspect, bool) { return c.Aspect, true })
	catalogPlatforms := lo.SliceToMap(catalog, func(c *model.Check) (model.Platform, bool) { return c.Platform, true })
	names := slices.Concat(model.PlatformNames(), model.AspectNames(), slices.Collect(maps.Keys(knownIDs)))
	slices.Sort(names)

	words := resolved{
		ids:       map[string]bool{},
		aspects:   map[model.Aspect]bool{},
		platforms: map[model.Platform]bool{},
	}
	for _, word := range SelectorTokens(tokens) {
		aspect, isAspect := model.AspectByName(word)
		platform, isPlatform := model.PlatformByName(word)
		switch {
		case isPlatform && catalogPlatforms[platform]:
			words.platforms[platform] = true
		case isAspect && catalogAspects[aspect]:
			words.aspects[aspect] = true
		case knownIDs[word]:
			words.ids[word] = true
		default:
			return resolved{}, fmt.Errorf("unknown %s %q%s", what, word, closeMatches(word, names))
		}
	}
	return words, nil
}
