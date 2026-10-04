// Selector parsing: platform names, aspect names, or check ids, with commas and
// spaces equivalent. local, ssh, and list share this parser.

package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/samber/lo"

	"karma/internal/model"
)

// SelectorTokens expands one command-line word into individual selector words,
// with commas and spaces equivalent.
func SelectorTokens(raw []string) []string {
	words := lo.FlatMap(raw, func(item string, _ int) []string {
		return strings.Fields(strings.ReplaceAll(item, ",", " "))
	})
	return lo.Compact(words)
}

// SelectChecks returns the selected checks in catalog order; a platform name
// expands to every check of that platform and an aspect name to every check of
// that aspect.
//
// The word order does not affect the output order; an empty slice means all of
// them. A platform or aspect word counts only if this catalog carries it
// (selecting windows on the Linux catalog reports it as unknown), and an unknown
// word returns an error carrying close names for the caller to show.
func SelectChecks(tokens []string, catalog []*model.Check) ([]*model.Check, error) {
	wanted := SelectorTokens(tokens)
	if len(wanted) == 0 {
		return catalog, nil
	}

	knownIDs := lo.SliceToMap(catalog, func(c *model.Check) (string, bool) { return c.ID, true })
	catalogAspects := lo.SliceToMap(catalog, func(c *model.Check) (model.Aspect, bool) { return c.Aspect, true })
	catalogPlatforms := lo.SliceToMap(catalog, func(c *model.Check) (model.Platform, bool) { return c.Platform, true })
	names := slices.Concat(model.PlatformNames(), model.AspectNames(), lo.Keys(knownIDs))
	slices.Sort(names)

	wantedIDs := map[string]bool{}
	aspects := map[model.Aspect]bool{}
	platforms := map[model.Platform]bool{}
	for _, word := range wanted {
		aspect, isAspect := model.AspectByName(word)
		platform, isPlatform := model.PlatformByName(word)
		switch {
		case isPlatform && catalogPlatforms[platform]:
			platforms[platform] = true
		case isAspect && catalogAspects[aspect]:
			aspects[aspect] = true
		case knownIDs[word]:
			wantedIDs[word] = true
		default:
			return nil, fmt.Errorf("unknown selector %q%s", word, closeMatches(word, names))
		}
	}
	return lo.Filter(catalog, func(c *model.Check, _ int) bool {
		return wantedIDs[c.ID] || aspects[c.Aspect] || platforms[c.Platform]
	}), nil
}
