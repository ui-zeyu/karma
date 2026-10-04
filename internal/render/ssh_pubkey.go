// ssh-pubkey pseudo-lexer: "type base64 comment" rows.

package render

var sshPubKey = compile(`(?P<type>(?:sk-)?(?:ecdsa-sha2-nistp\d+|ssh-(?:rsa|dss|ed25519))(?:@openssh\.com)?)` +
	`\s+(?P<blob>[A-Za-z0-9+/]{20,}={0,2})`)

func styleSSHPublicKey(line string) []Span {
	// "type base64 comment" form (possibly with an options prefix): the key type
	// is lit and the base64 blob is dimmed — that string is unreadable noise;
	// the comment stays at the default color
	matched := sshPubKey.FindStringSubmatchIndex(line)
	if matched == nil {
		return nil
	}
	typeIdx := sshPubKey.SubexpIndex("type") * 2
	blobIdx := sshPubKey.SubexpIndex("blob") * 2
	if typeIdx < 0 || blobIdx < 0 {
		return nil
	}
	return []Span{
		{Start: matched[typeIdx], End: matched[typeIdx+1], Style: style{fg: "4"}},
		{Start: matched[blobIdx], End: matched[blobIdx+1], Style: dimStyle},
	}
}
