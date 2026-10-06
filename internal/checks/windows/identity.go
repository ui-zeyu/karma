// identity account surface: local users and administrator group members.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

// One line per user: name, enabled state, last logon, description; the description often hides operational hints.
const localUsersScript = `Get-LocalUser -ErrorAction SilentlyContinue | Sort-Object Name | ForEach-Object { $ll = ''; if ($_.LastLogon) { $ll = $_.LastLogon.ToString('yyyy-MM-dd HH:mm:ss') }; $en = 'disabled'; if ($_.Enabled) { $en = 'enabled' }; $_.Name + '  ' + $en + '  ' + $ll + '  ' + $_.Description }`

// net user does not show accounts ending in $; Get-LocalUser does, and an enabled $ account is
// a classic hiding trick.
const hiddenUserRule = `(?i)^\S*\$\s+enabled`

// The Administrators group is read by well-known SID, immune to localized group
// names, and the machine's own account is dropped: on a domain-joined host the
// computer account (DOMAIN\PC$) is a member by default, and it is the host
// itself rather than a hidden account. An enabled $ account is the finding this
// check exists for, and one that is not this machine still lights the rule.
const adminGroupScript = `$g = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue
if ($g) {
  $machine = $env:COMPUTERNAME + '$'
  Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | Where-Object { $_.Name.Split('\')[-1] -ne $machine } | ForEach-Object { $_.Name + '  ' + $_.PrincipalSource }
}`

const adminDollarRule = `(?i)^\S*\$\s`

// IdentityChecks is the account aspect.
var IdentityChecks = []*model.Check{
	define.WindowsCheck("local-users", "Local Users", model.AspectIdentity,
		[]model.Step{{PSProbe("localuser", localUsersScript)}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("local-user-hidden", hiddenUserRule, model.High,
					"enabled account ending in $ (account-hiding trick)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("admin-group", "Administrator Group Members", model.AspectIdentity,
		[]model.Step{{PSProbe("localgroup", adminGroupScript)}},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("admin-group-dollar", adminDollarRule, model.Medium,
					"$ account in the Administrators group"),
				define.KeywordRule,
			},
		}),
}
