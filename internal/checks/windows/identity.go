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

// The Administrators group is fetched by well-known SID, immune to localized group names.
const adminGroupScript = `$g = Get-LocalGroup -SID 'S-1-5-32-544' -ErrorAction SilentlyContinue; if ($g) { Get-LocalGroupMember -Group $g -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '  ' + $_.PrincipalSource } }`

const adminDollarRule = `(?i)^\S*\$\s`

// IdentityChecks is the account aspect.
var IdentityChecks = []*model.Check{
	define.WindowsCheck("local-users", "Local Users", model.AspectIdentity,
		[]model.Probe{PSProbe("localuser", localUsersScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("local-user-hidden", hiddenUserRule, model.High,
					"enabled account ending in $ (account-hiding trick)"),
				define.KeywordRule,
			},
		}),
	define.WindowsCheck("admin-group", "Administrator Group Members", model.AspectIdentity,
		[]model.Probe{PSProbe("localgroup", adminGroupScript)},
		define.CheckOpt{
			Rules: []model.Rule{
				model.NewRule("admin-group-dollar", adminDollarRule, model.Medium,
					"$ account in the Administrators group"),
				define.KeywordRule,
			},
		}),
}
