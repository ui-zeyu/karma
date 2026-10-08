// devices peripherals: USB / SCSI storage devices and their plug times.
//
// Times come from the FILETIME of each device instance's Properties\{83da6326-...}\{0064,0066,0067}
// (installed, last connected, last removed); some property values are unreadable by regular users
// and left blank, complete only from an administrator's view. The one-line-per-device shape is
// assembled in the remote PowerShell, one enumeration root per section.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
	"karma/internal/powershell"
	"karma/internal/script"
)

// usbRoots are the three enumeration roots the check covers, one section each.
var usbRoots = []string{"USBSTOR", "SCSI", "USB"}

// usbHelper is the FILETIME formatter every root's call carries: each root is a
// PowerShell call of its own.
const usbHelper = `$tid = '{83da6326-97a6-4088-9453-a1923f573b29}'
function Fmt-Time($key) {
  $t = ''
  if (Test-Path $key) {
    try {
      $v = (Get-ItemProperty $key -ErrorAction Stop).'(default)'
      if ($v -and $v.Length -ge 8) {
        $t = [DateTime]::FromFileTime([BitConverter]::ToInt64($v, 0))
        $t = $t.ToString('yyyy-MM-dd HH:mm:ss')
      }
    } catch {}
  }
  $t
}`

// usbRead reads one enumeration root's devices, one row each.
func usbRead(root string) string {
	return script.Lines(usbHelper, `$base = 'HKLM:\SYSTEM\CurrentControlSet\Enum\`+root+`'
if (Test-Path $base) {
  Get-ChildItem $base -ErrorAction SilentlyContinue | ForEach-Object {
    $parent = $_
    Get-ChildItem $parent.PSPath -ErrorAction SilentlyContinue | ForEach-Object {
      $prop = Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue
      $name = if ($prop.FriendlyName) { $prop.FriendlyName } else { $prop.DeviceDesc }
      $props = Join-Path $_.PSPath 'Properties'
      $installed = Fmt-Time (Join-Path $props ($tid + '\0064'))
      $arrived = Fmt-Time (Join-Path $props ($tid + '\0066'))
      $removed = Fmt-Time (Join-Path $props ($tid + '\0067'))
      $cols = @($name, $_.PSChildName)
      if ($installed) { $cols += 'Installed ' + $installed }
      if ($arrived) { $cols += 'Last Connected ' + $arrived }
      if ($removed) { $cols += 'Last Removed ' + $removed }
      $cols -join ' | '
    }
  }
}`)
}

// usbProbes is one probe per root, each titled with the root it enumerates, all of
// them answering as one step.
var usbProbes = func() model.Step {
	probes := make(model.Step, 0, len(usbRoots))
	for _, root := range usbRoots {
		probes = append(probes, model.Probe{
			Label: "reg", Title: root, Inv: powershell.PowerShell(usbRead(root)),
		})
	}
	return probes
}()

// DevicesChecks is the devices aspect.
var DevicesChecks = []*model.Check{
	define.WindowsCheck("usb-devices", "USB Storage Devices (USBSTOR/SCSI/USB)", model.AspectDevices,
		[]model.Step{usbProbes},
		define.CheckOpt{Syntax: model.SyntaxPipe}),
}
