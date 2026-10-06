// devices peripherals: USB / SCSI storage devices and their plug times.
//
// Times come from the FILETIME of each device instance's Properties\{83da6326-...}\{0064,0066,0067}
// (installed, last connected, last removed); some property values are unreadable by regular users
// and left blank, complete only from an administrator's view. The one-line-per-device shape is
// assembled in the remote PowerShell.

package windows

import (
	"karma/internal/define"
	"karma/internal/model"
)

const usbScript = `$tid = '{83da6326-97a6-4088-9453-a1923f573b29}'
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
}
foreach ($root in 'USBSTOR', 'SCSI', 'USB') {
  $base = 'HKLM:\SYSTEM\CurrentControlSet\Enum\' + $root
  if (-not (Test-Path $base)) { continue }
  "== " + $root
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
}`

// DevicesChecks is the devices aspect.
var DevicesChecks = []*model.Check{
	define.WindowsCheck("usb-devices", "USB Storage Devices (USBSTOR/SCSI/USB)", model.AspectDevices,
		[]model.Probe{PSProbe("reg", usbScript)},
		define.CheckOpt{Syntax: model.SyntaxPipe}),
}
