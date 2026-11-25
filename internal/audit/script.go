package audit

import (
	"encoding/base64"
	"fmt"
	"strings"
)

// Script is the sh source's activity and boundary collector. The seed paths —
// the activation targets the first collector read — join the candidate set so
// the content ledger covers them exactly as the native source does; they ride
// in as base64, so a path's spelling cannot touch the script. The script reads
// the target's own /proc, stat, readlink and package ledger; it executes
// nothing it finds. The record tags: T boundary facts, K boundary, U uid, V
// services, S sockets, P path facts, Q processes, A authority paths, D/R which
// package manager answered, O ownership rows, Y package timeline, E expected
// content hashes, C conffiles, L ledger file stamps, F mounts, X rpm verify, H
// actual content hashes. A `name` record's next line is the base64 of its
// payload.
func Script(seedPaths []string) string {
	seed := ""
	if len(seedPaths) > 0 {
		seed = strings.Join(seedPaths, "\n")
		seed = fmt.Sprintf("printf '%%s' '%s' | base64 -d >> \"$paths\"\n",
			base64.StdEncoding.EncodeToString([]byte(seed)))
	}
	return `command -v base64 >/dev/null 2>&1 || exit 127
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
paths=$tmp/paths
existing=$tmp/existing
: > "$paths" || exit 1
: > "$existing" || exit 1
printf 'KARMA-AUDIT 2\n'
` + seed + `
b64() {
  if [ -z "$1" ]; then
    printf '%s' "-"
    return 0
  fi
  printf '%s' "$1" | base64 | tr -d '\n'
}

blob() {
  printf '%s %s\n' "$1" "$2"
  base64 < "$3" 2>/dev/null | tr -d '\n'
  printf '\n'
}

btime=$(awk '/^btime /{print $2; exit}' /proc/stat 2>/dev/null)
[ -n "$btime" ] || btime=0
start_ticks=$(sed 's/^[^)]*) //' /proc/1/stat 2>/dev/null | awk '{print $20}')
[ -n "$start_ticks" ] || start_ticks=0
container=0
[ -e /.dockerenv ] && container=1
[ -e /run/.containerenv ] && container=1
grep -Eq 'docker|kubepods|containerd|lxc|podman|garden' /proc/1/cgroup 2>/dev/null && container=1
if [ "$container" = 1 ]; then
  edge=$((btime + start_ticks / 100))
else
  edge=$btime
fi
host=$(hostname 2>/dev/null)
kernel=$(uname -r 2>/dev/null)
osname=
if [ -r /etc/os-release ]; then
  osname=$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME")
fi
printf 'T %s %s %s %s %s %s\n' "$btime" "$start_ticks" "$container" "$(b64 "$host")" "$(b64 "$kernel")" "$(b64 "$osname")"
printf 'K %s\n' "$edge"
uid=$(id -u 2>/dev/null)
[ -n "$uid" ] && printf 'U %s\n' "$uid"

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
  systemctl list-units --type=service --all --no-pager --no-legend 2>/dev/null | while read -r unit load active sub rest; do
    unit=${unit#●}
    [ -n "$unit" ] || continue
    printf 'V %s %s %s %s %s\n' "$(b64 "$unit")" "$(b64 "$load")" "$(b64 "$active")" "$(b64 "$sub")" "$(b64 "$rest")"
  done
fi

ss_bin=$(command -v ss 2>/dev/null)
if [ -z "$ss_bin" ] && [ -x /usr/sbin/ss ]; then
  ss_bin=/usr/sbin/ss
fi
if [ -n "$ss_bin" ]; then
  # Every TCP state and every UDP socket: the listening surface and the
  # established connections that show an image is live.
  "$ss_bin" -H -a -t -u -n -p 2>/dev/null | awk '$2 == "LISTEN" || $2 == "ESTAB" || $1 ~ /^udp/' | while IFS= read -r line; do
    [ -n "$line" ] && printf 'S %s\n' "$(b64 "$line")"
  done
else
  # No ss: read the kernel tables directly. The inode owner is not resolved
  # here, so these rows carry uid only.
  for f in /proc/net/tcp /proc/net/udp; do
    [ -r "$f" ] || continue
    proto=${f##*/}
    case "$proto" in
      tcp6) proto=tcp ;;
      udp6) proto=udp ;;
    esac
    awk -v proto="$proto" '
      function h2d(s,   k, r, c) {
        r = 0
        for (k = 1; k <= length(s); k++) {
          c = substr(s, k, 1)
          if (c ~ /[0-9]/) { r = r * 16 + c } else { r = r * 16 + index("0123456789abcdef", tolower(c)) - 1 }
        }
        return r
      }
      NR > 1 {
        split($2, lp, ":")
        port = h2d(lp[2])
        uid = $10
        state = $4
        label = "UNCONN"
        if (proto == "tcp") {
          if (state == "0A") { label = "LISTEN" }
          else if (state == "01") { label = "ESTAB" }
          else { next }
        }
        if (length(lp[1]) == 8) {
          printf "%s %s %d.%d.%d.%d:%d *:* uid=%s\n", proto, label,
            h2d(substr(lp[1], 7, 2)), h2d(substr(lp[1], 5, 2)),
            h2d(substr(lp[1], 3, 2)), h2d(substr(lp[1], 1, 2)), port, uid
        } else {
          printf "%s %s [%s]:%d *:* uid=%s\n", proto, label, lp[1], port, uid
        }
      }' "$f" 2>/dev/null | while IFS= read -r line; do
      [ -n "$line" ] && printf 'S %s\n' "$(b64 "$line")"
    done
  done
fi

parent_flags() {
  d=$(dirname "$1")
  replaceable=0
  open=0
  while :; do
    if [ -d "$d" ]; then
      set -- $(stat -Lc '%u %a' "$d" 2>/dev/null)
      if [ $# -eq 2 ]; then
        u=$1
        m=$((0$2))
        if [ $((m & 01000)) -eq 0 ]; then
          if [ $((m & 0022)) -ne 0 ]; then open=1; replaceable=1; fi
          if [ "$u" -ne 0 ] && [ $((m & 0200)) -ne 0 ]; then replaceable=1; fi
        fi
      fi
    fi
    [ "$d" = "/" ] && break
    d=$(dirname "$d")
    [ -n "$d" ] || break
  done
  printf '%s %s' "$replaceable" "$open"
  return 0
}

emit_facts() {
  p=$1
  [ -n "$p" ] || return 0
  link=0
  [ -L "$p" ] && link=1
  real=$p
  r=$(readlink -f "$p" 2>/dev/null) && [ -n "$r" ] && real=$r
  kind=-
  mode=0
  uid=-1
  gid=-1
  if [ -f "$real" ]; then kind=f
  elif [ -d "$real" ]; then kind=d
  elif [ -e "$real" ]; then kind=o
  fi
  ctime=0
  inode=0
  caps=0
  if [ -e "$real" ]; then
    # %Z is the inode change time: userland cannot set it, and it is the
    # signal the origin judgment reads. %Y would be the mtime, which a
    # backdating touch controls.
    set -- $(stat -Lc '%a %u %g %Z %i' "$real" 2>/dev/null)
    if [ $# -eq 5 ]; then mode=$1; uid=$2; gid=$3; ctime=$4; inode=$5; fi
    if command -v getcap >/dev/null 2>&1; then
      [ -n "$(getcap "$real" 2>/dev/null)" ] && caps=1
    fi
  fi
  pw=0
  po=0
  lpw=0
  lpo=0
  set -- $(parent_flags "$real")
  [ $# -eq 2 ] && { pw=$1; po=$2; }
  set -- $(parent_flags "$p")
  [ $# -eq 2 ] && { lpw=$1; lpo=$2; }
  printf 'P %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' "$(b64 "$p")" "$kind" "$mode" "$uid" "$gid" "$link" "$(b64 "$real")" "$pw" "$po" "$lpw" "$lpo" "$ctime" "$inode" "$caps"
  [ -e "$real" ] && printf '%s\n%s\n' "$p" "$real" >> "$existing"
  return 0
}

script_arg() {
  cmd=$1
  first=1
  for arg in $cmd; do
    if [ $first = 1 ]; then first=0; continue; fi
    case "$arg" in
      -c|-e|-r|-m) return 0 ;;
      -*) continue ;;
    esac
    printf '%s' "$arg"
    return 0
  done
  return 0
}

for dir in /proc/[0-9]*; do
  pid=${dir#/proc/}
  [ -r "$dir/stat" ] || continue
  rest=$(sed 's/^[^)]*) //' "$dir/stat" 2>/dev/null)
  [ -n "$rest" ] || continue
  set -- $rest
  state=$1
  ppid=$2
  start=$20
  uid=-1
  gid=-1
  if [ -r "$dir/status" ]; then
    uid=$(awk '/^Uid:/{print $2; exit}' "$dir/status" 2>/dev/null)
    gid=$(awk '/^Gid:/{print $2; exit}' "$dir/status" 2>/dev/null)
  fi
  [ -n "$uid" ] || uid=-1
  [ -n "$gid" ] || gid=-1
  comm=$(cat "$dir/comm" 2>/dev/null)
  cwd=$(readlink "$dir/cwd" 2>/dev/null)
  root=$(readlink "$dir/root" 2>/dev/null)
  cmdline=
  if [ -r "$dir/cmdline" ]; then
    cmdline=$(tr '\000' ' ' < "$dir/cmdline" 2>/dev/null)
  fi
  exe=$(readlink "$dir/exe" 2>/dev/null)
  if [ -z "$exe" ]; then
    # A process of another account hides its exe link. The command line still
    # names the image: an absolute path is taken as-is, a bare name is looked
    # up in the distribution's program directories.
    name=${cmdline%% *}
    case "$name" in
      /*) exe=$name ;;
      ""|" "*|*[\[\?\*]*) exe= ;;
      *\/*)
        case "$cwd" in
          "") exe= ;;
          *) exe=$cwd/$name ;;
        esac
        ;;
      *)
        exe=
        for d in /bin /usr/bin /sbin /usr/sbin /usr/local/bin /usr/local/sbin; do
          if [ -f "$d/$name" ]; then
            exe=$d/$name
            break
          fi
        done
        ;;
    esac
  fi
  printf 'Q %s %s %s %s %s %s %s %s %s %s %s\n' "$pid" "$ppid" "$uid" "$gid" "$start" "$state" "$(b64 "$comm")" "$(b64 "$exe")" "$(b64 "$cwd")" "$(b64 "$root")" "$(b64 "$cmdline")"
  if [ -n "$exe" ]; then
    printf '%s\n' "$exe" >> "$paths"
    base=${exe##*/}
    case "$base" in
      bash|sh|dash|zsh|ksh|fish|python*|perl*|ruby*|node*|php*|lua*)
        arg=$(script_arg "$cmdline")
        if [ -n "$arg" ]; then
          case "$arg" in
            /*) printf '%s\n' "$arg" >> "$paths" ;;
            *) [ -n "$cwd" ] && printf '%s\n' "$cwd/$arg" >> "$paths" ;;
          esac
        fi
        ;;
    esac
  fi
done

for p in /etc/sudoers /etc/sudoers.d/* /etc/passwd /etc/shadow \
         /etc/ssh/ssh_host_*_key; do
  [ -e "$p" ] || continue
  printf 'A %s\n' "$(b64 "$p")"
  printf '%s\n' "$p" >> "$paths"
done

if [ -d /bin ]; then
  for p in $(find /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt /etc -xdev -type f -perm -4000 2>/dev/null); do
    printf 'A %s\n' "$(b64 "$p")"
    printf '%s\n' "$p" >> "$paths"
  done
fi
if command -v getcap >/dev/null 2>&1; then
  getcap -r /bin /sbin /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local /opt /etc 2>/dev/null | while read -r p caps; do
    [ -n "$p" ] || continue
    printf 'A %s\n' "$(b64 "$p")"
    printf '%s\n' "$p" >> "$paths"
  done
fi

sort -u "$paths" > "$tmp/uniq" 2>/dev/null || cp "$paths" "$tmp/uniq"
while IFS= read -r p; do
  emit_facts "$p"
done < "$tmp/uniq"

dpkg_bin=
rpm_bin=
command -v dpkg >/dev/null 2>&1 && dpkg_bin=$(command -v dpkg)
command -v rpm >/dev/null 2>&1 && rpm_bin=$(command -v rpm)
runner=
command -v timeout >/dev/null 2>&1 && runner="timeout 20"

# The ancestor directories of every candidate join the ownership questions, so
# an unowned file can be placed in the tree it sits in.
while IFS= read -r p; do
  d=$(dirname "$p")
  while [ "$d" != "/" ] && [ -n "$d" ]; do
    printf '%s\n' "$d"
    d=$(dirname "$d")
  done
done < "$tmp/uniq" 2>/dev/null | sort -u > "$tmp/parents" 2>/dev/null || : > "$tmp/parents"
sort -u "$existing" > "$tmp/existing-uniq" 2>/dev/null || cp "$existing" "$tmp/existing-uniq"
cat "$tmp/existing-uniq" "$tmp/parents" > "$tmp/ask" 2>/dev/null || cp "$tmp/existing-uniq" "$tmp/ask"
tr '\n' '\0' < "$tmp/ask" > "$tmp/ask-nul" 2>/dev/null

if [ -n "$dpkg_bin" ] && [ -s "$tmp/ask-nul" ]; then
  $runner xargs -0 -r "$dpkg_bin" -S < "$tmp/ask-nul" > "$tmp/dpkg" 2>/dev/null
  rc=$?
  case "$rc" in
    0|123)
      printf 'D 1\n'
      printf 'O dpkg\n'
      base64 < "$tmp/dpkg" | tr -d '\n'
      printf '\n'
      ;;
    *) printf 'D 0\n' ;;
  esac
elif [ -n "$dpkg_bin" ]; then
  printf 'D 1\n'
fi

if [ -n "$rpm_bin" ] && [ -s "$tmp/ask-nul" ]; then
  $runner xargs -0 -r "$rpm_bin" -qf --qf '%{NAME} %{FILENAMES}\n' < "$tmp/ask-nul" > "$tmp/rpm" 2>/dev/null
  rc=$?
  case "$rc" in
    0|123)
      printf 'R 1\n'
      printf 'O rpm\n'
      base64 < "$tmp/rpm" | tr -d '\n'
      printf '\n'
      ;;
    *) printf 'R 0\n' ;;
  esac
elif [ -n "$rpm_bin" ]; then
  printf 'R 1\n'
fi

# Package timeline: each package's last transaction, condensed from the log on
# the target so the wire carries one line per package.
if [ -r /var/log/dpkg.log ]; then
  awk '{
    if ($3 == "status") { if (NF >= 5) pkg = $5; else next }
    else { if (NF >= 4) pkg = $4; else next }
    sub(/:.*/, "", pkg)
    d = $1; gsub(/-/, " ", d)
    t = $2; gsub(/:/, " ", t)
    e = mktime(d " " t)
    if (e > 0 && e > c[pkg]) c[pkg] = e
  }
  END { for (p in c) print p, c[p] }' /var/log/dpkg.log > "$tmp/timeline" 2>/dev/null
  [ -s "$tmp/timeline" ] && blob Y timeline "$tmp/timeline"
fi

# Expected content hashes, filtered to the candidate set on the target. The
# candidates are the asked spellings and the resolved ones — the ledger
# records the resolved tree — plus the usrmerge variants the native
# comparison allows.
if [ -d /var/lib/dpkg/info ]; then
  cat "$tmp/uniq" "$tmp/existing-uniq" > "$tmp/asked" 2>/dev/null || cp "$tmp/uniq" "$tmp/asked"
  sed 's|^/||' "$tmp/asked" > "$tmp/cand" 2>/dev/null || cp "$tmp/asked" "$tmp/cand"
  sed 's|^usr/||' "$tmp/cand" > "$tmp/cand2" 2>/dev/null
  sort -u "$tmp/cand" "$tmp/cand2" -o "$tmp/cand" 2>/dev/null
  : > "$tmp/md5-all"
  for f in /var/lib/dpkg/info/*.md5sums; do
    [ -f "$f" ] || continue
    pkg=${f##*/}
    pkg=${pkg%.md5sums}
    pkg=${pkg%%:*}
    awk -v p="$pkg" '{print p "\t" $1 "\t" $2}' "$f" >> "$tmp/md5-all"
  done
  awk -F'\t' 'NR==FNR{c[$0]=1;next} ($3 in c){print}' "$tmp/cand" "$tmp/md5-all" > "$tmp/expected" 2>/dev/null
  [ -s "$tmp/expected" ] && blob E md5sums "$tmp/expected"

  cat /var/lib/dpkg/info/*.conffiles > "$tmp/conffiles" 2>/dev/null
  [ -s "$tmp/conffiles" ] && blob C conffiles "$tmp/conffiles"

  # The ledger files' own change times for every package: a ledger written
  # after its package's last transaction is tampered evidence, and the
  # offender's package needs no other qualification.
  : > "$tmp/ledger-all"
  for f in /var/lib/dpkg/info/*.md5sums /var/lib/dpkg/info/*.list; do
    [ -f "$f" ] || continue
    pkg=${f##*/}
    pkg=${pkg%.*}
    pkg=${pkg%%:*}
    c=$(stat -c '%Z' "$f" 2>/dev/null) || continue
    printf '%s\t%s\t%s\n' "$c" "$pkg" "$f" >> "$tmp/ledger-all"
  done
  if [ -r /var/log/dpkg.log ]; then
    t=$(stat -c '%Z' /var/log/dpkg.log 2>/dev/null)
    [ -n "$t" ] && printf '%s\t%s\t%s\n' "$t" '*' /var/log/dpkg.log >> "$tmp/ledger-all"
  fi
  [ -s "$tmp/ledger-all" ] && blob L ledgerstat "$tmp/ledger-all"
fi

if [ -n "$rpm_bin" ]; then
  if [ -n "$runner" ]; then
    timeout 60 rpm -Va > "$tmp/rpmva" 2>/dev/null
  else
    rpm -Va > "$tmp/rpmva" 2>/dev/null
  fi
  [ -s "$tmp/rpmva" ] && blob X rpm-verify "$tmp/rpmva"
  $runner rpm -qa --qf '%{NAME} %{INSTALLTID}\n' > "$tmp/rpmtime" 2>/dev/null
  [ -s "$tmp/rpmtime" ] && blob Y rpm-time "$tmp/rpmtime"
fi

cat /proc/self/mounts > "$tmp/mounts" 2>/dev/null
[ -s "$tmp/mounts" ] && blob F mounts "$tmp/mounts"

if [ -s "$tmp/ask-nul" ]; then
  $runner xargs -0 -r md5sum < "$tmp/ask-nul" > "$tmp/hashes" 2>/dev/null
  [ -s "$tmp/hashes" ] && blob H md5sum "$tmp/hashes"
fi

exit 0
`
}
