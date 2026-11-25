package startup

// Script is the sh source's collector: the same surfaces, read through the
// target's own stat, readlink and package database, and printed in the line
// protocol ParseCorpus reads. It executes nothing it finds; the only programs
// it runs are the target's own readers.
//
// The paths are the collector's declaration, not a second list: unitDirs and
// profileFiles above are walked by the native source, and this script walks
// the same trees. A file is read whole to maxFileBytes, then scanned for
// absolute path tokens, so a target the file names has its facts even though
// only the Go parser decides which token is an edge.
func Script() string {
	return `command -v base64 >/dev/null 2>&1 || exit 127
tmp=$(mktemp -d) || exit 1
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
paths=$tmp/paths
existing=$tmp/existing
: > "$paths" || exit 1
: > "$existing" || exit 1
printf 'KARMA-STARTUP 1\n'

TOKEN='/[A-Za-z0-9._+@%,:=-]+(/[A-Za-z0-9._+@%,:=-]+)*'

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

emit_file() {
  f=$1
  [ -f "$f" ] || return 0
  if [ ! -r "$f" ] || ! head -c 65536 "$f" > "$tmp/body" 2>/dev/null; then
    printf 'E %s\n' "$(b64 "$f")"
    return 0
  fi
  printf 'B %s\n' "$(b64 "$f")"
  base64 < "$tmp/body" | tr -d '\n'
  printf '\n'
  printf '%s\n' "$f" >> "$paths"
  grep -oE "$TOKEN" "$f" 2>/dev/null >> "$paths"
  return 0
}

for base in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
            /etc/systemd/user /root/.config/systemd/user /home/*/.config/systemd/user; do
  [ -d "$base" ] || continue
  for f in "$base"/*.service "$base"/*.socket "$base"/*.timer "$base"/*.path; do
    emit_file "$f"
  done
  for d in "$base"/*.d; do
    [ -d "$d" ] || continue
    for f in "$d"/*.conf; do
      emit_file "$f"
    done
    unit=${d##*/}
    unit=${unit%.d}
    for v in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
             /usr/lib/systemd/system /lib/systemd/system; do
      if [ -e "$v/$unit" ]; then
        [ -f "$v/$unit" ] && emit_file "$v/$unit"
        break
      fi
    done
  done
  for d in "$base"/*.wants "$base"/*.requires; do
    [ -d "$d" ] || continue
    for l in "$d"/*; do
      [ -L "$l" ] || continue
      printf 'L %s %s\n' "$(b64 "$l")" "$(b64 "$(readlink "$l")")"
      target=$(readlink -f "$l" 2>/dev/null)
      case "$target" in
        *.service|*.socket|*.timer|*.path) emit_file "$target" ;;
      esac
    done
  done
done

# The distribution's own enablement links name the vendor units that run at
# boot; read what those units execute without walking every vendor unit file.
# They describe a boot only when systemd is the running init.
if [ -d /run/systemd/system ]; then
  for base in /usr/lib/systemd/system /lib/systemd/system; do
    [ -d "$base" ] || continue
    for d in "$base"/*.wants "$base"/*.requires; do
      [ -d "$d" ] || continue
      for l in "$d"/*; do
        [ -L "$l" ] || continue
        printf 'L %s %s\n' "$(b64 "$l")" "$(b64 "$(readlink "$l")")"
        target=$(readlink -f "$l" 2>/dev/null)
        case "$target" in
          *.service|*.socket|*.timer|*.path) emit_file "$target" ;;
        esac
      done
    done
  done
fi

# A timer or socket reaches its service through Unit=; that unit may live in
# the distribution tree the admin layers above did not name.
for d in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system; do
  [ -d "$d" ] || continue
  for f in "$d"/*.timer "$d"/*.socket; do
    [ -f "$f" ] || continue
    unit=$(sed -n 's/^Unit=//p' "$f" 2>/dev/null | head -n 1)
    [ -n "$unit" ] || continue
    for v in /etc/systemd/system /run/systemd/system /usr/local/lib/systemd/system \
             /usr/lib/systemd/system /lib/systemd/system; do
      if [ -e "$v/$unit" ]; then
        [ -f "$v/$unit" ] && emit_file "$v/$unit"
        break
      fi
    done
  done
done

for f in /etc/profile /etc/bash.bashrc /etc/bashrc /etc/bash.bash_logout \
         /etc/zsh/zshenv /etc/zsh/zprofile /etc/zsh/zshrc /etc/zsh/zlogin \
         /etc/environment \
         /root/.bashrc /root/.bash_profile /root/.bash_login /root/.profile /root/.bash_logout \
         /root/.zshrc /root/.zprofile /root/.zshenv /root/.zlogin \
         /home/*/.bashrc /home/*/.bash_profile /home/*/.bash_login /home/*/.profile /home/*/.bash_logout \
         /home/*/.zshrc /home/*/.zprofile /home/*/.zshenv /home/*/.zlogin \
         /etc/skel/.bashrc /etc/skel/.bash_profile /etc/skel/.bash_login /etc/skel/.profile \
         /etc/skel/.bash_logout /etc/skel/.zshrc /etc/skel/.zprofile /etc/skel/.zshenv \
         /etc/skel/.zlogin \
         /etc/profile.d/*.sh; do
  emit_file "$f"
done

for f in /etc/crontab /etc/anacrontab /etc/cron.d/* \
         /var/spool/cron/crontabs/* /var/spool/cron/* \
         /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.weekly/* /etc/cron.monthly/* \
         /var/spool/cron/atjobs/* /var/spool/at/*; do
  emit_file "$f"
done

for f in /etc/rc.local /etc/rc.d/rc.local /etc/init.sh /etc/init.d/*; do
  emit_file "$f"
done
for d in /etc/rc*.d /etc/rc.d/rc*.d; do
  [ -d "$d" ] || continue
  for l in "$d"/S*; do
    [ -L "$l" ] || continue
    printf 'L %s %s\n' "$(b64 "$l")" "$(b64 "$(readlink "$l")")"
  done
done

emit_file /etc/ld.so.preload
for f in /etc/udev/rules.d/*.rules /run/udev/rules.d/*.rules; do
  emit_file "$f"
done

for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* \
         /etc/ssh/sshrc /root/.ssh/rc /home/*/.ssh/rc \
         /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys \
         /etc/ssh/authorized_keys /etc/ssh/authorized_keys.d/*; do
  emit_file "$f"
done
for f in /etc/pam.d/*; do
  emit_file "$f"
done
for f in /etc/supervisor/supervisord.conf /etc/supervisor/conf.d/*.conf \
         /etc/supervisord.conf /etc/supervisord.d/*.ini \
         /etc/s6/services/*/run /etc/services.d/*/run \
         /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/up \
         /docker-entrypoint.d/*.sh /docker-entrypoint-initdb.d/*.sh /entrypoint.d/*.sh; do
  emit_file "$f"
done
for f in /etc/xdg/autostart/*.desktop /root/.config/autostart/*.desktop \
         /home/*/.config/autostart/*.desktop; do
  emit_file "$f"
done
for f in /etc/apt/apt.conf /etc/apt/apt.conf.d/*; do
  emit_file "$f"
done
for f in /etc/modprobe.d/*.conf /run/modprobe.d/*.conf /usr/local/lib/modprobe.d/*.conf; do
  emit_file "$f"
done

sort -u "$paths" > "$tmp/uniq" 2>/dev/null || cp "$paths" "$tmp/uniq"

dpkg_bin=
rpm_bin=
command -v dpkg >/dev/null 2>&1 && dpkg_bin=$(command -v dpkg)
command -v rpm >/dev/null 2>&1 && rpm_bin=$(command -v rpm)
runner=
command -v timeout >/dev/null 2>&1 && runner="timeout 20"

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
  if [ -e "$real" ]; then
    set -- $(stat -Lc '%a %u %g' "$real" 2>/dev/null)
    if [ $# -eq 3 ]; then mode=$1; uid=$2; gid=$3; fi
  fi
  pw=0
  po=0
  lpw=0
  lpo=0
  set -- $(parent_flags "$real")
  [ $# -eq 2 ] && { pw=$1; po=$2; }
  set -- $(parent_flags "$p")
  [ $# -eq 2 ] && { lpw=$1; lpo=$2; }
  ctime=0
  inode=0
  caps=0
  if [ -e "$real" ]; then
    set -- $(stat -Lc '%Y %i' "$real" 2>/dev/null)
    [ $# -eq 2 ] && { ctime=$1; inode=$2; }
    if command -v getcap >/dev/null 2>&1; then
      [ -n "$(getcap "$real" 2>/dev/null)" ] && caps=1
    fi
  fi
  printf 'P %s %s %s %s %s %s %s %s %s %s %s %s %s %s\n' "$(b64 "$p")" "$kind" "$mode" "$uid" "$gid" "$link" "$(b64 "$real")" "$pw" "$po" "$lpw" "$lpo" "$ctime" "$inode" "$caps"
  if [ -e "$real" ]; then
    printf '%s\n%s\n' "$p" "$real" >> "$existing"
  fi
  return 0
}

while IFS= read -r p; do
  emit_facts "$p"
done < "$tmp/uniq"

sort -u "$existing" > "$tmp/existing-uniq" 2>/dev/null || cp "$existing" "$tmp/existing-uniq"
tr '\n' '\0' < "$tmp/existing-uniq" > "$tmp/existing-nul" 2>/dev/null

if [ -n "$dpkg_bin" ] && [ -s "$tmp/existing-nul" ]; then
  $runner xargs -0 -r "$dpkg_bin" -S < "$tmp/existing-nul" > "$tmp/dpkg" 2>/dev/null
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

if [ -n "$rpm_bin" ] && [ -s "$tmp/existing-nul" ]; then
  $runner xargs -0 -r "$rpm_bin" -qf --qf '%{NAME} %{FILENAMES}\n' < "$tmp/existing-nul" > "$tmp/rpm" 2>/dev/null
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

exit 0
`
}
