#!/usr/bin/env bash
# ssh-dl.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# Downloads files or folder trees from a remote host over SSH.
#
# Behavior:
# - Opens a reusable SSH control connection for the run
# - Scans a remote directory and filters by size, extension, name, or
#   content, then sorts by newest, oldest, largest, smallest, or name
# - Can list or summarize matches without downloading
# - Streams tar or tar.gz from the remote host; in single-file mode, adds
#   extensions to extensionless downloads based on local MIME detection
# - In whole-dir mode (-R), --count, --min-size, --max-size, and --sort
#   are ignored
# - Content matching is a literal, case-sensitive phrase search
# - Name patterns are shell-style globs matched against the basename and
#   the path relative to --remote-dir
# - When include and exclude filters both match the same file, exclude wins
# - Built-in temp/bookkeeping filename skips can be disabled with -A
# - Tildes in --dest and --remote-dir expand against the local and remote
#   $HOME respectively
#
# Access:
# - Tries direct access as the remote user first; falls back to passwordless
#   or cached sudo; prompts for a sudo password only if the path requires it
# - The remote sudo password is kept only in RAM for this script run
# - The initial SSH connection may prompt for a login password or key
#   passphrase if key or agent auth is not already available
#
# Requirements:
# - Remote: python3 or python in PATH
# - Local: ssh, tar, awk, mktemp
#
# Environment:
# - NO_COLOR=1 disables colored output
#
# Limitations:
# - Single quotes in arguments are not supported

set -euo pipefail
umask 077

# Defaults and parameters

readonly DEFAULT_COUNT=10
readonly DEFAULT_SORT="newest"

REMOTE_HOST=""
REMOTE_USER=""
REMOTE_DIR=""
LOCAL_DEST=""

COUNT="$DEFAULT_COUNT"
MIN_SIZE=""
MAX_SIZE=""
SORT_MODE="$DEFAULT_SORT"
SEARCH_TEXT=""
USE_COMPRESSION=1
WHOLE_DIR_MODE=0
AUTO_YES=0
LIST_ONLY=0
STATS_ONLY=0
USE_DEFAULT_EXCLUDES=1
INCLUDE_EXTS=()
EXCLUDE_EXTS=()
INCLUDE_NAME_PATTERNS=()
EXCLUDE_NAME_PATTERNS=()
USED_NAMES=()
DUP_BASENAMES=()

SSH_TARGET=""
REMOTE_PYTHON=""
REMOTE_ACCESS_MODE=""
REMOTE_ACCESS_LABEL=""
SSH_AUTH_LABEL=""
SSH_ASKPASS_HELPER=""
SUDO_PASS=""

# Embedded Python helpers used on the remote host
readonly REMOTE_SCAN_PY='
import fnmatch
import os
import sys
from datetime import datetime

dir_path = sys.argv[1]
count = int(sys.argv[2])
min_size_raw = sys.argv[3].strip().lower()
max_size_raw = sys.argv[4].strip().lower()
sort_mode = sys.argv[5].strip().lower()
include_exts_raw = sys.argv[6].strip().lower()
exclude_exts_raw = sys.argv[7].strip().lower()
whole_dir_mode = sys.argv[8] == "1"
use_default_excludes = sys.argv[9] == "1"
search_text = sys.argv[10]
include_name_patterns_raw = sys.argv[11]
exclude_name_patterns_raw = sys.argv[12]

def size_to_bytes(raw):
    if not raw:
        return None

    mult = 1
    if raw[-1] in ("k", "m", "g", "t"):
        suffix = raw[-1]
        num = raw[:-1]
        if suffix == "k":
            mult = 1024
        elif suffix == "m":
            mult = 1024 ** 2
        elif suffix == "g":
            mult = 1024 ** 3
        elif suffix == "t":
            mult = 1024 ** 4
    else:
        num = raw

    return int(num) * mult

min_bytes = size_to_bytes(min_size_raw) or 0
max_bytes = size_to_bytes(max_size_raw)
bad_suffixes = (
    ".partial",
    ".part",
    ".download",
    ".crdownload",
    ".tmp",
    ".temp",
    "_partial",
    "_tmp",
    "-wal",
    "-shm",
    "-journal",
)
bad_prefixes = (
    "db_sqlite",
    "partial-",
)
include_suffixes = tuple(
    ".{}".format(ext.lstrip("."))
    for ext in include_exts_raw.split(",")
    if ext.strip(".")
)
exclude_suffixes = tuple(
    ".{}".format(ext.lstrip("."))
    for ext in exclude_exts_raw.split(",")
    if ext.strip(".")
)
search_bytes = search_text.encode("utf-8") if search_text else b""
include_name_patterns = tuple(
    pattern for pattern in include_name_patterns_raw.split(",")
    if pattern
)
exclude_name_patterns = tuple(
    pattern for pattern in exclude_name_patterns_raw.split(",")
    if pattern
)
rows = []
root_parts = [
    part for part in os.path.normpath(dir_path).split(os.sep)
    if part not in ("", ".", "..")
]
root_name = os.path.join(*root_parts) if root_parts else "remote-root"

def file_contains(path, needle):
    if not needle:
        return True

    overlap = max(len(needle) - 1, 0)
    tail = b""

    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(65536)
            if not chunk:
                return needle in tail

            data = tail + chunk
            if needle in data:
                return True

            if overlap:
                tail = data[-overlap:]
            else:
                tail = b""

for root, dirs, files in os.walk(dir_path):
    for name in files:
        lower = name.lower()
        if use_default_excludes:
            if lower.endswith(bad_suffixes):
                continue
            if lower.startswith(bad_prefixes):
                continue
        if include_suffixes and not lower.endswith(include_suffixes):
            continue
        if exclude_suffixes and lower.endswith(exclude_suffixes):
            continue

        path = os.path.join(root, name)
        rel_path = os.path.relpath(path, dir_path)

        if include_name_patterns:
            if not any(
                fnmatch.fnmatchcase(name, pattern) or
                fnmatch.fnmatchcase(rel_path, pattern)
                for pattern in include_name_patterns
            ):
                continue

        if exclude_name_patterns:
            if any(
                fnmatch.fnmatchcase(name, pattern) or
                fnmatch.fnmatchcase(rel_path, pattern)
                for pattern in exclude_name_patterns
            ):
                continue

        if os.path.islink(path):
            continue

        try:
            st = os.stat(path)
        except Exception:
            continue

        if not os.path.isfile(path):
            continue

        if not whole_dir_mode and st.st_size < min_bytes:
            continue
        if not whole_dir_mode and max_bytes is not None and st.st_size > max_bytes:
            continue
        if search_bytes:
            try:
                if not file_contains(path, search_bytes):
                    continue
            except Exception:
                continue

        if whole_dir_mode:
            store_name = os.path.join(root_name, rel_path)
        else:
            store_name = os.path.basename(path)

        rows.append((st.st_mtime, st.st_size, store_name, path))

if sort_mode == "newest":
    rows.sort(key=lambda row: (-row[0], row[2].lower()))
elif sort_mode == "oldest":
    rows.sort(key=lambda row: (row[0], row[2].lower()))
elif sort_mode == "largest":
    rows.sort(key=lambda row: (-row[1], row[2].lower()))
elif sort_mode == "smallest":
    rows.sort(key=lambda row: (row[1], row[2].lower()))
elif sort_mode == "name":
    rows.sort(key=lambda row: row[2].lower())
else:
    raise SystemExit("unsupported sort mode: {}".format(sort_mode))

if not whole_dir_mode:
    rows = rows[:count]

for mtime, size, store_name, path in rows:
    ts = datetime.fromtimestamp(mtime).strftime("%Y-%m-%d %H:%M:%S")
    sys.stdout.write("{}\t{}\t{}\t{}\n".format(ts, size, store_name, path))
'

readonly REMOTE_PACK_PY='
import os
import sys
import tarfile

pack_mode = sys.argv[1] if len(sys.argv) > 1 else "gzip"
out = getattr(sys.stdout, "buffer", sys.stdout)

if pack_mode == "gzip":
    archive = tarfile.open(fileobj=out, mode="w|gz")
elif pack_mode == "plain":
    archive = tarfile.open(fileobj=out, mode="w|")
else:
    raise SystemExit("unsupported pack mode: {}".format(pack_mode))

for raw in sys.stdin:
    raw = raw.rstrip("\n")
    if not raw:
        continue

    parts = raw.split("\t", 1)
    if len(parts) != 2:
        continue

    arcname, path = parts
    if not arcname or not path:
        continue

    try:
        if os.path.islink(path):
            continue
        if not os.path.isfile(path):
            continue
        archive.add(path, arcname=arcname, recursive=False)
    except Exception as exc:
        sys.stderr.write("skip {}: {}\n".format(arcname, exc))
        continue

archive.close()
'

# Color support and formatting

USE_COLOR=0

# Enable ANSI colors when stdout is a TTY and NO_COLOR is not set
init_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		USE_COLOR=1
	fi
}

# Wrap a string in an ANSI color; pass through unchanged when colors are off
color() {
	local c="$1" s="$2"
	if [ "$USE_COLOR" -eq 0 ]; then
		printf '%s' "$s"
		return
	fi
	local code=""
	case "$c" in
		reset)   code=0 ;;
		bold)    code=1 ;;
		dim)     code=2 ;;
		red)     code=91 ;;
		green)   code=92 ;;
		yellow)  code=93 ;;
		blue)    code=94 ;;
		magenta) code=95 ;;
		cyan)    code=96 ;;
		gray)    code=90 ;;
		*)       printf '%s' "$s"; return ;;
	esac
	printf '\033[%sm%s\033[0m' "$code" "$s"
}

# Print a titled section banner with horizontal bars above and below the title
section() {
	local title="$1"
	local bar
	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

# Format a byte count as B, KB, MB, GB, or TB with one decimal place
human_size() {
	awk -v b="$1" 'BEGIN {
		if (b >= 1099511627776) printf "%.1f TB", b / 1099511627776;
		else if (b >= 1073741824) printf "%.1f GB", b / 1073741824;
		else if (b >= 1048576)    printf "%.1f MB", b / 1048576;
		else if (b >= 1024)       printf "%.1f KB", b / 1024;
		else                      printf "%d B", b;
	}'
}

# Return a local file's size in bytes, handling both BSD and GNU stat
file_size() {
	stat -f%z "$1" 2>/dev/null || stat -c%s "$1" 2>/dev/null || echo 0
}

# Helper functions

# Print the help text and exit; stdout for an explicit help request, stderr otherwise
usage() {
	local exit_code="${1:-1}"
	local out=2
	[ "$exit_code" -eq 0 ] && out=1

	cat >&"$out" <<-EOF
	Usage: $(basename "$0") [options]

	Download files from a remote directory over SSH.

	Required:
	  -H, --host HOST          Remote SSH host or SSH config alias
	  -u, --user USER          Remote SSH user
	  -r, --remote-dir DIR     Remote directory to scan
	  -d, --dest DIR           Local destination directory (created if missing)

	Optional:
	  -n, --count N            Number of newest files to consider
	                             (default: $DEFAULT_COUNT)
	  -s, --min-size SIZE      Minimum file size, with optional k/m/g/t suffix
	  -S, --max-size SIZE      Maximum file size, with optional k/m/g/t suffix
	  -o, --sort MODE          Sort by newest, oldest, largest, smallest, or name
	                             (default: $DEFAULT_SORT)
	  -C, --contains TEXT      Only include files whose contents contain TEXT
	  -R, --whole-dir          Download the whole remote directory tree
	  -i, --include-ext EXT    Only include files with this extension (can repeat)
	  -x, --exclude-ext EXT    Skip files with this extension (can repeat)
	  -N, --include-name PAT   Only include files whose basename or relative path
	                             matches PAT (can repeat)
	  -X, --exclude-name PAT   Skip files whose basename or relative path matches
	                             PAT (can repeat)
	  -A, --no-default-skips   Do not skip built-in temp/bookkeeping filename patterns
	  -y, --yes                Skip confirmation and download immediately
	  -l, --list-only          Show stats/list and exit without downloading
	  -t, --stats-only         Show only summary stats before downloading
	  -z, --no-compress        Stream a plain tar instead of tar.gz
	  -h, --help               Show this help and exit

	Examples:
	  $(basename "$0") -H remote-box -u admin \\
	      -r /var/tmp/downloads -d ~/Downloads/remote

	  $(basename "$0") -H remote-box -u admin -r /home/admin/archive \\
	      -d ~/Downloads/remote -R -y

	  $(basename "$0") -H remote-box -u admin -r /var/log -d ~/Downloads/logs \\
	      -n 20 -o largest -s 10m -S 1g -C "fatal error"
	EOF

	exit "$exit_code"
}

# Abort with a clear error if the named local command is not on PATH
require_local_cmd() {
	local cmd="$1"
	if ! command -v "$cmd" >/dev/null 2>&1; then
		printf '%s\n' "$(color red "Error: required local command not found: $cmd")" >&2
		exit 1
	fi
}

# Derive the top-level folder name used as the archive root in whole-dir mode
whole_dir_root() {
	awk -v path="$REMOTE_DIR" 'BEGIN {
		gsub(/\/+/, "/", path)
		n = split(path, parts, "/")
		out = ""
		for (i = 1; i <= n; i++) {
			if (parts[i] == "" || parts[i] == "." || parts[i] == "..") {
				continue
			}
			out = out (out ? "/" : "") parts[i]
		}
		if (out == "") {
			out = "remote-root"
		}
		print out
	}'
}

# Strip the REMOTE_DIR prefix from an absolute remote path, returning the
# remainder
relative_remote_path() {
	awk -v path="$1" -v root="$REMOTE_DIR" 'BEGIN {
		gsub(/\/+/, "/", path)
		gsub(/\/+/, "/", root)

		if (root != "/" && root ~ /\/$/) {
			sub(/\/$/, "", root)
		}

		if (root == "/") {
			sub(/^\/+/, "", path)
			print path
			exit
		}

		prefix = root "/"
		if (index(path, prefix) == 1) {
			print substr(path, length(prefix) + 1)
		} else if (path == root) {
			print "."
		} else {
			print path
		}
	}'
}

# Lowercase an extension, strip a leading dot, and reject quotes, commas, or
# empty values
normalize_ext_filter() {
	local flag_name="$1"
	local ext="$2"

	case "$ext" in
		*\'*)
			printf '%s\n' "$(color red "Error: $flag_name cannot contain single quotes: $ext")" >&2
			exit 1
			;;
	esac

	ext="${ext#.}"
	ext=$(printf '%s' "$ext" | tr '[:upper:]' '[:lower:]')

	if [ -z "$ext" ]; then
		printf '%s\n' "$(color red "Error: $flag_name cannot be empty")" >&2
		exit 1
	fi

	case "$ext" in
		*,*)
			printf '%s\n' "$(color red "Error: $flag_name cannot contain commas: $ext")" >&2
			exit 1
			;;
	esac

	printf '%s' "$ext"
}

# Expand a leading ~ or ~/ to the local $HOME; other paths pass through
# unchanged
expand_local_tilde() {
	local path="$1"
	case "$path" in
		\~)    printf '%s' "$HOME" ;;
		\~/*)  printf '%s' "$HOME/${path#\~/}" ;;
		*)     printf '%s' "$path" ;;
	esac
}

# Reject empty, comma-containing, or quote/newline-containing glob patterns
validate_name_pattern() {
	local flag_name="$1"
	local pattern="$2"

	case "$pattern" in
		'')
			printf '%s\n' "$(color red "Error: $flag_name cannot be empty")" >&2
			exit 1
			;;
		*\'*|*$'\n'*|*$'\r'*)
			printf '%s\n' "$(color red "Error: $flag_name cannot contain single quotes or newlines")" >&2
			exit 1
			;;
		*,*)
			printf '%s\n' "$(color red "Error: $flag_name cannot contain commas")" >&2
			exit 1
			;;
	esac

	printf '%s' "$pattern"
}

# Run a command on the remote host through the shared SSH control socket
ssh_exec() {
	ssh -o ControlPath="$SSH_CTL" "$SSH_TARGET" "$@"
}

# Lazily create the SSH_ASKPASS helper that prompts on /dev/tty for passwords
ensure_ssh_askpass_helper() {
	[ -n "$SSH_ASKPASS_HELPER" ] && return 0

	SSH_ASKPASS_HELPER="$(mktemp "${TMPDIR:-/tmp}/ssh-dl-askpass-XXXXXX")"

	cat > "$SSH_ASKPASS_HELPER" <<'SH'
#!/usr/bin/env bash
set -eu

tty="/dev/tty"
prompt="${1:-Password:}"
reply=""
secret=0
shown_prompt="$prompt"

case "$prompt" in
	*[Pp]assword*|*passphrase*)
		shown_prompt="Password:"
		secret=1
		;;
esac

cleanup() {
	if [ "$secret" -eq 1 ]; then
		stty echo < "$tty" 2>/dev/null || true
	fi
}
trap cleanup EXIT INT TERM

printf '%s' "$shown_prompt" > "$tty"
if [ "$secret" -eq 1 ]; then
	stty -echo < "$tty"
fi

IFS= read -r reply < "$tty"
printf '\n' > "$tty"

printf '%s\n' "$reply"
SH

	chmod 700 "$SSH_ASKPASS_HELPER"
}

# Open the reusable SSH control connection; retry with ASKPASS if key/agent auth
# fails
open_ssh_connection() {
	if ssh \
		-o LogLevel=ERROR \
		-o BatchMode=yes \
		-o ControlMaster=auto \
		-o ControlPersist=10m \
		-o ControlPath="$SSH_CTL" \
		-fN \
		"$SSH_TARGET" >/dev/null 2>&1; then
		SSH_AUTH_LABEL="ssh key, agent, or existing session"
		return 0
	fi

	printf "Auth          : %s\n" \
		"$(color yellow "password or key passphrase may be requested below")"

	ensure_ssh_askpass_helper

	DISPLAY="${DISPLAY:-ssh-dl}" \
	SSH_ASKPASS="$SSH_ASKPASS_HELPER" \
	SSH_ASKPASS_REQUIRE=force \
	ssh \
		-o LogLevel=ERROR \
		-o ControlMaster=auto \
		-o ControlPersist=10m \
		-o ControlPath="$SSH_CTL" \
		-fN \
		"$SSH_TARGET" </dev/null

	SSH_AUTH_LABEL="password or interactive authentication"
}

# Probe REMOTE_DIR as the login user; exit codes: 0 ok, 11 not found, 12 not a
# dir, 13 denied
remote_probe_dir_direct() {
	ssh_exec "sh -s -- '$REMOTE_DIR'" <<'SH'
dir=$1
if [ ! -e "$dir" ]; then
	exit 11
fi
if [ ! -d "$dir" ]; then
	exit 12
fi
if [ -r "$dir" ] && [ -x "$dir" ]; then
	exit 0
fi
exit 13
SH
}

# Probe REMOTE_DIR via passwordless sudo, using the same exit codes as the
# direct probe
remote_probe_dir_sudo_n() {
	ssh_exec "sudo -n sh -s -- '$REMOTE_DIR'" <<'SH'
dir=$1
if [ ! -e "$dir" ]; then
	exit 11
fi
if [ ! -d "$dir" ]; then
	exit 12
fi
if [ -r "$dir" ] && [ -x "$dir" ]; then
	exit 0
fi
exit 13
SH
}

# Probe REMOTE_DIR via sudo with the cached password piped on stdin
remote_probe_dir_sudo_s() {
	{
		printf '%s\n' "$SUDO_PASS"
		cat <<'SH'
dir=$1
if [ ! -e "$dir" ]; then
	exit 11
fi
if [ ! -d "$dir" ]; then
	exit 12
fi
if [ -r "$dir" ] && [ -x "$dir" ]; then
	exit 0
fi
exit 13
SH
	} | ssh_exec "sudo -S -p '' sh -s -- '$REMOTE_DIR'"
}

# True if the remote host has a `sudo` command on PATH
remote_sudo_available() {
	ssh_exec "sh -c 'command -v sudo >/dev/null 2>&1'" >/dev/null 2>&1
}

# True if passwordless or cached sudo currently works for the login user
remote_sudo_n_available() {
	ssh_exec "sudo -n true" >/dev/null 2>&1
}

# Map a dir-probe exit code to a human-readable reason for error messages
remote_probe_status_text() {
	case "$1" in
		0)  printf 'ok' ;;
		11) printf 'not found' ;;
		12) printf 'not a directory' ;;
		13) printf 'permission denied' ;;
		*)  printf 'unknown' ;;
	esac
}

# True if the candidate local filename already exists on disk or was claimed
# this run
name_taken() {
	local candidate="$1"
	local used

	if [ -e "$LOCAL_DEST/$candidate" ]; then
		return 0
	fi

	for used in "${USED_NAMES[@]}"; do
		if [ "$used" = "$candidate" ]; then
			return 0
		fi
	done

	return 1
}

# True if the given basename appears more than once in the scan results
basename_is_duplicated() {
	local candidate="$1"
	local dup_name

	for dup_name in "${DUP_BASENAMES[@]}"; do
		if [ "$dup_name" = "$candidate" ]; then
			return 0
		fi
	done

	return 1
}

# Return a local filename unused on disk and not yet claimed this run, appending
# ~N if needed
pick_unique_name() {
	local desired="$1"
	local candidate="$desired"
	local stem="$desired"
	local ext=""
	local n=2
	local used

	if [[ "$desired" == *.* && "$desired" != .* ]]; then
		stem="${desired%.*}"
		ext=".${desired##*.}"
	fi

	while :; do
		if ! name_taken "$candidate"; then
			printf '%s' "$candidate"
			return 0
		fi

		candidate="${stem}~${n}${ext}"
		n=$((n + 1))
	done
}

# Return a filename that does not yet exist under LOCAL_DEST, appending ~N if
# needed
pick_available_name() {
	local desired="$1"
	local candidate="$desired"
	local stem="$desired"
	local ext=""
	local n=2

	if [[ "$desired" == *.* && "$desired" != .* ]]; then
		stem="${desired%.*}"
		ext=".${desired##*.}"
	fi

	while [ -e "$LOCAL_DEST/$candidate" ]; do
		candidate="${stem}~${n}${ext}"
		n=$((n + 1))
	done

	printf '%s' "$candidate"
}

# Run the embedded scan script on the remote host with the current filter
# arguments
run_remote_scan() {
	local include_exts_arg=""
	local exclude_exts_arg=""
	local include_name_patterns_arg=""
	local exclude_name_patterns_arg=""
	local whole_dir_arg="0"
	local default_excludes_arg="1"
	local search_text_arg="$SEARCH_TEXT"

	if [ "${#INCLUDE_EXTS[@]}" -gt 0 ]; then
		include_exts_arg=$(printf '%s,' "${INCLUDE_EXTS[@]}")
		include_exts_arg="${include_exts_arg%,}"
	fi

	if [ "${#EXCLUDE_EXTS[@]}" -gt 0 ]; then
		exclude_exts_arg=$(printf '%s,' "${EXCLUDE_EXTS[@]}")
		exclude_exts_arg="${exclude_exts_arg%,}"
	fi

	if [ "${#INCLUDE_NAME_PATTERNS[@]}" -gt 0 ]; then
		include_name_patterns_arg=$(printf '%s,' "${INCLUDE_NAME_PATTERNS[@]}")
		include_name_patterns_arg="${include_name_patterns_arg%,}"
	fi

	if [ "${#EXCLUDE_NAME_PATTERNS[@]}" -gt 0 ]; then
		exclude_name_patterns_arg=$(printf '%s,' "${EXCLUDE_NAME_PATTERNS[@]}")
		exclude_name_patterns_arg="${exclude_name_patterns_arg%,}"
	fi

	if [ "$WHOLE_DIR_MODE" -eq 1 ]; then
		whole_dir_arg="1"
	fi

	if [ "$USE_DEFAULT_EXCLUDES" -eq 0 ]; then
		default_excludes_arg="0"
	fi

	case "$REMOTE_ACCESS_MODE" in
		direct)
			ssh_exec "$REMOTE_PYTHON -c '$REMOTE_SCAN_PY' '$REMOTE_DIR' '$COUNT' '$MIN_SIZE' '$MAX_SIZE' '$SORT_MODE' '$include_exts_arg' '$exclude_exts_arg' '$whole_dir_arg' '$default_excludes_arg' '$search_text_arg' '$include_name_patterns_arg' '$exclude_name_patterns_arg'"
			;;
		sudo-n)
			ssh_exec "sudo -n $REMOTE_PYTHON -c '$REMOTE_SCAN_PY' '$REMOTE_DIR' '$COUNT' '$MIN_SIZE' '$MAX_SIZE' '$SORT_MODE' '$include_exts_arg' '$exclude_exts_arg' '$whole_dir_arg' '$default_excludes_arg' '$search_text_arg' '$include_name_patterns_arg' '$exclude_name_patterns_arg'"
			;;
		sudo-s)
			printf '%s\n' "$SUDO_PASS" | \
				ssh_exec "sudo -S -p '' $REMOTE_PYTHON -c '$REMOTE_SCAN_PY' '$REMOTE_DIR' '$COUNT' '$MIN_SIZE' '$MAX_SIZE' '$SORT_MODE' '$include_exts_arg' '$exclude_exts_arg' '$whole_dir_arg' '$default_excludes_arg' '$search_text_arg' '$include_name_patterns_arg' '$exclude_name_patterns_arg'"
			;;
		*)
			printf '%s\n' "$(color red "Error: unknown remote access mode: $REMOTE_ACCESS_MODE")" >&2
			exit 1
			;;
	esac
}

# Stream a tar (or tar.gz) of the selected files from the remote host to stdout
run_remote_archive() {
	local pack_mode="gzip"

	if [ "$USE_COMPRESSION" -eq 0 ]; then
		pack_mode="plain"
	fi

	case "$REMOTE_ACCESS_MODE" in
		direct)
			awk -F'\t' '{ print $3 "\t" $4 }' "$DOWNLOAD_TSV" | \
				ssh_exec "$REMOTE_PYTHON -c '$REMOTE_PACK_PY' '$pack_mode'"
			;;
		sudo-n)
			awk -F'\t' '{ print $3 "\t" $4 }' "$DOWNLOAD_TSV" | \
				ssh_exec "sudo -n $REMOTE_PYTHON -c '$REMOTE_PACK_PY' '$pack_mode'"
			;;
		sudo-s)
			{
				printf '%s\n' "$SUDO_PASS"
				awk -F'\t' '{ print $3 "\t" $4 }' "$DOWNLOAD_TSV"
			} | ssh_exec "sudo -S -p '' $REMOTE_PYTHON -c '$REMOTE_PACK_PY' '$pack_mode'"
			;;
		*)
			printf '%s\n' "$(color red "Error: unknown remote access mode: $REMOTE_ACCESS_MODE")" >&2
			exit 1
			;;
	esac
}

# Parse and validate arguments
init_color

while [ "$#" -gt 0 ]; do
	case "$1" in
		-H|--host)
			[ -z "${2:-}" ] && usage
			REMOTE_HOST="$2"
			shift 2
			;;
		-u|--user)
			[ -z "${2:-}" ] && usage
			REMOTE_USER="$2"
			shift 2
			;;
		-r|--remote-dir)
			[ -z "${2:-}" ] && usage
			REMOTE_DIR="$2"
			shift 2
			;;
		-d|--dest)
			[ -z "${2:-}" ] && usage
			LOCAL_DEST="$2"
			shift 2
			;;
		-n|--count)
			[ -z "${2:-}" ] && usage
			COUNT="$2"
			shift 2
			;;
		-s|--min-size)
			[ -z "${2:-}" ] && usage
			MIN_SIZE="$2"
			shift 2
			;;
		-S|--max-size)
			[ -z "${2:-}" ] && usage
			MAX_SIZE="$2"
			shift 2
			;;
		-o|--sort)
			[ -z "${2:-}" ] && usage
			SORT_MODE="$2"
			shift 2
			;;
		-C|--contains)
			[ -z "${2:-}" ] && usage
			SEARCH_TEXT="$2"
			shift 2
			;;
		-R|--whole-dir)
			WHOLE_DIR_MODE=1
			shift
			;;
		-i|--include-ext)
			[ -z "${2:-}" ] && usage
			INCLUDE_EXTS+=("$2")
			shift 2
			;;
		-x|--exclude-ext)
			[ -z "${2:-}" ] && usage
			EXCLUDE_EXTS+=("$2")
			shift 2
			;;
		-N|--include-name)
			[ -z "${2:-}" ] && usage
			INCLUDE_NAME_PATTERNS+=("$2")
			shift 2
			;;
		-X|--exclude-name)
			[ -z "${2:-}" ] && usage
			EXCLUDE_NAME_PATTERNS+=("$2")
			shift 2
			;;
		-A|--no-default-skips|--no-name-skips|--no-default-excludes)
			USE_DEFAULT_EXCLUDES=0
			shift
			;;
		-z|--no-compress)
			USE_COMPRESSION=0
			shift
			;;
		-y|--yes)
			AUTO_YES=1
			shift
			;;
		-l|--list-only)
			LIST_ONLY=1
			shift
			;;
		-t|--stats-only)
			STATS_ONLY=1
			shift
			;;
		-h|--help)
			usage 0
			;;
		--)
			shift
			break
			;;
		-*)
			printf '%s\n\n' "$(color red "Unknown option: $1")" >&2
			usage
			;;
		*)
			printf '%s\n\n' "$(color red "Unexpected argument: $1")" >&2
			usage
			;;
	esac
done

missing=""
[ -z "$REMOTE_HOST" ] && missing="$missing --host"
[ -z "$REMOTE_USER" ] && missing="$missing --user"
[ -z "$REMOTE_DIR" ]  && missing="$missing --remote-dir"
[ -z "$LOCAL_DEST" ]  && missing="$missing --dest"

if [ -n "$missing" ]; then
	printf '%s\n\n' "$(color red "Error: missing required flag(s):$missing")" >&2
	usage
fi

case "$COUNT" in
	''|*[!0-9]*)
		printf '%s\n\n' "$(color red "Error: --count must be a positive integer, got: $COUNT")" >&2
		usage
		;;
esac

if [ "$COUNT" -eq 0 ]; then
	printf '%s\n\n' "$(color red "Error: --count must be greater than 0")" >&2
	usage
fi

if [ -n "$MIN_SIZE" ] && ! [[ "$MIN_SIZE" =~ ^[0-9]+[kmgtKMGT]?$ ]]; then
	printf '%s\n\n' "$(color red "Error: --min-size must be digits + optional k/m/g/t suffix, got: $MIN_SIZE")" >&2
	usage
fi

if [ -n "$MAX_SIZE" ] && ! [[ "$MAX_SIZE" =~ ^[0-9]+[kmgtKMGT]?$ ]]; then
	printf '%s\n\n' "$(color red "Error: --max-size must be digits + optional k/m/g/t suffix, got: $MAX_SIZE")" >&2
	usage
fi

case "$SEARCH_TEXT" in
	*\'*|*$'\n'*|*$'\r'*)
		printf '%s\n\n' "$(color red "Error: --contains cannot contain single quotes or newlines")" >&2
		usage
		;;
esac

SORT_MODE=$(printf '%s' "$SORT_MODE" | tr '[:upper:]' '[:lower:]')

case "$SORT_MODE" in
	newest|oldest|largest|smallest|name)
		;;
	*)
		printf '%s\n\n' "$(color red "Error: --sort must be one of: newest, oldest, largest, smallest, name")" >&2
		usage
		;;
esac

for val in "$REMOTE_HOST" "$REMOTE_USER" "$REMOTE_DIR" "$LOCAL_DEST"; do
	case "$val" in
		*\'*)
			printf '%s\n' "$(color red "Error: arguments cannot contain single quotes: $val")" >&2
			exit 1
			;;
	esac
done

LOCAL_DEST=$(expand_local_tilde "$LOCAL_DEST")

normalized_exts=()
for ext in "${INCLUDE_EXTS[@]}"; do
	normalized_exts+=("$(normalize_ext_filter "--include-ext" "$ext")")
done
INCLUDE_EXTS=("${normalized_exts[@]}")

normalized_exts=()
for ext in "${EXCLUDE_EXTS[@]}"; do
	normalized_exts+=("$(normalize_ext_filter "--exclude-ext" "$ext")")
done
EXCLUDE_EXTS=("${normalized_exts[@]}")

validated_patterns=()
for pattern in "${INCLUDE_NAME_PATTERNS[@]}"; do
	validated_patterns+=("$(validate_name_pattern "--include-name" "$pattern")")
done
INCLUDE_NAME_PATTERNS=("${validated_patterns[@]}")

validated_patterns=()
for pattern in "${EXCLUDE_NAME_PATTERNS[@]}"; do
	validated_patterns+=("$(validate_name_pattern "--exclude-name" "$pattern")")
done
EXCLUDE_NAME_PATTERNS=("${validated_patterns[@]}")

require_local_cmd ssh
require_local_cmd tar
require_local_cmd awk
require_local_cmd mktemp

mkdir -p "$LOCAL_DEST"

# Temporary files and cleanup
SCAN_TSV="$(mktemp)"
DOWNLOAD_TSV="$(mktemp)"
DUP_BASENAME_TSV="$(mktemp)"
SSH_CTL="$(mktemp -u "${TMPDIR:-/tmp}/ssh-dl-ssh-XXXXXX.sock")"

# EXIT trap: remove temp files, clear the sudo password, close the SSH control
# socket
cleanup() {
	rm -f "${SCAN_TSV:-}" "${DOWNLOAD_TSV:-}" "${DUP_BASENAME_TSV:-}" "${SSH_ASKPASS_HELPER:-}"
	unset SUDO_PASS || true
	if [ -n "${SSH_TARGET:-}" ] && [ -n "${SSH_CTL:-}" ]; then
		ssh -S "$SSH_CTL" -O exit "$SSH_TARGET" >/dev/null 2>&1 || true
	fi
}
trap cleanup EXIT

SSH_TARGET="${REMOTE_USER}@${REMOTE_HOST}"

# Open a reusable SSH connection
section "Opening SSH connection"

printf "Remote        : %s\n" "$(color cyan "$SSH_TARGET")"
printf "Destination   : %s\n" "$(color cyan "$LOCAL_DEST")"
printf "Session       : %s\n" "$(color dim "opening reusable SSH control connection")"

open_ssh_connection

printf "Status        : %s\n" "$(color green "connected")"
printf "Auth          : %s\n\n" "$(color green "$SSH_AUTH_LABEL")"

# Discover remote capabilities and access mode
section "Checking remote access"

REMOTE_PYTHON="$(ssh_exec "sh -c 'command -v python3 || command -v python || true'")"

if [ -z "$REMOTE_PYTHON" ]; then
	printf '%s\n' "$(color red "Error: remote host needs python3 or python in PATH")" >&2
	exit 1
fi

case "$REMOTE_DIR" in
	\~|\~/*)
		# shellcheck disable=SC2016
		REMOTE_HOME="$(ssh_exec 'printf %s "$HOME"')"
		if [ -z "$REMOTE_HOME" ]; then
			printf '%s\n' "$(color red "Error: could not resolve remote home directory for ~ expansion")" >&2
			exit 1
		fi
		if [ "$REMOTE_DIR" = "~" ]; then
			REMOTE_DIR="$REMOTE_HOME"
		else
			REMOTE_DIR="$REMOTE_HOME/${REMOTE_DIR#\~/}"
		fi
		;;
esac

printf "Folder        : %s\n" "$(color cyan "$REMOTE_DIR")"
printf "Python        : %s\n" "$(color cyan "$REMOTE_PYTHON")"

set +e
remote_probe_dir_direct >/dev/null 2>&1
probe_status=$?
set -e

direct_probe_status="$probe_status"

if [ "$probe_status" -eq 0 ]; then
	REMOTE_ACCESS_MODE="direct"
	REMOTE_ACCESS_LABEL="direct access"
else
	if ! remote_sudo_available; then
		printf '%s\n' "$(color red "Error: remote path is inaccessible without sudo, and sudo is unavailable: $REMOTE_DIR")" >&2
		printf '%s\n' "$(color dim "Direct probe result: $(remote_probe_status_text "$direct_probe_status")")" >&2
		exit 1
	fi

	if remote_sudo_n_available; then
		set +e
		remote_probe_dir_sudo_n >/dev/null 2>&1
		probe_status=$?
		set -e

		if [ "$probe_status" -eq 0 ]; then
			REMOTE_ACCESS_MODE="sudo-n"
			REMOTE_ACCESS_LABEL="passwordless or cached sudo"
		elif [ "$probe_status" -eq 11 ] || [ "$probe_status" -eq 12 ]; then
			printf '%s\n' "$(color red "Error: remote path is $(remote_probe_status_text "$probe_status"): $REMOTE_DIR")" >&2
			exit 1
		else
			printf '%s\n' "$(color red "Error: unable to access remote path even with sudo: $REMOTE_DIR")" >&2
			printf '%s\n' "$(color dim "Direct probe result: $(remote_probe_status_text "$direct_probe_status")")" >&2
			exit 1
		fi
	else
		read -r -s -p "Remote sudo password: " SUDO_PASS
		printf '\n'

		if ! printf '%s\n' "$SUDO_PASS" | ssh_exec "sudo -S -p '' -v" >/dev/null 2>&1; then
			printf '\n%s\n' "$(color red "Error: remote sudo authentication failed")" >&2
			exit 1
		fi

		set +e
		remote_probe_dir_sudo_s >/dev/null 2>&1
		probe_status=$?
		set -e

		if [ "$probe_status" -eq 0 ]; then
			REMOTE_ACCESS_MODE="sudo-s"
			REMOTE_ACCESS_LABEL="sudo with password"
		elif [ "$probe_status" -eq 11 ] || [ "$probe_status" -eq 12 ]; then
			printf '%s\n' "$(color red "Error: remote path is $(remote_probe_status_text "$probe_status"): $REMOTE_DIR")" >&2
			exit 1
		else
			printf '%s\n' "$(color red "Error: unable to access remote path with sudo: $REMOTE_DIR")" >&2
			printf '%s\n' "$(color dim "Direct probe result: $(remote_probe_status_text "$direct_probe_status")")" >&2
			exit 1
		fi
	fi
fi

printf "Access mode   : %s\n\n" "$(color green "$REMOTE_ACCESS_LABEL")"

# Scan the remote folder and build the file list
section "Scanning remote folder"

if [ "$WHOLE_DIR_MODE" -eq 1 ]; then
	printf "Mode          : %s\n" "$(color cyan "whole directory tree")"
	printf "Filters       : %s\n" "$(color dim "--count, --min-size, --max-size, and --sort ignored")"
else
	printf "Limit         : %s\n" "$(color cyan "$COUNT")"
	printf "Sort          : %s\n" "$(color cyan "$SORT_MODE")"
	printf "Min size      : %s\n" "$(color cyan "${MIN_SIZE:-<none>}")"
	printf "Max size      : %s\n" "$(color cyan "${MAX_SIZE:-<none>}")"
fi

if [ -n "$SEARCH_TEXT" ]; then
	printf "Contains      : %s\n" "$(color cyan "$SEARCH_TEXT")"
else
	printf "Contains      : %s\n" "$(color dim "<none>")"
fi

if [ "${#INCLUDE_NAME_PATTERNS[@]}" -gt 0 ]; then
	include_name_display=$(printf '%s, ' "${INCLUDE_NAME_PATTERNS[@]}")
	include_name_display="${include_name_display%, }"
	printf "Name include  : %s\n" "$(color cyan "$include_name_display")"
else
	printf "Name include  : %s\n" "$(color dim "<none>")"
fi

if [ "${#EXCLUDE_NAME_PATTERNS[@]}" -gt 0 ]; then
	exclude_name_display=$(printf '%s, ' "${EXCLUDE_NAME_PATTERNS[@]}")
	exclude_name_display="${exclude_name_display%, }"
	printf "Name exclude  : %s\n" "$(color cyan "$exclude_name_display")"
else
	printf "Name exclude  : %s\n" "$(color dim "<none>")"
fi

if [ "$USE_DEFAULT_EXCLUDES" -eq 1 ]; then
	printf "Default skips : %s\n\n" "$(color cyan "built-in temp/bookkeeping patterns")"
else
	printf "Default skips : %s\n\n" "$(color yellow "disabled")"
fi

run_remote_scan > "$SCAN_TSV"

if [ ! -s "$SCAN_TSV" ]; then
	printf '%s\n' "$(color yellow "No matching files found.")"
	exit 0
fi

file_count=$(wc -l < "$SCAN_TSV" | tr -d ' ')
total_bytes=$(awk -F'\t' '{ sum += $2 } END { print sum+0 }' "$SCAN_TSV")

USED_NAMES=()
DUP_BASENAMES=()

awk -F'\t' '
	{ counts[$3]++ }
	END {
		for (name in counts) {
			if (counts[name] > 1) {
				print name
			}
		}
	}
' "$SCAN_TSV" > "$DUP_BASENAME_TSV"

while IFS= read -r dup_name; do
	[ -n "$dup_name" ] || continue
	DUP_BASENAMES+=("$dup_name")
done < "$DUP_BASENAME_TSV"

while IFS=$'\t' read -r ts bytes store_name path; do
	if [ "$WHOLE_DIR_MODE" -eq 1 ]; then
		local_name="$store_name"
	else
		rel_path=$(relative_remote_path "$path")

		preferred_name="$store_name"
		if [ "$rel_path" != "$store_name" ]; then
			if basename_is_duplicated "$store_name" || name_taken "$store_name"; then
				preferred_name="$rel_path"
			fi
		fi

		local_name=$(pick_unique_name "$preferred_name")
		USED_NAMES+=("$local_name")
	fi

	printf '%s\t%s\t%s\t%s\n' "$ts" "$bytes" "$local_name" "$path" >> "$DOWNLOAD_TSV"
done < "$SCAN_TSV"

printf "Files found   : %s\n" "$(color green "$file_count")"
printf "Total size    : %s\n\n" "$(color green "$(human_size "$total_bytes")")"

if [ "$WHOLE_DIR_MODE" -eq 1 ]; then
	root_folder=$(whole_dir_root)
	if [ "$STATS_ONLY" -eq 0 ]; then
		printf "Folder tree   : %s\n\n" "$(color cyan "${root_folder:-remote-root}")"
	fi
elif [ "$STATS_ONLY" -eq 0 ]; then
	max_size_len=0
	while IFS=$'\t' read -r _ts bytes _local_name _path; do
		sz=$(human_size "$bytes")
		if [ "${#sz}" -gt "$max_size_len" ]; then
			max_size_len="${#sz}"
		fi
	done < "$DOWNLOAD_TSV"

	while IFS=$'\t' read -r ts bytes local_name path; do
		rel_path=$(relative_remote_path "$path")
		rel_base=$(basename "$rel_path")
		ts_short="${ts:0:16}"
		sz=$(human_size "$bytes")
		sz_padded=$(printf "%*s" "$max_size_len" "$sz")
		if [ "$rel_path" = "$local_name" ] || [ "$rel_base" = "$local_name" ]; then
			display_name="$rel_path"
		else
			display_name="$rel_path (saved as $local_name)"
		fi

		printf "  %s  %s  %s\n" \
			"$(color dim "$ts_short")" \
			"$(color cyan "$sz_padded")" \
			"$display_name"
	done < "$DOWNLOAD_TSV"

	printf '\n'
fi

if [ "$LIST_ONLY" -eq 1 ]; then
	section "Complete"
	printf "Mode          : %s\n" "$(color green "list only")"
	printf "Download      : %s\n" "$(color dim "skipped")"
	exit 0
fi

if [ "$WHOLE_DIR_MODE" -eq 1 ]; then
	if [ "$AUTO_YES" -eq 1 ]; then
		printf "Downloading folder tree %s to %s.\n\n" \
			"$(color cyan "${root_folder:-$(whole_dir_root)}")" "$(color cyan "$LOCAL_DEST")"
	else
		printf "Download folder tree %s to %s? [y/N] " \
			"$(color cyan "${root_folder:-$(whole_dir_root)}")" "$(color cyan "$LOCAL_DEST")"
		read -r ans

		case "$ans" in
			y|Y|yes|YES) ;;
			*)
				printf '%s\n' "$(color red "Cancelled.")"
				exit 0
				;;
		esac

		printf '\n'
	fi
elif [ "$AUTO_YES" -eq 1 ]; then
	printf "Downloading to %s.\n\n" "$(color cyan "$LOCAL_DEST")"
else
	printf "Download to %s? [y/N] " "$(color cyan "$LOCAL_DEST")"
	read -r ans

	case "$ans" in
		y|Y|yes|YES) ;;
		*)
			printf '%s\n' "$(color red "Cancelled.")"
			exit 0
			;;
	esac

	printf '\n'
fi

# Download the selected files or folder tree
section "Downloading"

if [ "$USE_COMPRESSION" -eq 1 ]; then
	printf "Packing and streaming %s files as %s...\n\n" \
		"$(color cyan "$file_count")" "$(color cyan "tar.gz")"
	run_remote_archive | tar -xzf - -C "$LOCAL_DEST"
else
	printf "Packing and streaming %s files as %s...\n\n" \
		"$(color cyan "$file_count")" "$(color cyan "tar")"
	run_remote_archive | tar -xf - -C "$LOCAL_DEST"
fi

unset SUDO_PASS || true

downloaded_count=0
downloaded_bytes=0
while IFS=$'\t' read -r _ts _bytes local_name _path; do
	local_file="$LOCAL_DEST/$local_name"
	if [ -f "$local_file" ]; then
		sz=$(file_size "$local_file")
		downloaded_bytes=$((downloaded_bytes + sz))
		downloaded_count=$((downloaded_count + 1))
	fi
done < "$DOWNLOAD_TSV"

if [ "$downloaded_count" -eq "$file_count" ]; then
	printf "Downloaded    : %s\n" "$(color green "$downloaded_count / $file_count files")"
else
	printf "Downloaded    : %s\n" "$(color yellow "$downloaded_count / $file_count files")"
fi
printf "Size          : %s\n\n" "$(color green "$(human_size "$downloaded_bytes")")"

# Add extensions based on local MIME detection
if [ "$WHOLE_DIR_MODE" -eq 0 ]; then
	section "Adding extensions"

	if ! command -v file >/dev/null 2>&1; then
		printf '%s\n\n' "$(color yellow "Skipping: local 'file' command not found.")"
	else
		renamed=0
		deduped=0
		skipped=0

		while IFS=$'\t' read -r _ts _bytes local_name _path; do
			f="$LOCAL_DEST/$local_name"
			base=$(basename "$local_name")

			case "$base" in
				*.*) continue ;;
			esac

			[ -f "$f" ] || continue

			mime=$(file -b --mime-type "$f" 2>/dev/null || true)

			case "$mime" in
				video/mp4)             ext="mp4" ;;
				video/quicktime)       ext="mov" ;;
				video/webm)            ext="webm" ;;
				video/x-matroska)      ext="mkv" ;;
				image/jpeg)            ext="jpg" ;;
				image/png)             ext="png" ;;
				image/webp)            ext="webp" ;;
				image/gif)             ext="gif" ;;
				image/heic|image/heif) ext="heic" ;;
				audio/mpeg)            ext="mp3" ;;
				audio/mp4)             ext="m4a" ;;
				audio/ogg)             ext="ogg" ;;
				audio/opus)            ext="opus" ;;
				audio/x-wav|audio/wav) ext="wav" ;;
				application/pdf)       ext="pdf" ;;
				application/zip)       ext="zip" ;;
				*)                     ext="" ;;
			esac

			if [ -z "$ext" ]; then
				skipped=$((skipped + 1))
				continue
			fi

			new="$f.$ext"

			if [ -e "$new" ]; then
				if cmp -s "$f" "$new" 2>/dev/null; then
					rm -f "$f"
					deduped=$((deduped + 1))
				else
					new_name=$(pick_available_name "${local_name}.${ext}")
					mv "$f" "$LOCAL_DEST/$new_name"
					renamed=$((renamed + 1))
				fi
			else
				mv "$f" "$new"
				renamed=$((renamed + 1))
			fi
		done < "$DOWNLOAD_TSV"

		printf "Renamed       : %s\n" "$(color green "$renamed")"
		printf "Deduped       : %s\n" "$(color dim "$deduped")"
		printf "Skipped       : %s\n\n" "$(color dim "$skipped")"
	fi
fi

# Done
section "Complete"

printf "Saved into    : %s\n" "$(color green "$LOCAL_DEST")"
