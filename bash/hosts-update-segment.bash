#!/usr/bin/env bash
# hosts-update-segment.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script manages /etc/hosts entries for a specific segment block.
#
# In simple terms:
# - Segment:
#   A label for a group of systems, e.g. "Parallels".
#   You can run the script like:
#     ./hosts-update-segment.bash
#     ./hosts-update-segment.bash Parallels
#     ./hosts-update-segment.bash Parallels /custom/backup/dir
#   If the first argument is omitted, it defaults to "Parallels".
#
# - Systems:
#   A list of machines with their IPs in "name/ip" form.
#   Example entries:
#     alma10-pro/10.211.55.34
#     ubuntu24-gpl/10.211.55.5
#
# - Domains:
#   One or more base domains that will be combined with each system name.
#   Example:
#     virtualmin.dev
#
# - Records:
#   Hostname prefixes that will be combined with each system and domain.
#   Example:
#     host autoconfig mail www
#
# For each system, the script generates lines like:
#   <ip> debug-<name>.<domain> <name>.<domain> <record1>.<name>.<domain> ...
#
# The script only touches the "operational area" under a matching header
# and leaves everything else in /etc/hosts unchanged.
#
# Backup location:
#   A backup of /etc/hosts is made before any modification.
#
#   Examples:
#     ./hosts-update-segment.bash
#     ./hosts-update-segment.bash Parallels /var/backups/hosts
#
# The script expects a header block in /etc/hosts that looks like this:
#
#   # Segment: Parallels [auto-local]
#   # Systems: alma10-pro/10.211.55.34 ubuntu24-gpl/10.211.55.5
#   # Domains: virtualmin.dev
#   # Records: host autoconfig autodiscover mail webmail admin ftp www
#
# It will:
#   - Find the matching "# Segment: <name> [auto|auto-local]" block
#   - Read the Systems, Domains and Records lines
#   - Replace the lines below them (until the next "#" line or end of file)
#     with freshly generated /etc/hosts entries

set -euo pipefail

# Configuration
HOSTS_FILE="/etc/hosts"
SEGMENT="${1:-Parallels}"

BACKUP_DIR_DEFAULT="$HOME/Backups/System/etc"
if [ "${2:-}" != "" ]; then
	BACKUP_DIR="$2"
else
	BACKUP_DIR="${BACKUP_DIR:-$BACKUP_DIR_DEFAULT}"
fi

# Colors (disable with NO_COLOR or non-tty)
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	use_color=1
else
	use_color=0
fi

# Helper functions
color() {
	local c="$1" s="$2"
	if [ "$use_color" -eq 0 ]; then
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

section() {
	local title="$1"
	local bar
	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

trim() {
	sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# Print starting message
section "Detecting segment block"

# Find the start line of the relevant segment block
start_line="$(
	grep -nE "^[[:space:]]*# [[:space:]]*Segment[[:space:]]*:?[[:space:]]*${SEGMENT}[[:space:]]*\[auto(-local)?\]" "$HOSTS_FILE" \
		| head -n1 \
		| cut -d: -f1
)" || true

if [ -z "${start_line:-}" ]; then
	printf '%s\n' "$(color red "Error: No relevant segment block found for: $SEGMENT")" >&2
	exit 1
fi

printf "Hosts file : %s\n" "$(color cyan "$HOSTS_FILE")"
printf "Segment    : %s (line %s)\n" "$(color cyan "$SEGMENT")" "$start_line"
printf "Backup dir : %s\n\n" "$(color cyan "$BACKUP_DIR")"

systems_line="$(sed -n "$((start_line + 1))p" "$HOSTS_FILE" || true)"
domains_line="$(sed -n "$((start_line + 2))p" "$HOSTS_FILE" || true)"
records_line="$(sed -n "$((start_line + 3))p" "$HOSTS_FILE" || true)"

# Validate block header lines
if [ -z "$systems_line" ] || [ -z "$domains_line" ] || [ -z "$records_line" ]; then
	printf '%s\n' "$(color red "Error: Block header incomplete after segment line.")" >&2
	exit 1
fi

if ! printf '%s\n' "$systems_line" | grep -qE '^[[:space:]]*#\s*Systems\s*:'; then
	printf '%s\n' "$(color red "Error: Expected '# Systems   :' after segment line.")" >&2
	exit 1
fi

if ! printf '%s\n' "$domains_line" | grep -qE '^[[:space:]]*#\s*Domains\s*:'; then
	printf '%s\n' "$(color red "Error: Expected '# Domains   :' after systems line.")" >&2
	exit 1
fi

if ! printf '%s\n' "$records_line" | grep -qE '^[[:space:]]*#\s*Records\s*:'; then
	printf '%s\n' "$(color red "Error: Expected '# Records   :' after domains line.")" >&2
	exit 1
fi

# Locate the boundaries of the block to be replaced
section "Locating block boundaries"

s=$((start_line + 3))
next_hash="$(awk -v s="$s" 'NR > s && /^#/ { print NR; exit }' "$HOSTS_FILE")"

if [ -n "$next_hash" ]; then
	block_end=$((next_hash - 1))
else
	block_end=$(wc -l < "$HOSTS_FILE")
fi

data_start=$((start_line + 4))
data_end="$block_end"

printf "Operational area: lines %s to %s\n\n" "$data_start" "$data_end"

# Parse systems, domains and records
section "Parsing systems, domains and records"

systems_str="${systems_line#*:}"
systems_str="$(printf '%s\n' "$systems_str" | trim)"

domains_str="${domains_line#*:}"
domains_str="$(printf '%s\n' "$domains_str" | trim)"

records_str="${records_line#*:}"
records_str="$(printf '%s\n' "$records_str" | trim)"

IFS=' ' read -r -a systems <<<"$systems_str"
IFS=' ' read -r -a domains <<<"$domains_str"
IFS=' ' read -r -a records <<<"$records_str"

if [ "${#systems[@]}" -eq 0 ]; then
	printf '%s\n' "$(color red "Error: No systems defined in Systems line.")" >&2
	exit 1
fi
if [ "${#domains[@]}" -eq 0 ]; then
	printf '%s\n' "$(color red "Error: No domains defined in Domains line.")" >&2
	exit 1
fi
if [ "${#records[@]}" -eq 0 ]; then
	printf '%s\n' "$(color red "Error: No records defined in Records line.")" >&2
	exit 1
fi

printf "Systems : %s\n"  "$(color dim "${systems[*]}")"
printf "Domains : %s\n"  "$(color dim "${domains[*]}")"
printf "Records : %s\n\n" "$(color dim "${records[*]}")"

# Compute max IP length for alignment
max_ip_len=0
for sys in "${systems[@]}"; do
	case "$sys" in
		*/*)
			ip="${sys##*/}"
			len=${#ip}
			if [ "$len" -gt "$max_ip_len" ]; then
				max_ip_len="$len"
			fi
			;;
		*)
			:
			;;
	esac
done

# Backup and prepare output
section "Backing up and preparing output"

mkdir -p "$BACKUP_DIR"
backup="${BACKUP_DIR}/hosts.$(date +%Y%m%d%H%M%S)"
tmpfile="$(mktemp)"

cp "$HOSTS_FILE" "$backup"
printf "Backup saved to: %s\n\n" "$(color green "$backup")"

# Copy everything up to and including the block header
sed -n "1,$((start_line + 3))p" "$HOSTS_FILE" >"$tmpfile"
printf '\n' >>"$tmpfile"

# Generate new hosts entries (grouped by label and aligned)
prev_label=""

for sys in "${systems[@]}"; do
	case "$sys" in
		*/*)
			name="${sys%%/*}"
			ip="${sys##*/}"
			;;
		*)
			printf '%s\n' "$(color yellow "Warning: Skipping malformed system entry: $sys")" >&2
			continue
			;;
	esac

	label="$(printf '%s\n' "$name" | sed -E 's/^([A-Za-z]+).*/\1/')"

	if [ -n "$prev_label" ] && [ "$label" != "$prev_label" ]; then
		printf '\n' >>"$tmpfile"
	fi
	prev_label="$label"

	all_names=()

	for dom in "${domains[@]}"; do
		base="${name}.${dom}"
		debug="debug-${name}.${dom}"

		all_names+=( "$debug" "$base" )

		for r in "${records[@]}"; do
			all_names+=( "${r}.${name}.${dom}" )
		done
	done

	# IP padded to max width, then one space, then all hostnames
	printf '%-*s ' "$max_ip_len" "$ip" >>"$tmpfile"
	for hn in "${all_names[@]}"; do
		printf '%s ' "$hn" >>"$tmpfile"
	done
	printf '\n' >>"$tmpfile"
done

printf '\n' >>"$tmpfile"

# Append everything after the old block
sed -n "$((data_end + 1)),\$p" "$HOSTS_FILE" >>"$tmpfile"

section "Writing updated hosts file"

cat "$tmpfile" >"$HOSTS_FILE"
rm -f "$tmpfile"

printf "%s\n" "$(color green "Updated $HOSTS_FILE for segment: $SEGMENT")"
