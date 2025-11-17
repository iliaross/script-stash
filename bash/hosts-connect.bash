#!/usr/bin/env bash
# hosts-connect.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This is a helper script to connect to "debug-*" hosts from /etc/hosts.
#
# Usage:
#   hosts-connect.bash host
#   hosts-connect.bash "<ssh-params>" host
#   hosts-connect.bash --password host
#   hosts-connect.bash --password "<ssh-params>" host
#   echo "secret" | hosts-connect.bash --password host
#
# Password:
#   - Uses DEBUG_SSHPASS environment variable if set
#   - If --password flag is given:
#       * If running in a terminal, it will prompt (masked).
#       * If not a terminal (e.g. piped), it will read one line from stdin.

readonly hosts_file="/etc/hosts"

prompt_password() {
	local pw=""
	if [ -t 0 ]; then
		# Interactive prompt, masked
		printf "Enter SSH password: " >&2
		IFS= read -rs pw
		printf '\n' >&2
	else
		# Non-interactive: read from stdin
		if ! IFS= read -r pw; then
			echo "hosts-connect.bash: --password used but no password was read from stdin" >&2
			exit 1
		fi
	fi
	printf '%s' "$pw"
}

password=""

# Handle explicit --password flag
if [ "${1:-}" = "--password" ]; then
	password="$(prompt_password)"
	shift
else
	# Try env var first
	password="${DEBUG_SSHPASS:-}"
fi

# If still empty and interactive, ask nicely
if [ -z "$password" ] && [ -t 0 ]; then
	password="$(prompt_password)"
fi

if [ -z "$password" ]; then
	echo "Error: no password available (set DEBUG_SSHPASS or use --password)." >&2
	exit 1
fi

# Require at least a host
if [ $# -lt 1 ]; then
	echo "Usage: hosts-connect.bash [--password] [ssh-params] host" >&2
	exit 1
fi

# Params / host handling (optional params as first arg)
if [ -z "${2:-}" ]; then
	params=""
	host="$1"
else
	params="$1"
	host="$2"
fi

# If user didn't include debug- prefix, add it for lookup
if [[ "$host" == debug-* ]]; then
	search="$host"
else
	search="debug-$host"
fi

# Find first matching debug host from /etc/hosts (FQDN). Match any hostname that
# starts with a search.
host_fqdn="$(
	awk -v h="$search" '
	{
		for (i = 2; i <= NF; i++) {
			if (index($i, h) == 1) {
				print $i
				exit
			}
		}
	}
	' "$hosts_file"
)"

if [ -z "$host_fqdn" ]; then
	echo "ssh: $search: Name or service not known" >&2
	exit 1
fi

nosec=(
	-o UserKnownHostsFile=/dev/null
	-o StrictHostKeyChecking=no
	-o PasswordAuthentication=yes
	-o PreferredAuthentications=password
	-o PubkeyAuthentication=no
	-o LogLevel=QUIET
)

exec sshpass -p "$password" ssh $params "${nosec[@]}" "root@$host_fqdn"
