#!/usr/bin/env bash
# hosts-sync-exec.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# Convenience wrapper around hosts-sync.bash remote-command mode.
#
# Usage:
#   hosts-sync-exec.bash ls -lsa
#   hosts-sync-exec.bash rm -f /root/bad-file
#   hosts-sync-exec.bash --running:rocky9-gpl systemctl status webmin
#   hosts-sync-exec.bash --regex:synology.gdn uname -a
#   hosts-sync-exec.bash --all uptime

set -euo pipefail

resolve_script_path() {
	local path="$1"
	local dir=""

	while [ -L "$path" ]; do
		dir="$(cd "$(dirname "$path")" && pwd)"
		path="$(readlink "$path")"
		case "$path" in
			/*) ;;
			*) path="${dir}/${path}" ;;
		esac
	done

	dir="$(cd "$(dirname "$path")" && pwd)"
	printf '%s/%s\n' "$dir" "$(basename "$path")"
}

script_path="$(resolve_script_path "${BASH_SOURCE[0]}")"
script_dir="$(cd "$(dirname "$script_path")" && pwd)"
hosts_sync="${script_dir}/hosts-sync.bash"
script_name="$(basename "$0")"

usage() {
	cat <<EOF
Usage:
  ${script_name} [--running|--running:<name>] [--regex:<pattern>] [--all] [--] <command> [args...]

Examples:
  ${script_name} ls -lsa
  ${script_name} rm -f /root/bad-file
  ${script_name} --running:rocky9-gpl systemctl status webmin
  ${script_name} --regex:synology.gdn uname -a
  ${script_name} --all uptime
EOF
}

if [ ! -x "$hosts_sync" ]; then
	printf 'Error: required helper not found or not executable: %s\n' "$hosts_sync" >&2
	exit 1
fi

declare -a control_args
declare -a command_args
control_args=()
command_args=()

default_running=1

while [ $# -gt 0 ]; do
	case "$1" in
		--help|-h)
			usage
			exit 0
			;;
		--)
			shift
			command_args=( "$@" )
			break
			;;
		--all)
			default_running=0
			shift
			;;
		--running|--running:*|--regex:*)
			control_args+=( "$1" )
			if [[ "$1" == --running* ]]; then
				default_running=0
			fi
			shift
			;;
		-*)
			# Treat unknown flags as part of the remote command.
			command_args+=( "$1" )
			shift
			while [ $# -gt 0 ]; do
				command_args+=( "$1" )
				shift
			done
			break
			;;
		*)
			command_args+=( "$1" )
			shift
			while [ $# -gt 0 ]; do
				command_args+=( "$1" )
				shift
			done
			break
			;;
	esac
done

if [ "${#command_args[@]}" -eq 0 ]; then
	usage >&2
	exit 1
fi

if [ "$default_running" -eq 1 ]; then
	control_args=( "--running" "${control_args[@]}" )
fi

declare -a quoted_command
quoted_command=()
for arg in "${command_args[@]}"; do
	printf -v q '%q' "$arg"
	quoted_command+=( "$q" )
done
remote_command="${quoted_command[*]}"

arg2="${control_args[0]:-}"
arg3="${control_args[1]:-}"
arg4="${control_args[2]:-}"

exec "$hosts_sync" "" "$arg2" "$arg3" "$arg4" "$remote_command"
