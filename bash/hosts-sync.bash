#!/usr/bin/env bash
# hosts-sync.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script syncs local Git projects to remote "debug-*" hosts defined in
# /etc/hosts. Specifically supports Webmin and its modules but can be adapted
# for any other projects as well.
#
# It can work together with:
#
#   hosts-update-segment.bash
#
# Features
#   - Scans /etc/hosts for all "debug-*" entries. If an entry contains a port
#     (e.g. debug-cloud-pubkey-1.2.3.4:2222), it prefers connecting by IP
#     and uses that port for SSH/rsync.
#   - Detects "local" debug bases only from [auto-local] segments
#   - Detects locally running virtual machines via "prlctl" or "virsh" and
#     matches them to those bases
#   - Maps project roots to proper Webmin/Usermin/module paths on the target
#   - Filters hosts by:
#       --running             (only running local VMs)
#       --running:<name>      (only a specific local VM, e.g. rocky10-pro)
#       --running=<file-name> (sync only that file to all running local VMs)
#       --regex:<pattern>     (only hosts whose FQDN matches pattern)
#   - Syncs either:
#       * a full project tree, or
#       * a single file inside the project
#   - Can also run remote commands instead of rsync (upgrade-packages, sync-ssl,
#     sync-time, etc.)
#
# SSH password:
#   The SSH password is read from the DEBUG_SSHPASS environment variable.
#
# Examples:
#
#   # Sync project to all debug hosts
#   ./hosts-sync.bash /path/to/project
#
#   # Sync project only to hosts matching a domain pattern
#   ./hosts-sync.bash /path/to/project --regex:synology.gdn
#   ./hosts-sync.bash /path/to/project --regex:webmin.dev
#
#   # Sync full project to all running local VMs
#   ./hosts-sync.bash /path/to/project --running
#
#   # Sync full project to a specific running VM
#   ./hosts-sync.bash /path/to/project --running:debian12-pro
#
#   # Sync a single file to all running local VMs
#   ./hosts-sync.bash /path/to/project --running=authentic.pl
#
#   # Sync a single file to all selected hosts (no running filter)
#   ./hosts-sync.bash /path/to/project miniserv.pl
#
#   # Run a remote maintenance command on all running local VMs
#   ./hosts-sync.bash "" --running "" "" "upgrade-packages"
#
#   # Run a remote command on hosts matched by regex only (no running filter)
#   ./hosts-sync.bash "" --regex:webmin.dev "" "" "upgrade-packages"
#
#   # Push SSL cert or sync time to running local VMs
#   ./hosts-sync.bash "" --running "" "" "sync-ssl"
#   ./hosts-sync.bash "" --running "" "" "sync-time"

readonly hosts_file="/etc/hosts"
readonly git_home="${HOME}/Git"

readonly sed_cmd="sed"
readonly rsync_cmd="rsync"
readonly ssh_cmd="ssh"
readonly sshpass_cmd="sshpass"
readonly nohup_cmd="nohup"

readonly default_user="root"
readonly sshnocheck='-o ConnectTimeout=1 -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o LogLevel=QUIET'

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
	use_color=1
else
	use_color=0
fi

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
	$sed_cmd -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

in_list() {
	local needle="$1"; shift || true
	for x in "$@"; do
		[ "$x" = "$needle" ] && return 0
	done
	return 1
}

get_host_port() {
	local key="$1"
	local i
	for (( i = 0; i < ${#host_ports_keys[@]}; i++ )); do
		if [ "${host_ports_keys[$i]}" = "$key" ]; then
			printf '%s\n' "${host_ports_vals[$i]}"
			return 0
		fi
	done
	return 1
}

get_host_ip() {
	local key="$1"
	local i
	for (( i = 0; i < ${#host_ips_keys[@]}; i++ )); do
		if [ "${host_ips_keys[$i]}" = "$key" ]; then
			printf '%s\n' "${host_ips_vals[$i]}"
			return 0
		fi
	done
	return 1
}

# Main arguments
project_arg="${1:-}"
arg2="${2:-}"
arg3="${3:-}"
arg4="${4:-}"
sshcmd="${5:-}"

running_mode=0
target_name=""
domain_filter=""
single_file_sync=0
single_file_name=""

if printf '%s %s %s %s\n' "$arg2" "$arg3" "$arg4" "$sshcmd" | grep -q -- '--running'; then
	running_mode=1
fi

if [[ "$arg2" == --running:* ]]; then
	val="${arg2#--running:}"
	val="${val#debug-}"
	target_name="${val%%.*}"
elif [[ "$arg2" == --running=* ]]; then
	val="${arg2#--running=}"
	single_file_sync=1
	single_file_name="$val"
fi

if printf '%s %s %s %s\n' "$arg2" "$arg3" "$arg4" "$sshcmd" | grep -q -- '--regex:'; then
	regex_val="$(printf '%s %s %s %s\n' "$arg2" "$arg3" "$arg4" "$sshcmd" \
		| grep -o -- '--regex:[^[:space:]]*' \
		| head -n1)"
	domain_filter="${regex_val#--regex:}"
	domain_filter="$(printf '%s\n' "$domain_filter" | trim)"
fi

# Arguments and mode
section "Arguments and mode"

if [ -n "$project_arg" ]; then
	case "$project_arg" in
		~/*) project_abs="${HOME}/${project_arg#~/}" ;;
		/*)  project_abs="$project_arg" ;;
		*)   project_abs="$project_arg" ;;
	esac
else
	project_abs=""
fi

pretty_git_home="${git_home/$HOME/~}"
pretty_project="${project_abs/$HOME/~}"

printf "Project : %s\n" "$(color cyan "${pretty_project:-<none>}")"
printf "Running : %s\n" "$(color cyan "$([ "$running_mode" -eq 1 ] && echo yes || echo no)")"
printf "Target  : %s\n" "$(color cyan "${target_name:-<all>}")"
printf "Regex   : %s\n\n" "$(color cyan "${domain_filter:-<none>}")"

# Project detection
section "Project detection"

if [ -z "$project_abs" ] && [ -z "$sshcmd" ]; then
	printf "%s\n" "$(color red "Error: Specify project directory (or provide ssh command only).")" >&2
	exit 1
fi

if [ -n "$project_abs" ]; then
	case "$project_abs" in
		"$git_home"/*)
			;;
		*)
			if [ -z "$sshcmd" ]; then
				printf "%s\n" "$(color red "Error: Requested project directory is outside safe '$git_home' path")" >&2
				exit 1
			else
				project_abs="/path/to/project"
			fi
			;;
	esac
fi

project_rel="${project_abs#"${git_home}/"}"
project_root="${project_rel%%/*}"

printf "Git home : %s\n" "$(color cyan "$pretty_git_home")"
printf "Project  : %s\n" "$(color cyan "${pretty_project:-<none>}")"
printf "Root     : %s\n\n" "$(color cyan "${project_root:-<none>}")"

# Debug-bash should never sync
if [ "$project_root" = "debug-bash" ]; then
	printf "%s\n" "$(color yellow "Project root 'debug-bash' is configured to not sync. Exiting.")"
	exit 0
fi

# Rsync / mode / source
rsyncdefflags="-rvz"
rsyncextraflags=""
rsyncdefexcludeflags="--exclude=*.wbt.gz* --exclude=*.css.gz* --exclude=*.js.gz* --exclude=.git --exclude=.git-data --exclude=.scripts --exclude=.art --exclude=node_modules --exclude=*.fuse_* --exclude=.build --exclude=.backups --exclude=.vscode"

# Decide mode and source path
if [ "$single_file_sync" -eq 1 ]; then
	project_source_rel="$project_rel"
	source_rel="${project_source_rel}/${single_file_name}"
	mode_label="single"
elif [ -n "$arg2" ] && [[ "$arg2" != --running* ]] && [[ "$arg2" != --regex:* ]]; then
	project_source_rel="$project_rel"
	source_rel="${project_source_rel}/${arg2}"
	mode_label="single"
else
	project_source_rel="$project_root"
	source_rel="${project_source_rel}/"
	mode_label="full"
fi

# Decide rsyncextraflags *after* we know the mode:
# - full  : --no-links --existing (unless force)
# - single: --no-links only       (unless force)
if [ "$arg4" != "force" ]; then
	if [ "$mode_label" = "full" ]; then
		rsyncextraflags="--no-links --existing"
	else
		rsyncextraflags="--no-links"
	fi
elif [ "$project_root" = "usermin" ]; then
	rsyncextraflags="--copy-links"
fi

printf "Mode     : %s\n" "$(color cyan "$mode_label")"
printf "Source   : %s\n" "$(color cyan "$source_rel")"
printf "Rsync    : %s\n\n" "$(color cyan "$rsyncdefflags $rsyncextraflags")"

# Detect running VMs (silent, used later)
declare -a incl_instances
declare -a incl_instances_lemp
incl_instances=()
incl_instances_lemp=()

if [ "$running_mode" -eq 1 ]; then
	if command -v prlctl >/dev/null 2>&1; then
		prlctl_list="$(prlctl list)"
		line_counter=0
		while IFS= read -r line; do
			((line_counter++))
			[ "$line_counter" -eq 1 ] && continue

			name="$(echo "$line" | awk '{print substr($0, index($0,$4))}')"

			os_name="$(echo "$name" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
			version="$(echo "$name" | awk '{print $2}')"
			if [[ "$version" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
				version=$(printf "%.0f" "$version")
			fi
			if echo "$name" | grep -qE "Ubuntu .*\.10|Ubuntu [0-9]+\.0[13579]"; then
				version="$(echo "$name" | grep -oE '[0-9]+' | head -1)i"
			fi

			if echo "$name" | grep -q "FreeBSD"; then
				type=""
			elif echo "$name" | grep -q "WikiSuite"; then
				type="-tiki"
			elif echo "$name" | grep -q "Pro"; then
				type="-pro"
			else
				type="-gpl"
			fi

			running_key="${os_name}${version}${type}"
			if echo "$name" | grep -q "Virtualmin Shop"; then
				running_key="local"
			fi

			incl_instances+=( "$running_key" )
			if echo "$name" | grep -q "Nginx"; then
				incl_instances_lemp+=( "$running_key" )
			fi
		done <<<"$prlctl_list"
	elif command -v virsh >/dev/null 2>&1; then
		virsh_list="$(virsh list --title)"
		line_counter=0
		while IFS= read -r line; do
			((line_counter++))
			[ "$line_counter" -le 2 ] && continue

			name="$(echo "$line" | awk '{print substr($0, index($0,$4))}')"

			os_name="$(echo "$name" | awk '{print $1}' | tr '[:upper:]' '[:lower:]')"
			version="$(echo "$name" | awk '{print $2}')"
			if [[ "$version" =~ ^-?[0-9]+(\.[0-9]+)?$ ]]; then
				version=$(printf "%.0f" "$version")
			fi
			if echo "$name" | grep -qE "Ubuntu .*\.10|Ubuntu [0-9]+\.0[13579]"; then
				version="$(echo "$name" | grep -oE '[0-9]+' | head -1)i"
			fi

			if echo "$name" | grep -q "FreeBSD"; then
				type=""
			elif echo "$name" | grep -q "WikiSuite"; then
				type="-tiki"
			elif echo "$name" | grep -q "Pro"; then
				type="-pro"
			else
				type="-gpl"
			fi

			running_key="${os_name}${version}${type}"
			if echo "$name" | grep -q "Virtualmin Shop"; then
				running_key="local"
			fi

			incl_instances+=( "$running_key" )
			if echo "$name" | grep -q "Nginx"; then
				incl_instances_lemp+=( "$running_key" )
			fi
		done <<<"$virsh_list"
	fi
fi

# Hosts from /etc/hosts
password="${DEBUG_SSHPASS:-}"
if [ -z "$password" ]; then
	printf "%s\n" "$(color red "Error: DEBUG_SSHPASS is not set (password must come from environment / keychain).")" >&2
	exit 1
fi

declare -a host_ports_keys
declare -a host_ports_vals
declare -a host_ips_keys
declare -a host_ips_vals
declare -a debug_hosts_all
declare -a local_bases
host_ports_keys=()
host_ports_vals=()
host_ips_keys=()
host_ips_vals=()
debug_hosts_all=()
local_bases=()

current_is_local=0

while IFS= read -r line; do
	# Detect segment line and whether it's auto-local
	if [[ "$line" =~ ^[[:space:]]*#[[:space:]]*Segment[[:space:]]*:(.*)$ ]]; then
		seg_body="${BASH_REMATCH[1]}"
		seg_body="$(trim <<<"$seg_body")"
		if printf '%s\n' "$seg_body" | grep -q '\[auto-local\]'; then
			current_is_local=1
		else
			current_is_local=0
		fi
		continue
	fi

	# Skip pure comment lines
	if [[ "$line" =~ ^[[:space:]]*# ]]; then
		continue
	fi

	# Skip lines that end with a trailing comment-only marker
	stripped="$(echo "$line" | $sed_cmd 's/[[:space:]]*$//')"
	case "$stripped" in
		*'#') continue ;;
	esac

	# Extract IP (first field) from this line
	ip_field="$(printf '%s\n' "$line" | awk '{print $1}')"

	# Host lines
	for tok in $line; do
		case "$tok" in
			debug-*)
				# Collect all debug hosts
				if ! in_list "$tok" "${debug_hosts_all[@]}"; then
					debug_hosts_all+=( "$tok" )
				fi

				# Record SSH port from hostname if set, e.g.
				# debug-cloud-pubkey-1.2.3.4:2222-debian
				if [[ "$tok" =~ ^debug-[^:[:space:]]*:([0-9]{1,5})[^[:space:]]*$ ]]; then
					port="${BASH_REMATCH[1]}"
					# Optional sanity: only accept 1–65535
					if (( port >= 1 && port <= 65535 )); then
						if ! in_list "$tok" "${host_ports_keys[@]}"; then
							host_ports_keys+=( "$tok" )
							host_ports_vals+=( "$port" )
						fi
					fi
				fi

				# Record IP for this debug host token
				if [ -n "$ip_field" ] && ! in_list "$tok" "${host_ips_keys[@]}"; then
					host_ips_keys+=( "$tok" )
					host_ips_vals+=( "$ip_field" )
				fi

				# Collect local_bases only inside [auto-local] segment
				if [ "$current_is_local" -eq 1 ]; then
					server_no_debug="${tok#debug-}"
					server_no_star="${server_no_debug%\*}"
					server_fqdn="$server_no_star"          # e.g. ubuntu22-pro.virtualmin.dev
					[ -z "$server_fqdn" ] && continue
					if ! in_list "$server_fqdn" "${local_bases[@]}"; then
						local_bases+=( "$server_fqdn" )
					fi
				fi
				;;
		esac
	done
done <"$hosts_file"

if [ "${#debug_hosts_all[@]}" -eq 0 ]; then
	printf "%s\n" "$(color yellow "No debug-* hosts found in $hosts_file")"
	exit 0
fi

# Select hosts that will actually be synced
declare -a selected_hosts
selected_hosts=()

for h in "${debug_hosts_all[@]}"; do
	server_raw="$h"
	server_no_debug="${server_raw#debug-}"
	server_no_star="${server_no_debug%\*}"
	server="$server_no_star"
	server_key="${server%%.*}"
	
	is_local=0
	if [ "${#local_bases[@]}" -ne 0 ] && in_list "$server" "${local_bases[@]}"; then
		is_local=1
	fi

	if [ -n "$domain_filter" ]; then
		case "$server" in
			*"$domain_filter"*) ;;
			*)
				case "$server_raw" in
					*"$domain_filter"*) ;;
					*) continue ;;
				esac
				;;
		esac
	fi

	if [ -n "$target_name" ] && [ "$server_key" != "$target_name" ]; then
		continue
	fi

	if [ "$running_mode" -eq 1 ] && [ "$is_local" -eq 1 ]; then
		if [ "${#incl_instances[@]}" -eq 0 ]; then
			continue
		fi
		if ! in_list "$server_key" "${incl_instances[@]}"; then
			continue
		fi
	fi

	if [ "$project_root" = "shop.virtualmin.com" ] && [ "$server_raw" != "debug-local.virtualmin.dev" ]; then
		continue
	fi

	if [ "$project_root" = "virtualmin-tikimanager" ] && ! printf '%s\n' "$server_raw" | grep -q 'tiki'; then
		continue
	fi

	if [ "$project_root" = "virtualmin-pro" ]; then
		if ! printf '%s\n' "$server_raw" | grep -q -- '-pro'; then
			if [ "$server_raw" != "debug-local.virtualmin.dev" ]; then
				continue
			fi
		fi
	fi

	if printf '%s\n' "$project_root" | grep -q 'nginx'; then
		if [ "${#incl_instances_lemp[@]}" -ne 0 ] && ! in_list "$server_key" "${incl_instances_lemp[@]}"; then
			continue
		fi
	fi

	selected_hosts+=( "$server_raw" )
done

# Pretty list of selected hosts (without "debug-" and "*")
display_hosts=()
for h in "${selected_hosts[@]}"; do
	s="${h#debug-}"
	s="${s%\*}"
	display_hosts+=( "$s" )
done

# Compute local running bases in intersection
# of "local_bases" and "incl_instances"
declare -a running_local_bases
running_local_bases=()
for b in "${local_bases[@]}"; do
	if in_list "$b" "${incl_instances[@]}"; then
		running_local_bases+=( "$b" )
	fi
done

# Prepare selected hosts string
if [ "${#selected_hosts[@]}" -eq 0 ]; then
	hosts_selected_str="<none> (no matching debug hosts found)"
else
	hosts_selected_str="${display_hosts[*]}"
fi

# Combined view with local hosts and selected
section "Scanning local hosts file"

display_debug_hosts=()
if [ "${#debug_hosts_all[@]}" -eq 0 ]; then
	display_debug_hosts+=( "<none>" )
else
	for h in "${debug_hosts_all[@]}"; do
		s="${h#debug-}"
		s="${s%\*}"
		display_debug_hosts+=( "$s" )
	done
fi

printf "Found all debug hosts:\n    %s\n" \
	"$(color gray "${display_debug_hosts[*]}")"
printf "Selected debug hosts for sync:\n    %s\n\n" \
	"$(color gray "$hosts_selected_str")"

if [ "${#selected_hosts[@]}" -eq 0 ]; then
	exit 0
fi

# Project-specific target mapping
projectroottarget="$project_root"
projectroottarget_usermin=""

# Special handling for Webmin modules (e.g. webmin/xterm, webmin/filemin)
if [ "$project_root" = "webmin" ]; then
	case "$project_rel" in
		webmin/*)
			# Take first component after "webmin/" as module name
			module="${project_rel#webmin/}"
			module="${module%%/*}"
			if [ -n "$module" ]; then
				projectroottarget="webmin/$module"
			fi
			;;
	esac
fi

if [[ "$project_root" =~ ^(authentic-theme-src|virtual-server-theme|server-manager|virtualmin-.*)$ ]]; then
	if [ -n "$arg2" ] && [[ "$arg2" != --running* ]] && [[ "$arg2" != --regex:* ]]; then
		subprojectdir="$project_rel"
	else
		subprojectdir="$project_root"
	fi
	projectroottarget="webmin/$subprojectdir"

	if [ "$project_root" = "authentic-theme-src" ]; then
		projectroottarget_usermin="usermin/$subprojectdir"
		rsyncextraflags=""
		projectroottarget="${projectroottarget/$project_root/authentic-theme}"
		projectroottarget_usermin="${projectroottarget_usermin/$project_root/authentic-theme}"
	fi

	if [ "$project_root" = "virtual-server-theme" ]; then
		projectroottarget_usermin="usermin/$subprojectdir"
		rsyncextraflags=""
		projectroottarget="${projectroottarget/$project_root/virtual-server-theme}"
		projectroottarget_usermin="${projectroottarget_usermin/$project_root/virtual-server-theme}"
	fi

	if [ "$project_root" = "virtualmin-gpl" ]; then
		projectroottarget="${projectroottarget/$project_root/virtual-server}"
		rsyncextraflags+=" --exclude=module.info"
	fi

	if [ "$project_root" = "virtualmin-pro" ]; then
		projectroottarget="${projectroottarget/$project_root/virtual-server/pro}"
	fi

	if [ "$project_rel" = "server-manager/server-manager" ]; then
		projectroottarget="${projectroottarget/$project_root\/server-manager/server-manager}"
		rsyncextraflags+=" --exclude=module.info"
	fi
fi

section "Sync overview"

if [ -n "$sshcmd" ]; then
	printf "%s\n\n" "$(color cyan "Executing remote command across selected debug hosts...")"
else
	if [ "$mode_label" = "single" ]; then
		printf "%s\n\n" "$(color cyan "Syncing single file across selected debug hosts...")"
	else
		printf "%s\n\n" "$(color cyan "Syncing full project across selected debug hosts...")"
	fi
fi

# Per-host processing
process_host() {
	local server_raw="$1"

	local server_no_debug="${server_raw#debug-}"
	local server_no_star="${server_no_debug%\*}"
	local server="$server_no_star"
	local server_key="${server%%.*}"

	local initial_source="$source_rel"
	local user="$default_user"
	local local_sshnocheck="$sshnocheck"

	# If a port was recorded for this host, add it to SSH options
	local local_sshport_opt=""
	local ssh_port=""
	ssh_port="$(get_host_port "$server_raw" 2>/dev/null || true)"
	if [ -n "$ssh_port" ]; then
		local_sshport_opt=" -p $ssh_port"
	fi

	# Decide what hostname/IP to use for ssh/rsync
	local ssh_host="debug-$server"  # default: normal debug-FQDN
	if [ -n "$ssh_port" ]; then
		# For port-encoded hosts, prefer connecting by IP
		local ssh_ip=""
		ssh_ip="$(get_host_ip "$server_raw" 2>/dev/null || true)"
		if [ -n "$ssh_ip" ]; then
			ssh_host="$ssh_ip"
		fi
	fi


	local freebsdwebmindir=0
	local rhelwebmindir=0

	local is_local=0
	if [ "${#local_bases[@]}" -ne 0 ] && in_list "$server_key" "${local_bases[@]}"; then
		is_local=1
	fi

	if printf '%s\n' "$server" | grep -qi 'freebsd'; then
		freebsdwebmindir=1
		rhelwebmindir=0
	elif printf '%s\n' "$server" | grep -qiE 'rhel|fedora|centos|rocky|alma|oracle|local\.virtualmin\.dev'; then
		freebsdwebmindir=0
		rhelwebmindir=1
	else
		freebsdwebmindir=0
		rhelwebmindir=0
	fi

	if [ "$project_root" = "virtualmin-pro" ] && ! printf '%s\n' "$server_raw" | grep -q -- '-pro'; then
		if [ "$server_raw" != "debug-local.virtualmin.dev" ]; then
			return 0
		fi
	fi

	if printf '%s\n' "$project_root" | grep -q 'nginx'; then
		if [ "${#incl_instances_lemp[@]}" -ne 0 ]; then
			if ! in_list "$server_key" "${incl_instances_lemp[@]}"; then
				return 0
			fi
		fi
	fi

	local target=""
	local target_usermin=""

	if [ "$freebsdwebmindir" -eq 1 ]; then
		if printf '%s\n' "$project_root" | grep -qE 'webmin|usermin|authentic-theme|virtual-server|virtualmin-'; then
			target="usr/local/$projectroottarget"
			if [ -n "$projectroottarget_usermin" ]; then
				target_usermin="usr/local/$projectroottarget_usermin"
			fi
		else
			return 0
		fi
	elif [ "$rhelwebmindir" -eq 1 ]; then
		target="usr/libexec/$projectroottarget"
		if [ -n "$projectroottarget_usermin" ]; then
			target_usermin="usr/libexec/$projectroottarget_usermin"
		fi
	else
		target="usr/share/$projectroottarget"
		if [ -n "$projectroottarget_usermin" ]; then
			target_usermin="usr/share/$projectroottarget_usermin"
		fi
	fi


	# For single-file/path syncs, mirror the subdirectory layout
	# inside the repo on the remote side.
	if [ "$mode_label" = "single" ] && [ "$project_root" != "Virtualmin-Config" ]; then
		local base_rel rel_to_base rel_subdir

		# Decide which part of the repo maps to the remote target:
		# - webmin/usermin: include the module (webmin/mysql, usermin/mailbox, ...)
		# - everything else: use project_root
		if [ "$project_root" = "webmin" ]; then
			case "$project_rel" in
				webmin/*)
					local module="${project_rel#webmin/}"
					module="${module%%/*}"
					if [ -n "$module" ]; then
						base_rel="webmin/$module"
					else
						base_rel="webmin"
					fi
					;;
				*)
					base_rel="webmin"
					;;
			esac
		elif [ "$project_root" = "usermin" ]; then
			case "$project_rel" in
				usermin/*)
					local module="${project_rel#usermin/}"
					module="${module%%/*}"
					if [ -n "$module" ]; then
						base_rel="usermin/$module"
					else
						base_rel="usermin"
					fi
					;;
				*)
					base_rel="usermin"
					;;
			esac
		else
			base_rel="$project_root"
		fi

		# Example:
		#   base_rel    = webmin/mysql
		#   source_rel  = webmin/mysql/lang/en
		#   rel_to_base = lang/en
		rel_to_base="${source_rel#$base_rel/}"

		# Only adjust if we actually stripped the prefix and still
		# have a subdirectory part.
		if [ "$rel_to_base" != "$source_rel" ] && [[ "$rel_to_base" == */* ]]; then
			# If the local source is a directory, mirror the full path;
			# if it's a file, mirror just its parent directory.
			if [ -d "$git_home/$source_rel" ]; then
				rel_subdir="$rel_to_base"
			else
				rel_subdir="${rel_to_base%/*}"
			fi

			if [ -n "$rel_subdir" ]; then
				target="${target}/${rel_subdir}"
				if [ -n "$target_usermin" ]; then
					target_usermin="${target_usermin}/${rel_subdir}"
				fi
			fi
		fi
	fi

	if [ "$project_root" = "webmin-jailkit" ]; then
		projectroottarget="${projectroottarget/webmin-jailkit/webmin/jailkit}"
	fi

	if [ "$project_root" = "Virtualmin-Config" ]; then
		projectroottarget="Virtualmin-Config/lib/Virtualmin"
		projectroottarget="${projectroottarget/$project_root/Virtualmin}"
		projectroottarget="${projectroottarget/\/lib\/Virtualmin/}"
		if [ "$freebsdwebmindir" -eq 1 ]; then
			return 0
		elif [ "$rhelwebmindir" -eq 1 ]; then
			if [ "$mode_label" = "full" ]; then
				target="usr/share/perl5/vendor_perl/$projectroottarget"
			else
				if [[ "$project_abs" =~ /Plugin ]]; then
					target="usr/share/perl5/vendor_perl/$projectroottarget/Config/Plugin"
				elif [[ "$project_abs" =~ /Config ]]; then
					target="usr/share/perl5/vendor_perl/$projectroottarget/Config/"
				else
					target="usr/share/perl5/vendor_perl/$projectroottarget/"
				fi
			fi
		else
			if [ "$mode_label" = "full" ]; then
				target="usr/share/perl5/$projectroottarget"
			else
				if [[ "$project_abs" =~ /Plugin ]]; then
					target="usr/share/perl5/$projectroottarget/Config/Plugin"
				elif [[ "$project_abs" =~ /Config ]]; then
					target="usr/share/perl5/$projectroottarget/Config/"
				else
					target="usr/share/perl5/$projectroottarget/"
				fi
			fi
		fi
		if [ "$mode_label" = "full" ]; then
			initial_source="${source_rel}lib/Virtualmin/"
		fi
	fi

	if [ "$project_root" = "virtualmin-install" ] || \
	   [ "$project_root" = "cloudmin-install" ] || \
	   [ "$project_root" = "slib" ]; then
		projectroottarget="root"
		target="root"
	fi

	if [ "$project_root" = "webmin-ci-cd" ]; then
		projectroottarget="root"
		target="root/build-scripts"
	fi
	if [ "$project_root" = "webmin-ci-cd" ] && [ "$server_key" = "rocky10-pro" ]; then
		if [[ "$arg2" == *"sign-repo.bash" ]] || [[ "$arg2" == *"sign-all-repos.bash" ]]; then
			target="home/rocky10-pro/.local/sbin"
		fi
	fi

	if [ "$project_root" = "wikisuite-packages" ] && printf '%s\n' "$server_raw" | grep -q 'tiki'; then
		projectroottarget="root"
		target="root"
	fi

	if [ "$project_rel" = "server-manager/server-manager" ]; then
		projectroottarget="${projectroottarget//\/server-manager\/server-manager/}"
		if [ "$freebsdwebmindir" -eq 1 ]; then
			return 0
		elif [ "$rhelwebmindir" -eq 1 ]; then
			target="usr/libexec/$projectroottarget"
		else
			target="usr/share/$projectroottarget"
		fi
	fi

	if [ "$project_root" = "shop.virtualmin.com" ]; then
		projectroottarget="${projectroottarget/webmin\/shop.virtualmin\.com/virtualmin}"
		target="home/$projectroottarget"
		user="virtualmin"
	fi

	if printf '%s\n' "$server" | grep -q 'build'; then
		target="root/$projectroottarget"
		if [ -n "$projectroottarget_usermin" ]; then
			target_usermin="root/$projectroottarget_usermin"
		fi
		if printf '%s\n' "$project_root" | grep -q 'authentic-theme'; then
			return 0
		fi
	fi

	local local_nohup_sshpass=""
	if printf '%s\n' "$server_raw" | grep -q -- '-pubkey'; then
		if printf '%s\n' "$server_raw" | grep -q 'cloud-'; then
			local_sshnocheck="${sshnocheck/ConnectTimeout=1/ConnectTimeout=3}"
		fi
		local_sshnocheck="${local_sshnocheck/ -o PubkeyAuthentication=no/}"
	else
		if ! printf '%s\n' "$local_sshnocheck" | grep -q ' -o PubkeyAuthentication=no'; then
			local_sshnocheck="$local_sshnocheck -o PubkeyAuthentication=no"
		fi
		if ! printf '%s\n' "$server_raw" | grep -q 'cloud-'; then
			local_sshnocheck="${local_sshnocheck/ConnectTimeout=3/ConnectTimeout=1}"
		fi
		local_nohup_sshpass="$sshpass_cmd -p $password "
	fi

	local sourcefull="$git_home/$initial_source"
	local targetfull="/$target"
	local targetfull_usermin=""
	if [ -n "$target_usermin" ]; then
		targetfull_usermin="/$target_usermin"
	fi

	# SSH-only commands
	if [ -n "$sshcmd" ]; then
		local sshcmdprelocal=""
		local sshcmdlocal="$sshcmd"

		# Remote package upgrade
		if printf '%s\n' "$sshcmd" | grep -q 'upgrade-packages'; then
			if printf '%s\n' "$target" | grep -q 'libexec'; then
				sshcmdlocal="systemctl restart chronyd ; sleep 15 ; dnf clean all ; dnf -y upgrade > /root/package-updates.log 2>&1"
			else
				sshcmdlocal="systemctl restart systemd-timesyncd ; sleep 15 ; apt-get clean ; apt-get update > /root/package-updates.log 2>&1 ; apt-get -y upgrade --with-new-pkgs --allow-change-held-packages --fix-missing -o APT::Get::Always-Include-Phased-Updates=true >> /root/package-updates.log 2>&1 ; apt -y autoremove >> /root/package-updates.log 2>&1"
			fi
		fi

		# SSL cert sync
		if printf '%s\n' "$sshcmd" | grep -q 'sync-ssl'; then
			local domdef="$server"
			if [ -n "$domain_filter" ]; then
				domdef="$server"
			fi
			sshcmdprelocal='tar -cf - -C ~/Git/.ssl/virtualmin.dev ssl.cert ssl.key ssl.ca | '
			sshcmdlocal="tar -xf - -C /root && virtualmin install-cert --domain $domdef --cert /root/ssl.cert --key /root/ssl.key --ca /root/ssl.ca > /root/virtualmin-install-cert.log 2>&1 && rm -f /root/ssl.cert /root/ssl.key /root/ssl.ca"
		fi

		# Time sync
		if printf '%s\n' "$sshcmd" | grep -q 'sync-time'; then
			if printf '%s\n' "$target" | grep -q 'libexec'; then
				sshcmdlocal="systemctl restart chronyd"
			else
				sshcmdlocal="systemctl restart systemd-timesyncd"
			fi
		fi

		local cmd=""
		if printf '%s\n' "$local_sshnocheck" | grep -q ' -o PubkeyAuthentication=no'; then
			cmd="$sshcmdprelocal$sshpass_cmd -p $password $ssh_cmd$local_sshport_opt -t -T $local_sshnocheck root@$ssh_host \"$sshcmdlocal\""
		else
			cmd="$sshcmdprelocal$ssh_cmd$local_sshport_opt -t -T $local_sshnocheck root@$ssh_host \"$sshcmdlocal\""
		fi

		printf "\nSyncing to    : %s (command)\n" "$(color cyan "$server")"
		local cmd_print="$cmd"
		if [ -n "$password" ]; then
			cmd_print="${cmd_print//$password/<password>}"
		fi
		printf "Command used  : %s\n" "$(color dim "$cmd_print")"

		local ssh_output ssh_status short_err
		ssh_output=$(eval "$cmd" 2>&1)
		ssh_status=$?

		if [ "$ssh_status" -eq 0 ]; then
			printf "Status   : %s\n\n" "$(color green "Success")"
		else
			short_err="$(
				printf '%s\n' "$ssh_output" \
				| "$sed_cmd" '/^[[:space:]]*$/d' \
				| head -n 2 \
				| tr '\n' '; ' \
				| "$sed_cmd" 's/[;[:space:]]*$//'
			)"
			[ -z "$short_err" ] && short_err="non-zero exit $ssh_status"
		
			printf "Status   : %s\n\n" "$(color red "Error: $short_err")"
		fi
		return 0
	fi

	# Rsync sync
	printf "\nSyncing to    : %s (Webmin)\n" "$(color cyan "$server")"
	local cmdsync
	cmdsync="${local_nohup_sshpass}${rsync_cmd} ${rsyncdefflags} ${rsyncextraflags} ${rsyncdefexcludeflags} -e \"$ssh_cmd$local_sshport_opt ${local_sshnocheck}\" \"$sourcefull\" $user@$ssh_host:\"$targetfull\"/"
	local cmd_print="$cmdsync"
	if [ -n "$password" ]; then
		cmd_print="${cmd_print//$password/<password>}"
	fi
	printf "Command used  : %s\n" "$(color dim "$cmd_print")"

	local rsync_output rsync_status short_err
	rsync_output=$(eval "$cmdsync" 2>&1)
	rsync_status=$?

	if [ "$rsync_status" -eq 0 ]; then
		printf "Status   : %s\n\n" "$(color green "Success")"
	else
		short_err="$(
			printf '%s\n' "$rsync_output" \
			| "$sed_cmd" '/^[[:space:]]*$/d' \
			| head -n 2 \
			| tr '\n' '; ' \
			| "$sed_cmd" 's/[;[:space:]]*$//'
		)"
		[ -z "$short_err" ] && short_err="non-zero exit $rsync_status"
	
		printf "Status   : %s\n\n" "$(color red "Error: $short_err")"
	fi

	if [ -n "$target_usermin" ]; then
		printf "Syncing to    : %s (Usermin)\n" "$(color cyan "$server")"
		cmdsync="${local_nohup_sshpass}${rsync_cmd} ${rsyncdefflags} ${rsyncextraflags} ${rsyncdefexcludeflags} -e \"$ssh_cmd$local_sshport_opt ${local_sshnocheck}\" \"$sourcefull\" $user@$ssh_host:\"$targetfull_usermin\"/"
		local cmd_print="$cmdsync"
		if [ -n "$password" ]; then
			cmd_print="${cmd_print//$password/<password>}"
		fi
		printf "Command used  : %s\n" "$(color dim "$cmd_print")"

		rsync_output=$(eval "$cmdsync" 2>&1)
		rsync_status=$?

		if [ "$rsync_status" -eq 0 ]; then
			printf "Status   : %s\n\n" "$(color green "Success")"
		else
			short_err="$(printf '%s\n' "$rsync_output" | head -n 2 | tr '\n' '; ' | $sed_cmd 's/; $//')"
			printf "Status   : %s\n\n" "$(color red "Error: ${short_err:-non-zero exit $rsync_status}")"
		fi
	fi

	if [ "$mode_label" = "single" ] && printf '%s\n' "$source_rel" | grep -q 'miniserv.pl'; then
		(
			sleep 2
			local min_restart_cmd=""
			if [ "$project_root" = "usermin" ]; then
				min_restart_cmd="systemctl restart usermin"
			else
				min_restart_cmd="systemctl restart webmin"
			fi

			local cmd
			if printf '%s\n' "$local_sshnocheck" | grep -q ' -o PubkeyAuthentication=no'; then
				cmd="$sshpass_cmd -p $password $ssh_cmd$local_sshport_opt -t -T $local_sshnocheck root@$ssh_host \"$min_restart_cmd\""
			else
				cmd="$ssh_cmd$local_sshport_opt -t -T $local_sshnocheck root@$ssh_host \"$min_restart_cmd\""
			fi
			eval "$nohup_cmd $cmd >/dev/null 2>&1 &"
		) &
	fi
}

# Run per-host syncs in parallel, but keep output grouped per host
declare -a job_pids
declare -a job_logs
job_pids=()
job_logs=()

idx=0
for h in "${selected_hosts[@]}"; do
	log_file="$(mktemp "/tmp/sync-host-${idx}.XXXX")"
	job_logs[idx]="$log_file"

	# Run the whole host processing in the background, logging to a file
	(
		process_host "$h"
	) >"$log_file" 2>&1 &

	job_pids[idx]=$!
	((idx++))
done

# Wait for each job and print its output once it's done
for i in "${!job_pids[@]}"; do
	wait "${job_pids[$i]}" >/dev/null 2>&1
	cat "${job_logs[$i]}"
	rm -f "${job_logs[$i]}"
done

exit 0
