#!/usr/bin/env bash
# discourse-user-triage.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script gathers Discourse user activity and generates a support triage
# report with AI-assisted scoring and recommendations.
#
# Description:
# - Input:
#   --base forum URL and --user target username.
# - Data collected:
#   Profile/summary, recent activity streams, private messages, and optional
#   admin metadata (IPs, email visibility, account flags).
# - Output:
#   Terminal report with profile, activity stats, latest unique topics, and AI
#   analysis for prioritization.
#
# Usage:
#   ./discourse-user-triage.bash --base <forum-url> --user <username> [options]
#
# Examples:
#   # Run triage for last 10 days (default samples: 3)
#   ./discourse-user-triage.bash \
#     --base https://forum.example.com --user alice
#
#   # Show more history and more latest topics
#   ./discourse-user-triage.bash \
#     --base https://forum.example.com --user alice \
#     --since-days 30 --samples 10

set -euo pipefail
umask 077

# Script constants and global variables
SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME

BASE_URL=""
TARGET_USER=""
MAX_PAGES=10
SINCE_DAYS=10
SAMPLE_LIMIT=3
USE_COLOR=0

CLEANUP_PATHS=()

# Enable color output when stdout is a TTY and NO_COLOR is unset
init_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		USE_COLOR=1
	fi
}

# Print text with ANSI color/style codes when color output is enabled
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
		red)     code=31 ;;
		green)   code=92 ;;
		yellow)  code=33 ;;
		blue)    code=94 ;;
		magenta) code=95 ;;
		cyan)    code=96 ;;
		gray)    code=90 ;;
		*)       printf '%s' "$s"; return ;;
	esac
	printf '\033[%sm%s\033[0m' "$code" "$s"
}

# Render a section header with top and bottom separators
section() {
	local title="$1"
	local bar
	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '\n%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

# Render a compact subsection marker line
subsection() {
	local title="$1"
	printf '\n%s\n' "$(color cyan "► $title")"
}

# Prints key-value pair with aligned colons
print_kv() {
	local key="$1"
	local value="$2"
	local width="${3:-20}"
	
	printf '%s%*s %s\n' \
		"$(color bold "$key")" \
		$((width - ${#key})) ":" \
		"$(color dim "$value")"
}

# Return success when a command exists in PATH
have_cmd() {
	command -v "$1" &>/dev/null
}

# Normalize boolean-like values to yes/no for display
format_bool() {
	local val="${1:-}"
	case "$val" in
		[Tt][Rr][Uu][Ee]|1|[Yy][Ee][Ss]) printf 'yes' ;;
		[Ff][Aa][Ll][Ss][Ee]|0|[Nn][Oo]) printf 'no' ;;
		*) printf '%s' "$val" ;;
	esac
}

# Strip common markdown markers while preserving link targets.
strip_markdown() {
	local text="$1"

	text=$(printf '%s' "$text" \
		| sed -E 's/!\[([^][]*)\]\(([^)]*)\)/\1 (\2)/g')
	text=$(printf '%s' "$text" \
		| sed -E 's/\[([^][]+)\]\(([^)]*)\)/\1 (\2)/g')
	text=$(printf '%s' "$text" \
		| sed -E 's/(^|[[:space:]])#{1,6}[[:space:]]+/\1/g')
	text=$(printf '%s' "$text" | sed -E 's/[*_`~]+//g')
	text=$(printf '%s' "$text" | tr '\r\n' ' ')
	text=$(printf '%s' "$text" \
		| sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')
	printf '%s' "$text"
}

# Remove all temporary files tracked in CLEANUP_PATHS
cleanup() {
	local path
	for path in "${CLEANUP_PATHS[@]}"; do
		[ -e "$path" ] && rm -rf "$path"
	done
}
trap cleanup EXIT INT TERM

# Print CLI usage text and exit
usage() {
	cat >&2 <<-EOF
Usage: $SCRIPT_NAME --base <forum-url> --user <username> [options]

Options:
    -b, --base <url>             Base forum URL (required)
    -u, --user <name>            Target Discourse username (required)
    -p, --pages <n>              Max pages per stream (default: 10)
    -d, --since-days <n>         Only include last N days (default: 10)
    -s, --samples <n>            Sample topics per section (default: 3)
    -N, --no-color               Disable colors
    -h, --help                   Show help

Env (Discourse):
    DISCOURSE_API_KEY            Admin API key (required)
    DISCOURSE_API_USERNAME       Admin username (required)

Env (OpenAI):
    OPENAI_API_KEY               Required
    OPENAI_MODEL                 Default: gpt-5.2-chat-latest
EOF
	exit 1
}

# Print an error message and exit with non-zero status
die() {
	printf '%s\n' "$(color red "Error: $1")" >&2
	exit 1
}

# Verify required external commands are available
need_cmds() {
	local missing=()
	have_cmd curl || missing+=("curl")
	have_cmd jq   || missing+=("jq")
	have_cmd date || missing+=("date")
	have_cmd sed  || missing+=("sed")
	have_cmd tr   || missing+=("tr")
	if [ "${#missing[@]}" -gt 0 ]; then
		die "Missing required tools: ${missing[*]}"
	fi
}

# Validate the base URL format and basic safety constraints
validate_base_url() {
	local url="$1"
	[[ "$url" == https://* ]] || return 1
	[[ "$url" != *' '* && "$url" != *'@'* ]] || return 1
	return 0
}

# Format an ISO timestamp in local time as YYYY-MM-DD HH:MM TZ
format_iso_date() {
	local iso="$1"
	[ -z "$iso" ] || [ "$iso" = "null" ] && { printf "Never"; return; }
	
	if date -d "$iso" '+%Y-%m-%d %H:%M %Z' 2>/dev/null; then
		return
	fi

	local trimmed="${iso%%.*}"
	trimmed="${trimmed%Z}"
	if date -j -f "%Y-%m-%dT%H:%M:%S" "$trimmed" \
		'+%Y-%m-%d %H:%M %Z' 2>/dev/null; then
		return
	fi
	
	printf '%s' "$iso"
}

# Compact timestamp formatter used for sample item display
format_iso_compact() {
	local iso="$1"
	[ -z "$iso" ] || [ "$iso" = "null" ] && { printf "unknown"; return; }

	if date -d "$iso" '+%Y-%m-%d %H:%M %Z' 2>/dev/null; then
		return
	fi

	local trimmed="${iso%%.*}"
	trimmed="${trimmed%Z}"
	if date -j -f "%Y-%m-%dT%H:%M:%S" "$trimmed" \
		'+%Y-%m-%d %H:%M %Z' 2>/dev/null; then
		return
	fi

	printf '%s' "$iso"
}

# Convert an ISO timestamp to Unix epoch seconds
iso_to_epoch() {
	local iso="$1"
	[ -z "$iso" ] || [ "$iso" = "null" ] && return 1

	local epoch
	if epoch=$(date -u -d "$iso" +%s 2>/dev/null); then
		printf '%s' "$epoch"
		return 0
	fi

	local trimmed="${iso%%.*}"
	trimmed="${trimmed%Z}"
	if epoch=$(date -u -j -f "%Y-%m-%dT%H:%M:%S" "$trimmed" +%s 2>/dev/null); then
		printf '%s' "$epoch"
		return 0
	fi

	return 1
}

# Render an ISO timestamp as relative age (e.g. <1m, 2h, 3d)
format_relative_date() {
	local iso="$1"
	[ -z "$iso" ] || [ "$iso" = "null" ] && { printf "Never"; return; }

	local ts now delta
	ts=$(iso_to_epoch "$iso") || {
		printf '%s' "$(format_iso_date "$iso")"
		return
	}
	now=$(date +%s 2>/dev/null || printf '0')
	delta=$((now - ts))
	[ "$delta" -lt 0 ] && delta=0

	if [ "$delta" -lt 60 ]; then
		printf '<1m'
	elif [ "$delta" -lt 3600 ]; then
		printf '%dm' $((delta / 60))
	elif [ "$delta" -lt 86400 ]; then
		printf '%dh' $((delta / 3600))
	elif [ "$delta" -lt 604800 ]; then
		printf '%dd' $((delta / 86400))
	elif [ "$delta" -lt 2592000 ]; then
		printf '%dw' $((delta / 604800))
	elif [ "$delta" -lt 31536000 ]; then
		printf '%dmo' $((delta / 2592000))
	else
		printf '%dy' $((delta / 31536000))
	fi
}

# Convert read-time seconds into a compact duration string
format_read_time() {
	local secs="${1:-0}"

	case "$secs" in
		''|*[!0-9]*)
			printf '%s' "$secs"
			return
			;;
	esac

	local days=$((secs / 86400))
	local remaining=$((secs % 86400))
	local hours=$((remaining / 3600))
	remaining=$((remaining % 3600))
	local mins=$((remaining / 60))

	local parts=()
	[ "$days" -gt 0 ] && parts+=("${days}d")
	[ "$hours" -gt 0 ] && parts+=("${hours}h")
	[ "$mins" -gt 0 ] && parts+=("${mins}m")
	[ "${#parts[@]}" -eq 0 ] && parts+=("<1m")

	printf '%s (%d seconds)' "${parts[*]}" "$secs"
}

# Ensure required environment variables are set
check_env() {
	local missing=()
	[ -z "${DISCOURSE_API_KEY:-}" ] && missing+=("DISCOURSE_API_KEY")
	[ -z "${DISCOURSE_API_USERNAME:-}" ] && missing+=("DISCOURSE_API_USERNAME")
	[ -z "${OPENAI_API_KEY:-}" ] && missing+=("OPENAI_API_KEY")
	
	if [ "${#missing[@]}" -gt 0 ]; then
		die "Missing required environment variables: ${missing[*]}"
	fi
}

# Perform an authenticated GET request to a Discourse JSON endpoint
discourse_get() {
	local url="$1"
	local outfile="$2"

	[[ "$url" == "$BASE_URL"/* ]] || die "URL outside base: $url"
	[[ "$url" == *.json* ]] || die "Non-JSON endpoint: $url"

	sleep 0.3 2>/dev/null || true

	local errfile
	errfile=$(mktemp)
	CLEANUP_PATHS+=("$errfile")

	if curl -sSL --fail \
		-H "Api-Key: ${DISCOURSE_API_KEY}" \
		-H "Api-Username: ${DISCOURSE_API_USERNAME}" \
		-H "Accept: application/json" \
		"$url" > "$outfile" 2>"$errfile"; then
		return 0
	else
		printf '%s %s\n' "$(color red "GET failed:")" "$url" >&2
		local err_msg
		err_msg=$(cat "$errfile" 2>/dev/null || true)
		if [ -n "$err_msg" ]; then
			printf 'Error details: %s\n' "$err_msg" >&2
		fi
		grep -qiE 'rate|429|too many' <<<"$err_msg" && die "Rate limited"
		return 1
	fi
}

# Resolve a username to numeric Discourse user ID
get_user_id() {
	local user="$1"
	local tmp
	tmp=$(mktemp); CLEANUP_PATHS+=("$tmp")

	discourse_get "$BASE_URL/u/$user.json" "$tmp" >&2 || return 1
	jq -r '.user.id // empty' "$tmp" 2>/dev/null || return 1
}

# Confirm that the target Discourse user exists
validate_user_exists() {
	local user="$1"
	local tmp
	tmp=$(mktemp); CLEANUP_PATHS+=("$tmp")

	discourse_get "$BASE_URL/u/$user.json" "$tmp" || return 1
	jq -e '.user?' "$tmp" >/dev/null 2>&1
}

# Normalize IP values for lookup endpoints
normalize_ip_for_lookup() {
	local ip="$1"
	ip=$(printf '%s' "$ip" | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//')
	ip="${ip#[}"
	ip="${ip%]}"

	if [[ "$ip" == ::ffff:* ]]; then
		ip="${ip#::ffff:}"
	fi

	if [[ "$ip" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}):[0-9]+$ ]]; then
		ip="${BASH_REMATCH[1]}"
	fi

	printf '%s' "$ip"
}

# Query active users list by IP and normalize user records
fetch_users_by_ip() {
	local ip="$1"
	local out_json="$2"
	printf '[]\n' > "$out_json"
	[ -n "$ip" ] || return 0

	local normalized_ip
	normalized_ip=$(normalize_ip_for_lookup "$ip")
	[ -n "$normalized_ip" ] || return 0

	local encoded_ip
	encoded_ip=$(jq -nr --arg value "$normalized_ip" '$value | @uri')

	local tmp
	tmp=$(mktemp); CLEANUP_PATHS+=("$tmp")

	discourse_get "$BASE_URL/admin/users/list/active.json?ip=$encoded_ip" \
		"$tmp" 2>/dev/null || return 0

	jq '
		if type != "array" then []
		else
			[
				.[]?
				| (.username // .user.username // empty)
				| tostring
				| select(length > 0)
			]
			| unique
		end
	' "$tmp" > "$out_json" 2>/dev/null || printf '[]\n' > "$out_json"
}

# Filter an activity list to items newer than N days
filter_since_days() {
	local in_json="$1"
	local out_json="$2"
	local days="$3"
	local label="$4"

	local cutoff=""
	if cutoff=$(date -u -d "$days days ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
		:
	elif cutoff=$(date -u -v-"$days"d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null); then
		:
	else
		printf '%s\n' "$(color yellow \
			"Warning: Cannot filter by date, including all")"
		cp -f "$in_json" "$out_json"
		return 0
	fi

	print_kv "$label since" "$(format_iso_date "$cutoff")" 26
	local cutoff_date
	cutoff_date="${cutoff%%T*}"
	jq --arg cutoff "$cutoff" --arg cutoff_date "$cutoff_date" \
		'
			def pick_ts:
				(
					.action_created_at //
					.last_posted_at //
					.bumped_at //
					.updated_at //
					.created_at //
					""
				) | tostring;

			[
				.[]
				| (pick_ts) as $ts
				| (($ts[0:10]) // "") as $d
				| select(
					($ts >= $cutoff) or
					(($d | length) == 10 and $d >= $cutoff_date)
				)
			]
		' \
		"$in_json" > "$out_json"
}

# Strip optional markdown code fences from model output
strip_code_fences() {
	awk '
		NR==1 && $0 ~ /^```/ {f=1; next}
		f==1 && $0 ~ /^```[[:space:]]*$/ {exit}
		f==0 && $0 ~ /^```[[:space:]]*$/ {exit}
		{print}
	'
}

# Fetch paginated Discourse user actions for a single action filter
fetch_user_actions() {
	local filter="$1"
	local user="$2"
	local out_json="$3"

	local total_label
	case "$filter" in
		1) total_label="All posts fetched" ;;
		2) total_label="Private messages fetched" ;;
		4) total_label="Topics created fetched" ;;
		5) total_label="Posts fetched" ;;
		6) total_label="Replies fetched" ;;
		*) total_label="Filter $filter fetched" ;;
	esac

	printf '[]\n' > "$out_json"

	local tmp page=0 total=0
	tmp=$(mktemp); CLEANUP_PATHS+=("$tmp")

	while [ "$page" -lt "$MAX_PAGES" ]; do
		page=$((page + 1))
		local offset=$(( (page - 1) * 30 ))
		local action_url
		action_url="$BASE_URL/user_actions.json?offset=$offset&username=$user"
		action_url="${action_url}&filter=$filter"
		
		discourse_get "$action_url" "$tmp" || break

		local count
		count=$(jq -r '(.user_actions // []) | length' "$tmp" \
			2>/dev/null || printf '0')
		[ "$count" -eq 0 ] && break

		jq -s '.[0] + (.[1].user_actions // [])' "$out_json" "$tmp" \
			> "${out_json}.tmp"
		mv "${out_json}.tmp" "$out_json"

		total=$((total + count))
	done

	print_kv "$total_label" "$total" 26
}

# Fetch staff-related PM data with mailbox and endpoint fallback
fetch_private_messages() {
	local user="$1"
	local out_json="$2"
	local staff_usernames="${3:-}"
	local staff_user_ids="${4:-}"
	local target_is_staff="${5:-0}"

	printf '[]\n' > "$out_json"

	local tmp
	tmp=$(mktemp); CLEANUP_PATHS+=("$tmp")

	local endpoints=(
		"$BASE_URL/u/$user/messages/group/staff.json"
		"$BASE_URL/u/$user/messages/group/staff/latest.json"
		"$BASE_URL/topics/private-messages/$user.json"
		"$BASE_URL/topics/private-messages-sent/$user.json"
	)

	local endpoint source_kind
	for endpoint in "${endpoints[@]}"; do
		source_kind="general_pm"
		case "$endpoint" in
			*/u/*/messages/group/staff.json|\
			*/u/*/messages/group/staff/latest.json)
				source_kind="staff_box"
				;;
		esac

		local page=0
		while [ "$page" -lt "$MAX_PAGES" ]; do
			local page_url="$endpoint"
			if [ "$page" -gt 0 ]; then
				if [[ "$endpoint" == *\?* ]]; then
					page_url="${endpoint}&page=$page"
				else
					page_url="${endpoint}?page=$page"
				fi
			fi

			if discourse_get "$page_url" "$tmp" 2>/dev/null; then
				local count
				count=$(jq -r '
					(
						.topic_list.topics //
						.topics //
						[]
					) | length
				' "$tmp" \
					2>/dev/null || printf '0')
				[ "$count" -eq 0 ] && break

				jq -s --arg source_kind "$source_kind" '
					def id_to_name:
						(
							.[1].users // []
							| map(
								select(type == "object" and (.id? != null))
							)
							| map({
								key: (.id | tostring),
								value: (
									(.username // "") | ascii_downcase
								)
							})
							| from_entries
						);
					def response_staff_ids:
						(
							.[1].users // []
							| map(select(type == "object"))
							| map(
								select(
									(.admin // false) or
									(.moderator // false) or
									(.staff // false)
								)
							)
							| map(.id | tostring)
							| unique
						);
					def response_staff_names:
						(
							.[1].users // []
							| map(select(type == "object"))
							| map(
								select(
									(.admin // false) or
									(.moderator // false) or
									(.staff // false)
								)
							)
							| map((.username // "") | ascii_downcase)
							| map(select(length > 0))
							| unique
						);
					def topic_ts_epoch:
						(
							(
								.action_created_at //
								.last_posted_at //
								.bumped_at //
								.updated_at //
								.created_at //
								""
							)
							| tostring
							| gsub("\\.[0-9]+"; "")
							| (fromdateiso8601? // 0)
						);
					(id_to_name) as $user_map
					| (response_staff_ids) as $resp_staff_ids
					| (response_staff_names) as $resp_staff_names
					|
					(
						.[0] + (
							.[1].topic_list.topics //
							.[1].topics //
							[]
						)
					)
						| map(select(type == "object"))
						| map(._source_kind = $source_kind)
						| map(._response_staff_ids = $resp_staff_ids)
						| map(._response_staff_names = $resp_staff_names)
						| map(
							._participant_user_ids = (
								[
									(.participants[]?.user_id),
									(.posters[]?.user_id),
									(.details.participants[]?.user_id)
								]
								| map(select(. != null) | tostring)
								| unique
							)
						)
						| map(
							._participant_usernames = (
								._participant_user_ids
								| map($user_map[.] // empty)
								| map(select(length > 0))
								| unique
							)
						)
						| map(
							._pm_key = (
								((.id // .topic_id // 0) | tostring) + "|" +
							(.title // .topic_title // "")
							)
						)
						| sort_by(topic_ts_epoch)
						| reverse
						| unique_by(._pm_key)
						| map(del(._pm_key))
					' \
					"$out_json" "$tmp" > "${out_json}.tmp"
				mv "${out_json}.tmp" "$out_json"
			else
				break
			fi

			page=$((page + 1))
		done
	done

	local filtered_tmp
	filtered_tmp=$(mktemp); CLEANUP_PATHS+=("$filtered_tmp")

	jq --arg staff_users "$staff_usernames" \
		--arg staff_ids "$staff_user_ids" \
		--argjson target_staff "$target_is_staff" '
		def staff_list:
			(
				$staff_users
				| split(" ")
				| map(select(length > 0) | ascii_downcase)
			);
		def staff_id_list:
			(
				$staff_ids
				| split(" ")
				| map(select(length > 0))
			);
		def names_from($arr):
			[
				$arr[]?
				| (
					if type == "object" then
						(.username // .name // .user.username // empty)
					else
						.
					end
				)
				| select(type == "string")
				| ascii_downcase
			];
		def topic_groups:
			(
				names_from(.allowed_groups // []) +
				names_from(.target_allowed_groups // []) +
				[
					.allowed_group_names[]?,
					.participant_groups[]?,
					.group_names[]?,
					.target_group_names[]?
				]
				| map(select(type == "string") | ascii_downcase)
			);
		def users_from_topic:
			(
				names_from(.allowed_users // []) +
				names_from(.participants // []) +
				names_from(.posters // []) +
				names_from(.details.participants // [])
			);
		def has_staff_group:
			(
				topic_groups
				| any(.[]; . == "staff" or . == "moderators" or . == "admins")
			);
		def has_staff_user:
			(
				staff_list as $staff
				| (._participant_usernames // []) as $users
				| (._response_staff_names // []) as $resp_staff
				| ($staff + $resp_staff | unique) as $all_staff
				| if ($all_staff | length) == 0 then
					false
				else
					(
						(users_from_topic + $users)
						| any(.[]; ($all_staff | index(.)) != null)
					)
				end
			);
		def has_staff_user_id:
			(
				staff_id_list as $staff
				| (._response_staff_ids // []) as $resp_staff
				| ($staff + $resp_staff | unique) as $all_staff
				| (._participant_user_ids // []) as $ids
				| if ($all_staff | length) == 0 then
					false
				else
					($ids | any(.[]; ($all_staff | index(.)) != null))
				end
			);
		def has_staff_flag:
			(
				[.participants[]?, .posters[]?, .details.participants[]?]
				| map(
					if type == "object" then
						(
							(.admin // false) or
							(.moderator // false) or
							(.staff // false)
						)
					else
						false
					end
				)
				| any(.[]; . == true)
			);
		def topic_ts_epoch:
			(
				(
					.action_created_at //
					.last_posted_at //
					.bumped_at //
					.updated_at //
					.created_at //
					""
				)
				| tostring
				| gsub("\\.[0-9]+"; "")
				| (fromdateiso8601? // 0)
			);
		def staff_catalog_missing:
			(
				(staff_list | length) == 0 and
				(staff_id_list | length) == 0
			);

		[
			.[] |
			select(
				(
					$target_staff == 1 and
					(
						(._source_kind // "") == "general_pm" or
						(._source_kind // "") == "staff_box"
					)
				) or
				(
					staff_catalog_missing and
					(._source_kind // "") == "general_pm"
				) or
				(._source_kind // "") == "staff_box" or
				has_staff_group or
				has_staff_user or
				has_staff_user_id or
				has_staff_flag
			)
			| del(
				._source_kind,
				._response_staff_ids,
				._response_staff_names,
				._participant_user_ids,
				._participant_usernames
			)
		]
			| map(
				._pm_key = (
					((.id // .topic_id // 0) | tostring) + "|" +
					(.title // .topic_title // "")
				)
			)
			| sort_by(topic_ts_epoch)
			| reverse
			| unique_by(._pm_key)
			| map(del(._pm_key))
	' "$out_json" > "$filtered_tmp"
	mv "$filtered_tmp" "$out_json"

	local total
	total=$(jq -r 'length' "$out_json" 2>/dev/null || printf '0')
	print_kv "Staff messages total" "$total" 26
}

# Build the text corpus sent to the AI model for behavior analysis
build_corpus_text() {
	local profile_json="$1"
	local summary_json="$2"
	local posts_json="$3"
	local replies_json="$4"
	local pms_json="$5"

	cat <<-EOF
	Discourse user: $TARGET_USER
	Forum: $BASE_URL
	
	== PROFILE ==
	EOF

	jq -r '.user as $u | [
		"Username: \($u.username // "")",
		"Name: \($u.name // "")",
		"Trust level: \($u.trust_level // 0)",
		"Admin: \($u.admin // false)",
		"Moderator: \($u.moderator // false)",
		"Created: \($u.created_at // "")",
		"Last seen: \($u.last_seen_at // "")"
	] | map(select(. != "Name: ")) | .[]' "$profile_json" 2>/dev/null || true

	cat <<-EOF
	
	== ACTIVITY COUNTS ==
	EOF

	local public_posts_count public_replies_count private_messages_count
	public_posts_count=$(
		jq -r 'length' "$posts_json" 2>/dev/null || printf '0'
	)
	public_replies_count=$(
		jq -r 'length' "$replies_json" 2>/dev/null || printf '0'
	)
	private_messages_count=$(
		jq -r 'length' "$pms_json" 2>/dev/null || printf '0'
	)
	printf 'Public posts: %d\n' "$public_posts_count"
	printf 'Public replies: %d\n' "$public_replies_count"
	printf 'Staff messages: %d\n' "$private_messages_count"

	cat <<-EOF
	
	== PUBLIC POSTS (sample) ==
	EOF

	jq -r '.[:100] | .[] | [
		"---",
		"When: \(.created_at // .action_created_at // "")",
		"Topic: \(.topic_title // .title // "")",
		"Excerpt: \(
			(.excerpt // .text // .cooked // "")
			| gsub("[\\r\\n]+";" ")
			| .[0:300]
		)"
	] | .[]' "$posts_json" 2>/dev/null || true

	cat <<-EOF
	
	== PUBLIC REPLIES (sample) ==
	EOF

	jq -r '.[:100] | .[] | [
		"---",
		"When: \(.created_at // .action_created_at // "")",
		"Topic: \(.topic_title // .title // "")",
		"Excerpt: \(
			(.excerpt // .text // .cooked // "")
			| gsub("[\\r\\n]+";" ")
			| .[0:300]
		)"
	] | .[]' "$replies_json" 2>/dev/null || true

	cat <<-EOF
	
	== PRIVATE MESSAGES (titles only) ==
	EOF

	jq -r '
		.[:50]
		| .[]
		| "- \(
			.action_created_at //
			.last_posted_at //
			.bumped_at //
			.updated_at //
			.created_at //
			""
		) | \(.title // "(no title)")"
	' "$pms_json" 2>/dev/null || true
}

# Repeat a character N times, including multibyte characters
repeat_char() {
	local count="$1"
	local char="$2"
	[ "$count" -le 0 ] && return 0
	local pad
	printf -v pad '%*s' "$count" ''
	printf '%s' "${pad// /$char}"
}

# Render a colored score bar where higher values are higher risk
score_bar() {
	local val="$1" max="${2:-100}" width="${3:-20}"
	local filled=$(( val * width / max ))
	[ "$filled" -gt "$width" ] && filled=$width
	local empty=$(( width - filled ))
	local bar_color="green"
	[ "$val" -ge 40 ] && bar_color="yellow"
	[ "$val" -ge 70 ] && bar_color="red"
	local filled_block empty_block
	filled_block=$(repeat_char "$filled" "█")
	empty_block=$(repeat_char "$empty" "░")
	printf '%s%s %s' \
		"$(color "$bar_color" "$filled_block")" \
		"$(color gray "$empty_block")" \
		"$(color dim "$val/100")"
}

# Render a colored score bar where higher values are better
score_bar_inverse() {
	local val="$1" max="${2:-100}" width="${3:-20}"
	local filled=$(( val * width / max ))
	[ "$filled" -gt "$width" ] && filled=$width
	local empty=$(( width - filled ))
	local bar_color="red"
	[ "$val" -ge 40 ] && bar_color="yellow"
	[ "$val" -ge 70 ] && bar_color="green"
	local filled_block empty_block
	filled_block=$(repeat_char "$filled" "█")
	empty_block=$(repeat_char "$empty" "░")
	printf '%s%s %s' \
		"$(color "$bar_color" "$filled_block")" \
		"$(color gray "$empty_block")" \
		"$(color dim "$val/100")"
}

# Call OpenAI with collected user activity and print a formatted report
openai_analyze() {
	local corpus_text="$1"

	: "${OPENAI_API_KEY:?OPENAI_API_KEY not set}"
	local model="${OPENAI_MODEL:-gpt-5.2-chat-latest}"

	local system_prompt
	system_prompt="$(cat <<'EOF'
You are a support triage analyst for a small open-source project where
developers also handle support. Analyze a Discourse forum user's behavior
to help the team prioritize limited time.

Context: this is a small development team. Every minute spent on
unproductive support interactions is time taken away from development.
Identify users who waste support time through vague questions, refusal to
cooperate, topic derailment, emotional manipulation, or repeated low-effort
tickets.
If the profile marks the user as Admin: true or Moderator: true, treat them
as staff. Staff messages may include moderation/ops duties and should not be
judged as support abuse unless there is clear evidence.

Analyze the user's posts, replies, and private messages. Look for:
- Question clarity: does the user describe the problem, provide steps,
  include errors/screenshots?
- Responsiveness: do they answer follow-up questions directly?
- Cooperation: do they follow instructions, provide requested info, and stay
  on topic?
- Emotional state: calm, frustrated, aggressive, manipulative, or erratic?
- Patterns: repeated tickets for the same issue, abandoned threads?
- Abuse potential: willful vagueness, derailment, hostility?

Return ONLY valid JSON (no markdown fences, no commentary). JSON structure:
{
  "summary": "2-3 sentence behavioral summary",
  "top_topics": [
    {
      "topic": "brief description",
      "status": "resolved|unresolved|abandoned|recurring",
      "clarity": "clear|vague|incoherent"
    }
  ],
  "scores": {
    "question_clarity": 0-100,
    "responsiveness": 0-100,
    "cooperation": 0-100,
    "technical_competence": 0-100,
    "emotional_stability": 0-100,
    "abuse_likelihood": 0-100,
    "time_waste_risk": 0-100
  },
  "emotional_profile": "paragraph",
  "cooperation_breakdown": {
    "follows_instructions": "yes|no|partially - brief note",
    "provides_details": "yes|no|partially - brief note",
    "stays_on_topic": "yes|no|partially - brief note",
    "acknowledges_responses": "yes|no|partially - brief note",
    "accepts_solutions": "yes|no|partially - brief note"
  },
  "red_flags": ["specific concerning behaviors observed"],
  "time_drain_assessment": "paragraph",
  "recommended_action": "specific actionable advice",
  "confidence": 0-100
}

Score guide for abuse_likelihood and time_waste_risk:
- 0-20: Genuine user, productive interactions
- 21-40: Occasionally unfocused but generally cooperative
- 41-60: Frequently wastes time, needs firm boundaries
- 61-80: Significant unproductive pattern, consider limiting support
- 81-100: Actively harmful to team productivity, restrict access

For cooperation_breakdown fields, each value must use:
"yes|no|partially - concrete reason". Do not output bare status words.

For top_topics: list up to 5 most frequent/significant topics.
EOF
)"

	printf 'Calling OpenAI API (%s)...\n' "$model"

	local resp_json
	resp_json="$(curl -sS https://api.openai.com/v1/chat/completions \
		-H "Authorization: Bearer ${OPENAI_API_KEY}" \
		-H "Content-Type: application/json" \
		-d "$(jq -n \
			--arg model "$model" \
			--arg system "$system_prompt" \
			--arg user "$corpus_text" \
			'{
				model: $model,
				messages: [
					{role: "system", content: $system},
					{role: "user", content: $user}
				],
				response_format: {type: "json_object"}
			}')" 2>&1)" || {
		printf '%s\n' "$(color red "Curl failed: $resp_json")"
		return 1
	}

	if echo "$resp_json" | jq -e '.error?' >/dev/null 2>&1; then
		local error_msg
		error_msg=$(
			echo "$resp_json" \
				| jq -r '.error.message // .error.code // "Unknown API error"'
		)
		printf '%s\n' "$(color red "OpenAI API error: $error_msg")"
		printf '%s\n' "$(color yellow "Response: $resp_json")"
		return 1
	fi

	local out
	out="$(jq -r '.choices[0].message.content' <<<"$resp_json" 2>/dev/null)" || {
		printf '%s\n' "$(color red "Failed to extract response content")"
		printf '%s\n' "$(color yellow "Raw response: $resp_json")"
		return 1
	}

	out="$(printf '%s\n' "$out" | strip_code_fences)"

	if ! jq -e . >/dev/null 2>&1 <<<"$out"; then
		printf '%s\n' "$(color yellow "AI returned non-JSON output:")"
		printf '%s\n' "$out"
		return 1
	fi

	# Summary
	printf '\n%s\n' "$(color bold "Summary:")"
	jq -r '.summary // "(none)"' <<<"$out" | while read -r line; do
		printf '%s\n' "$(color dim "$line")"
	done

	# Scores
	printf '\n%s\n' "$(color bold "Scores:")"
	local -a score_keys=(
		"question_clarity"
		"responsiveness"
		"cooperation"
		"technical_competence"
		"emotional_stability"
	)
	local -a score_labels=(
		"Question clarity"
		"Responsiveness"
		"Cooperation"
		"Technical competence"
		"Emotional stability"
	)
	for i in "${!score_keys[@]}"; do
		local sval padded
		sval=$(jq -r ".scores.${score_keys[$i]} // 0" <<<"$out")
		padded=$(printf '%-22s' "${score_labels[$i]}")
		printf '  %s  %s\n' \
			"$(color dim "$padded")" \
			"$(score_bar_inverse "$sval")"
	done

	# Abuse and time waste (inverted: high = bad)
	printf '\n%s\n' "$(color bold "Risk Assessment:")"
	local abuse_val twaste_val padded
	local qclar rresp coop tech emo overall_score
	abuse_val=$(jq -r '.scores.abuse_likelihood // 0' <<<"$out")
	twaste_val=$(jq -r '.scores.time_waste_risk // 0' <<<"$out")
	padded=$(printf '%-22s' "Abuse likelihood")
	printf '  %s  %s\n' \
		"$(color dim "$padded")" \
		"$(score_bar "$abuse_val")"
	padded=$(printf '%-22s' "Time waste risk")
	printf '  %s  %s\n' \
		"$(color dim "$padded")" \
		"$(score_bar "$twaste_val")"
	qclar=$(jq -r '.scores.question_clarity // 0' <<<"$out")
	rresp=$(jq -r '.scores.responsiveness // 0' <<<"$out")
	coop=$(jq -r '.scores.cooperation // 0' <<<"$out")
	tech=$(jq -r '.scores.technical_competence // 0' <<<"$out")
	emo=$(jq -r '.scores.emotional_stability // 0' <<<"$out")
	overall_score=$((qclar + rresp + coop + tech + emo +
		(100 - abuse_val) + (100 - twaste_val) + 3))
	overall_score=$((overall_score / 7))
	[ "$overall_score" -lt 0 ] && overall_score=0
	[ "$overall_score" -gt 100 ] && overall_score=100

	# Separate value score block (high = more useful/valuable).
	printf '\n%s\n' "$(color bold "Overall Score:")"
	padded=$(printf '%-22s' "Overall score")
	printf '  %s  %s\n' \
		"$(color dim "$padded")" \
		"$(score_bar_inverse "$overall_score")"

	# Top topics
	printf '\n%s\n' "$(color bold "Top Topics:")"
	jq -r '(.top_topics // [])[:5] | if length == 0 then "  (none)"
		else .[] | "  " +
			(if .status == "resolved" then "✓"
			 elif .status == "abandoned" then "⊘"
			 elif .status == "recurring" then "↻"
			 else "●" end) +
			" " + .topic +
			" [" + (.clarity // "unknown") + "]"
		end' <<<"$out" | while read -r line; do
		printf '%s\n' "$(color dim "$line")"
	done

	# Emotional profile
	printf '\n%s\n' "$(color bold "Emotional Profile:")"
	local emotional_profile
	emotional_profile=$(jq -r '.emotional_profile // "(none)"' <<<"$out")
	printf '  %s\n' "$(color dim "$emotional_profile")"

	# Cooperation breakdown
	printf '\n%s\n' "$(color bold "Cooperation Breakdown:")"
	local -a coop_keys=(
		"follows_instructions"
		"provides_details"
		"stays_on_topic"
		"acknowledges_responses"
		"accepts_solutions"
	)
	local -a coop_labels=(
		"Follows instructions"
		"Provides details"
		"Stays on topic"
		"Acknowledges responses"
		"Accepts solutions"
	)
	for i in "${!coop_keys[@]}"; do
		local cval status note ccolor padded status_block status_field
		cval=$(
			jq -r \
				".cooperation_breakdown.${coop_keys[$i]} // \"unknown\"" \
				<<<"$out"
		)
		status="$cval"
		note=""
		case "$cval" in
			*" - "*) status="${cval%% - *}"; note="${cval#* - }" ;;
			*" – "*) status="${cval%% – *}"; note="${cval#* – }" ;;
		esac

		ccolor="gray"
		status_block="[unknown]"
		case "$status" in
			[Yy][Ee][Ss]*) ccolor="green"; status_block="[yes]" ;;
			[Nn][Oo]*) ccolor="red"; status_block="[no]" ;;
			[Pp][Aa][Rr][Tt][Ii][Aa][Ll][Ll][Yy]*)
				ccolor="yellow"
				status_block="[partial]"
				;;
		esac
		if [ -z "$note" ]; then
			if [ "$status_block" = "[unknown]" ]; then
				note="$cval"
			else
				note="(no details from model)"
			fi
		fi

		padded=$(printf '%-22s' "${coop_labels[$i]}")
		status_field=$(printf '%-10s' "$status_block")
		printf '  %s  %s  %s\n' \
			"$(color dim "$padded")" \
			"$(color "$ccolor" "$status_field")" \
			"$(color dim "$note")"
	done

	# Red flags
	local red_flags_count
	red_flags_count=$(jq -r '(.red_flags // []) | length' <<<"$out")
	if [ "$red_flags_count" -gt 0 ]; then
		printf '\n%s\n' "$(color bold "Red Flags:")"
	jq -r '(.red_flags // []) | .[] | "  ⚠ " + .' \
		<<<"$out" | while read -r line; do
			printf '%s\n' "$(color red "$line")"
		done
	fi

	# Time drain assessment
	printf '\n%s\n' "$(color bold "Time Drain Assessment:")"
	local time_drain_assessment
	time_drain_assessment=$(
		jq -r '.time_drain_assessment // "(none)"' <<<"$out"
	)
	printf '  %s\n' "$(color dim "$time_drain_assessment")"

	# Recommended action
	printf '\n%s\n' "$(color bold "Recommended Action:")"
	local recommended_action
	recommended_action=$(jq -r '.recommended_action // "(none)"' <<<"$out")
	printf '  %s\n' "$(color yellow "$recommended_action")"

	# Confidence
	local conf
	conf=$(jq -r '.confidence // 0' <<<"$out")
	printf '\n'
	print_kv "Confidence" "$conf/100" 15
}

# Parse CLI options and validate numeric arguments
parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			-b|--base)       BASE_URL="${2:-}"; shift 2 ;;
			-u|--user)       TARGET_USER="${2:-}"; shift 2 ;;
			-p|--pages)      MAX_PAGES="${2:-}"; shift 2 ;;
			-d|--since-days) SINCE_DAYS="${2:-}"; shift 2 ;;
			-s|--samples)    SAMPLE_LIMIT="${2:-}"; shift 2 ;;
			-N|--no-color)   USE_COLOR=0; shift ;;
			-h|--help)       usage ;;
			*)               die "Unknown option: $1" ;;
		esac
	done

	[ -n "$BASE_URL" ] || usage
	[ -n "$TARGET_USER" ] || usage
	validate_base_url "$BASE_URL" || die "Invalid base URL"
	if ! [[ "$MAX_PAGES" =~ ^[0-9]+$ ]] || [ "$MAX_PAGES" -le 0 ]; then
		die "--pages must be a positive integer"
	fi
	if ! [[ "$SINCE_DAYS" =~ ^[0-9]+$ ]]; then
		die "--since-days must be a non-negative integer"
	fi
	if ! [[ "$SAMPLE_LIMIT" =~ ^[0-9]+$ ]]; then
		die "--samples must be a non-negative integer"
	fi
}

# Coordinate data collection, filtering, and report rendering
main() {
	init_color
	need_cmds
	parse_args "$@"
	check_env

	section "Requesting analysis"
	print_kv "User" "$TARGET_USER" 10
	print_kv "Forum" "$BASE_URL" 10
	print_kv "Since" "last $SINCE_DAYS days" 10

	subsection "Validating user"
	validate_user_exists "$TARGET_USER" || die "User not found"

	local user_id
	user_id=$(get_user_id "$TARGET_USER") || die "Failed to get user ID"
	print_kv "User ID" "$user_id" 10

	subsection "Fetching profile"
	local profile_json summary_json admin_user_json admin_ips_json
	local admin_emails_json about_json
	local last_ip_users_json
	profile_json=$(mktemp); CLEANUP_PATHS+=("$profile_json")
	summary_json=$(mktemp); CLEANUP_PATHS+=("$summary_json")
	admin_user_json=$(mktemp); CLEANUP_PATHS+=("$admin_user_json")
	admin_ips_json=$(mktemp); CLEANUP_PATHS+=("$admin_ips_json")
	admin_emails_json=$(mktemp); CLEANUP_PATHS+=("$admin_emails_json")
	about_json=$(mktemp); CLEANUP_PATHS+=("$about_json")
	last_ip_users_json=$(mktemp); CLEANUP_PATHS+=("$last_ip_users_json")

	discourse_get "$BASE_URL/u/$TARGET_USER.json" "$profile_json"
	discourse_get "$BASE_URL/u/$TARGET_USER/summary.json" "$summary_json"
	printf '{}\n' > "$admin_user_json"
	printf '[]\n' > "$admin_ips_json"
	printf '{}\n' > "$admin_emails_json"
	printf '{}\n' > "$about_json"
	local admin_user_id_url admin_user_name_url
	local admin_ips_id_url admin_ips_name_url
	local user_emails_url admin_emails_id_url
	admin_user_id_url="$BASE_URL/admin/users/$user_id.json"
	admin_user_name_url="$BASE_URL/admin/users/$TARGET_USER.json"
	admin_ips_id_url="$BASE_URL/admin/users/$user_id/ips.json"
	admin_ips_name_url="$BASE_URL/admin/users/$TARGET_USER/ips.json"
	user_emails_url="$BASE_URL/u/$TARGET_USER/emails.json"
	admin_emails_id_url="$BASE_URL/admin/users/$user_id/emails.json"
	discourse_get "$admin_user_id_url" "$admin_user_json" 2>/dev/null \
		|| discourse_get "$admin_user_name_url" "$admin_user_json" \
		2>/dev/null || true
	discourse_get "$admin_ips_id_url" "$admin_ips_json" 2>/dev/null \
		|| discourse_get "$admin_ips_name_url" "$admin_ips_json" \
		2>/dev/null || true
	discourse_get "$user_emails_url" "$admin_emails_json" 2>/dev/null \
		|| discourse_get "$admin_emails_id_url" "$admin_emails_json" \
		2>/dev/null || true
	discourse_get "$BASE_URL/about.json" "$about_json" 2>/dev/null || true

	local name trust_level created_at last_seen last_posted_at
	local is_admin is_moderator is_staff
	local target_user_lc
	local staff_usernames staff_user_ids
	local locale timezone website location bio
	local email active approved silenced suspended_till
	local registration_ip last_known_ip bounce_score badge_count
	local email_display
	local known_ips_count known_ip_sample known_ip_countries account_status
	local last_ip_peer_count last_ip_peer_usernames
	
	name=$(jq -r '.user.name // ""' "$profile_json")
	trust_level=$(jq -r '.user.trust_level // 0' "$profile_json")
	created_at=$(jq -r '.user.created_at // ""' "$profile_json")
	last_seen=$(jq -r '.user.last_seen_at // ""' "$profile_json")
	last_posted_at=$(jq -r '.user.last_posted_at // ""' "$profile_json")
	is_admin=$(jq -r '.user.admin // false' "$profile_json")
	is_moderator=$(jq -r '.user.moderator // false' "$profile_json")
	is_staff=0
	if [ "$(format_bool "$is_admin")" = "yes" ] || \
		[ "$(format_bool "$is_moderator")" = "yes" ]; then
		is_staff=1
	fi
	target_user_lc=$(printf '%s' "$TARGET_USER" | tr '[:upper:]' '[:lower:]')
	staff_usernames=$(
		jq -r '
			[
				(.about.admins[]?.username // empty),
				(.about.moderators[]?.username // empty)
			]
			| map(select(type == "string"))
			| map(select(length > 0) | ascii_downcase)
			| unique
			| join(" ")
		' "$about_json" 2>/dev/null || printf ''
	)
	staff_user_ids=$(
		jq -r '
			[
				(.about.admins[]?.id // .about.admins[]?.user_id // empty),
				(
					.about.moderators[]?.id //
					.about.moderators[]?.user_id //
					empty
				)
			]
			| map(tostring)
			| map(select(length > 0))
			| unique
			| join(" ")
		' "$about_json" 2>/dev/null || printf ''
	)
	if [ "$is_staff" -eq 0 ] && [ -n "$staff_usernames" ]; then
		case " $staff_usernames " in
			*" $target_user_lc "*) is_staff=1 ;;
		esac
	fi
	if [ "$is_staff" -eq 0 ] && [ -n "$staff_user_ids" ]; then
		case " $staff_user_ids " in
			*" $user_id "*) is_staff=1 ;;
		esac
	fi
	if [ "$is_staff" -eq 1 ]; then
		staff_usernames=$(
			jq -nr --arg names "$staff_usernames" --arg user "$TARGET_USER" '
				(
					($names | split(" ")) +
					[($user | ascii_downcase)]
				)
				| map(select(length > 0))
				| unique
				| join(" ")
			'
		)
		staff_user_ids=$(
			jq -nr --arg ids "$staff_user_ids" --arg uid "$user_id" '
				(
					($ids | split(" ")) +
					[($uid | tostring)]
				)
				| map(select(length > 0))
				| unique
				| join(" ")
			'
		)
	fi
	locale=$(jq -r '.user.locale // ""' "$profile_json")
	timezone=$(jq -r '.user.timezone // ""' "$profile_json")
	website=$(
		jq -r '.user.website_name // .user.website // ""' "$profile_json"
	)
	location=$(jq -r '.user.location // ""' "$profile_json")
	bio=$(jq -r '.user.bio_raw // ""' "$profile_json")
	bio=$(strip_markdown "$bio")
	email=$(
		jq -r '
			[
				.user.email,
				.email,
				.user.primary_email,
				.primary_email,
				.user.email_address,
				.email_address,
				(.user_emails[]?.email?),
				(.emails[]?.email?),
				(.secondary_emails[]?)
			]
			| map(select(type == "string"))
			| map(select(length > 0 and . != "null"))
			| first // ""
		' "$admin_user_json" 2>/dev/null || printf ''
	)
	if [ -z "$email" ]; then
		email=$(jq -r '.user.email // ""' "$profile_json" \
			2>/dev/null || printf '')
	fi
	if [ -z "$email" ]; then
		email=$(
			jq -r '
				[
					.email,
					.primary_email,
					(.emails[]?.email?),
					(.user_emails[]?.email?),
					(.email_addresses[]?.email?),
					(.[]? | if type == "object" then (.email // empty)
						else empty end),
					(.[]? | if type == "string" then . else empty end)
				]
				| map(select(type == "string"))
				| map(select(length > 0 and . != "null"))
				| first // ""
			' "$admin_emails_json" 2>/dev/null || printf ''
		)
	fi
	active=$(jq -r '.user.active // .active // ""' "$admin_user_json" \
		2>/dev/null || printf '')
	approved=$(jq -r '.user.approved // .approved // ""' "$admin_user_json" \
		2>/dev/null || printf '')
	silenced=$(jq -r '.user.silenced // .silenced // ""' "$admin_user_json" \
		2>/dev/null || printf '')
	suspended_till=$(
		jq -r '.user.suspended_till // .suspended_till // ""' \
			"$admin_user_json" 2>/dev/null || printf ''
	)
	registration_ip=$(
		jq -r '
			.registration_ip_address // .registration_ip //
			.user.registration_ip_address // .user.registration_ip // ""
		' "$admin_user_json" 2>/dev/null || printf ''
	)
	last_known_ip=$(
		jq -r '
			.ip_address // .last_ip_address //
			.user.ip_address // .user.last_ip_address // ""
		' "$admin_user_json" 2>/dev/null || printf ''
	)
	last_known_ip=$(normalize_ip_for_lookup "$last_known_ip")
	if [ -z "$last_known_ip" ]; then
		last_known_ip=$(
			jq -r '
				(if type == "array" then .
				 else (.ip_addresses // .user_ips // .ips // [])
				 end)
				| [ .[]? | (.ip_address // .ip // .address // empty) ]
				| map(select(length > 0))
				| first // ""
			' "$admin_ips_json" 2>/dev/null || printf ''
		)
		last_known_ip=$(normalize_ip_for_lookup "$last_known_ip")
	fi
	bounce_score=$(jq -r '.user.bounce_score // .bounce_score // ""' \
		"$admin_user_json" 2>/dev/null || printf '')
	badge_count=$(
		jq -r '
			.user.badge_count // .badge_count //
			(
				if (.user.badges? | type) == "array"
				then (.user.badges | length)
				else empty
				end
			) // empty
		' "$profile_json" 2>/dev/null || printf ''
	)
	if [ -z "$badge_count" ]; then
		badge_count=$(
			jq -r '
				(if (.user_summary.badges? | type) == "array"
				 then (.user_summary.badges | length)
				 else empty
				 end) // empty
			' "$summary_json" 2>/dev/null || printf ''
		)
	fi
	[ -z "$bounce_score" ] && bounce_score="unknown"
	[ -z "$badge_count" ] && badge_count="unknown"
	email_display="$email"
	[ -z "$email_display" ] && email_display="(not available)"
	known_ips_count=$(
		jq -r '
			(if type == "array" then .
			 else (.ip_addresses // .user_ips // .ips // [])
			 end) as $ips
			| [ $ips[]? | (.ip_address // .ip // .address // empty) ]
			| map(select(length > 0))
			| unique
			| length
		' "$admin_ips_json" 2>/dev/null || printf '0'
	)
	known_ip_sample=$(
		jq -r '
			(if type == "array" then .
			 else (.ip_addresses // .user_ips // .ips // [])
			 end) as $ips
			| [ $ips[]? | (.ip_address // .ip // .address // empty) ]
			| map(select(length > 0))
			| unique
			| .[:5]
			| join(", ")
		' "$admin_ips_json" 2>/dev/null || printf ''
	)
	known_ip_countries=$(
		jq -r '
			(if type == "array" then .
			 else (.ip_addresses // .user_ips // .ips // [])
			 end) as $ips
			| [
				$ips[]?
				| (
					.country //
					.country_name //
					.country_code //
					.location //
					empty
				)
				| tostring
			]
			| map(select(length > 0))
			| map(
				if test(",")
				then (split(",")[-1] | gsub("^ +| +$"; ""))
				else .
				end
			)
			| unique
			| .[:6]
			| join(", ")
		' "$admin_ips_json" 2>/dev/null || printf ''
	)
	case "$known_ips_count" in
		''|*[!0-9]*) known_ips_count=0 ;;
	esac

	last_ip_peer_count=0
	last_ip_peer_usernames=""
	if [ -n "$last_known_ip" ]; then
		fetch_users_by_ip "$last_known_ip" "$last_ip_users_json"
		last_ip_peer_count=$(
			jq -r --arg user "$TARGET_USER" '
				[
					.[]?
					| tostring
					| select(length > 0)
					| select((ascii_downcase) != ($user | ascii_downcase))
				]
				| unique
				| length
			' "$last_ip_users_json" 2>/dev/null || printf '0'
		)
		last_ip_peer_usernames=$(
			jq -r --arg user "$TARGET_USER" '
				[
					.[]?
					| tostring
					| select(length > 0)
					| select((ascii_downcase) != ($user | ascii_downcase))
				]
				| unique
				| .[:10]
				| join(", ")
			' "$last_ip_users_json" 2>/dev/null || printf ''
		)
		case "$last_ip_peer_count" in
			''|*[!0-9]*) last_ip_peer_count=0 ;;
		esac
	fi

	account_status=""
	local -a account_flags=()
	if [ -n "$active" ] && [ "$(format_bool "$active")" = "no" ]; then
		account_flags+=("inactive")
	fi
	if [ -n "$approved" ] && [ "$(format_bool "$approved")" = "no" ]; then
		account_flags+=("unapproved")
	fi
	if [ -n "$silenced" ] && [ "$(format_bool "$silenced")" = "yes" ]; then
		account_flags+=("silenced")
	fi
	if [ "${#account_flags[@]}" -gt 0 ]; then
		account_status=$(IFS=', '; printf '%s' "${account_flags[*]}")
	fi

	local days_visited topics_entered post_count
	local likes_given likes_received time_read
	days_visited=$(jq -r '.user_summary.days_visited // 0' "$summary_json")
	topics_entered=$(jq -r '.user_summary.topics_entered // 0' "$summary_json")
	post_count=$(jq -r '.user_summary.post_count // 0' "$summary_json")
	likes_given=$(jq -r '.user_summary.likes_given // 0' "$summary_json")
	likes_received=$(jq -r '.user_summary.likes_received // 0' "$summary_json")
	time_read=$(jq -r '.user_summary.time_read // 0' "$summary_json")

	section "Profile"
	[ -n "$name" ] && print_kv "Name" "$name" 20
	print_kv "Username" "$TARGET_USER" 20
	print_kv "Trust level" "$trust_level" 20
	print_kv "Registered" "$(format_iso_date "$created_at")" 20
	if [ -n "$last_posted_at" ] && [ "$last_posted_at" != "null" ]; then
		print_kv "Last public post" "$(format_iso_date "$last_posted_at")" 20
	fi
	print_kv "Last seen" "$(format_relative_date "$last_seen")" 20
	[ -n "$locale" ] && print_kv "Locale" "$locale" 20
	[ -n "$timezone" ] && print_kv "Timezone" "$timezone" 20
	[ -n "$location" ] && print_kv "Location" "$location" 20
	[ -n "$website" ] && print_kv "Website" "$website" 20
	print_kv "Email" "$email_display" 20
	print_kv "Bounce score" "$bounce_score" 20
	print_kv "Badges" "$badge_count" 20
	[ -n "$account_status" ] && print_kv "Account flags" "$account_status" 20
	if [ -n "$suspended_till" ] && [ "$suspended_till" != "null" ]; then
		print_kv "Suspended until" "$(format_iso_date "$suspended_till")" 20
	fi
	[ -n "$registration_ip" ] && print_kv "Registration IP" "$registration_ip" 20
	[ -n "$last_known_ip" ] && print_kv "Last known IP" "$last_known_ip" 20
	if [ -n "$last_known_ip" ]; then
		if [ "$last_ip_peer_count" -gt 0 ] && \
			[ -n "$last_ip_peer_usernames" ]; then
			print_kv "Last IP peers" \
				"$last_ip_peer_count ($last_ip_peer_usernames)" 20
		else
			print_kv "Last IP peers" "$last_ip_peer_count" 20
		fi
	fi
	if [ "$known_ips_count" -gt 0 ]; then
		print_kv "Known IPs" "$known_ips_count" 20
		if [ -n "$known_ip_countries" ]; then
			print_kv "IP countries" "$known_ip_countries" 20
		fi
		[ -n "$known_ip_sample" ] && print_kv "IP sample" "$known_ip_sample" 20
	fi
	[ -n "$bio" ] && print_kv "Bio" "$bio" 20

	section "Forum Stats"
	print_kv "Days visited" "$days_visited" 20
	print_kv "Topics entered" "$topics_entered" 20
	print_kv "Public posts" "$post_count" 20
	print_kv "Likes given" "$likes_given" 20
	print_kv "Likes received" "$likes_received" 20
	print_kv "Time reading" "$(format_read_time "$time_read")" 20

	subsection "Fetching activity streams"
	print_kv "Scan cap" "$((MAX_PAGES * 30)) items per stream" 26
	local topics_raw posts_raw replies_raw pms_raw
	topics_raw=$(mktemp); CLEANUP_PATHS+=("$topics_raw")
	posts_raw=$(mktemp); CLEANUP_PATHS+=("$posts_raw")
	replies_raw=$(mktemp); CLEANUP_PATHS+=("$replies_raw")
	pms_raw=$(mktemp); CLEANUP_PATHS+=("$pms_raw")

	fetch_user_actions 4 "$TARGET_USER" "$topics_raw"
	fetch_user_actions 5 "$TARGET_USER" "$posts_raw"
	fetch_user_actions 6 "$TARGET_USER" "$replies_raw"
	fetch_private_messages "$TARGET_USER" "$pms_raw" "$staff_usernames" \
		"$staff_user_ids" "$is_staff"

	local all_posts
	all_posts=$(mktemp); CLEANUP_PATHS+=("$all_posts")
	jq -s '.[0] + .[1]' "$topics_raw" "$posts_raw" > "$all_posts"

	subsection "Filtering by date"
	local posts_json replies_json pms_json
	posts_json=$(mktemp); CLEANUP_PATHS+=("$posts_json")
	replies_json=$(mktemp); CLEANUP_PATHS+=("$replies_json")
	pms_json=$(mktemp); CLEANUP_PATHS+=("$pms_json")

	filter_since_days "$all_posts" "$posts_json" "$SINCE_DAYS" "Public posts"
	filter_since_days "$replies_raw" "$replies_json" "$SINCE_DAYS" "Public replies"
	filter_since_days "$pms_raw" "$pms_json" "$SINCE_DAYS" "Staff messages"

	local posts_f replies_f pms_f total_f
	posts_f=$(jq -r 'length' "$posts_json")
	replies_f=$(jq -r 'length' "$replies_json")
	pms_f=$(jq -r 'length' "$pms_json")
	total_f=$((posts_f + replies_f + pms_f))

	section "Activity (Last $SINCE_DAYS Days)"
	print_kv "Public posts" "$posts_f" 20
	print_kv "Public replies" "$replies_f" 20
	print_kv "Staff messages" "$pms_f" 20
	print_kv "Total" "$total_f" 20

	if [ "$total_f" -gt 0 ]; then
		if [ "$SAMPLE_LIMIT" -gt 0 ]; then
			section "Latest Activity"
			
			if [ "$posts_f" -gt 0 ]; then
				subsection "Latest public posts"
					jq -r --argjson limit "$SAMPLE_LIMIT" '
						map({
							ts: (
								.action_created_at //
								.last_posted_at //
								.bumped_at //
								.updated_at //
								.created_at //
								""
							),
							title: (.topic_title // .title // "(no title)")
						})
						| sort_by(
							.ts | gsub("\\.[0-9]+";"") |
							(fromdateiso8601? // 0)
						)
						| reverse
						| reduce .[] as $it
							([];
							 if any(.[]; .title == $it.title)
							 then .
							 else . + [$it]
							 end)
						| .[:$limit]
						| .[]
						| [.title, .ts]
						| @tsv' "$posts_json" \
					| while IFS=$'\t' read -r title ts; do
					ts="$(format_iso_compact "$ts")"
					printf '  %s  %s\n' \
						"$(color bold "$title")" \
						"$(color gray "[$ts]")"
				done
			fi

			if [ "$replies_f" -gt 0 ]; then
				subsection "Latest replies"
					jq -r --argjson limit "$SAMPLE_LIMIT" '
						map({
							ts: (
								.action_created_at //
								.last_posted_at //
								.bumped_at //
								.updated_at //
								.created_at //
								""
							),
							title: (.topic_title // .title // "(no title)")
						})
						| sort_by(
							.ts | gsub("\\.[0-9]+";"") |
							(fromdateiso8601? // 0)
						)
						| reverse
						| reduce .[] as $it
							([];
							 if any(.[]; .title == $it.title)
							 then .
							 else . + [$it]
							 end)
						| .[:$limit]
						| .[]
						| [.title, .ts]
						| @tsv' "$replies_json" \
					| while IFS=$'\t' read -r title ts; do
					ts="$(format_iso_compact "$ts")"
					printf '  %s  %s\n' \
						"$(color bold "$title")" \
						"$(color gray "[$ts]")"
				done
			fi

			if [ "$pms_f" -gt 0 ]; then
				subsection "Staff messages"
					jq -r --argjson limit "$SAMPLE_LIMIT" '
						map({
							ts: (
								.action_created_at //
								.last_posted_at //
								.bumped_at //
								.updated_at //
								.created_at //
								""
							),
							title: (.title // "(no title)")
						})
						| sort_by(
							.ts | gsub("\\.[0-9]+";"") |
							(fromdateiso8601? // 0)
						)
						| reverse
						| reduce .[] as $it
							([];
							 if any(.[]; .title == $it.title)
							 then .
							 else . + [$it]
							 end)
						| .[:$limit]
						| .[]
						| [.title, .ts]
						| @tsv' "$pms_json" \
					| while IFS=$'\t' read -r title ts; do
					ts="$(format_iso_compact "$ts")"
					printf '  %s  %s\n' \
						"$(color bold "$title")" \
						"$(color gray "[$ts]")"
				done
			fi
		fi

		section "AI Analysis"
		local corpus
		corpus="$(
			build_corpus_text \
				"$profile_json" \
				"$summary_json" \
				"$posts_json" \
				"$replies_json" \
				"$pms_json"
		)"
		openai_analyze "$corpus" || {
			printf '%s\n' "$(color yellow "Analysis unavailable")"
		}
	else
		printf '\n%s\n' "$(color yellow \
			"No posts/replies/PMs found in the last ${SINCE_DAYS} days")"
		printf '%s\n' "$(color dim \
			"User may still be active in other actions; try older range")"
	fi

}

main "$@"
