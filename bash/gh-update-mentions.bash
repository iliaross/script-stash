#!/usr/bin/env bash
# gh-update-mentions.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script replaces an old GitHub username with a new one in issue, PR bodies
# and comments. It uses `gh api` to search and then updates any matches in place,
# walking through all pages of results and comments.

set -euo pipefail

# Use stored auth login
unset GH_TOKEN GITHUB_TOKEN

readonly SCRIPT_NAME="gh-update-mentions.bash"

usage() {
	printf 'Usage: %s --old <user> --new <user> [--dry-run]\n' "$SCRIPT_NAME" >&2
	printf '\n' >&2
	printf 'Examples:\n' >&2
	printf '  %s\n' "$SCRIPT_NAME --old old_gh_user --new new_gh_user"
	printf '  %s\n' "$SCRIPT_NAME --old old_gh_user --new new_gh_user --dry-run"
	exit 1
}

main() {
	local OLD_USER=""
	local NEW_USER=""
	local DRY_RUN=0

	while [ "$#" -gt 0 ]; do
		case "$1" in
			--old)
				[ "${2:-}" != "" ] || usage
				OLD_USER="$2"
				shift 2
				;;
			--new)
				[ "${2:-}" != "" ] || usage
				NEW_USER="$2"
				shift 2
				;;
			--dry-run)
				DRY_RUN=1
				shift
				;;
			-h|--help)
				usage
				;;
			*)
				usage
				;;
		esac
	done

	if [ "$OLD_USER" = "" ] || [ "$NEW_USER" = "" ]; then
		usage
	fi

	# Allow passing "@user" without breaking search and matching
	OLD_USER="${OLD_USER#@}"
	NEW_USER="${NEW_USER#@}"

	readonly QUERY="mentions:${NEW_USER}"

	# Colors (disable with NO_COLOR or non-tty)
	local use_color=0
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		use_color=1
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

	need_cmd() {
		local c="$1"
		if ! command -v "$c" >/dev/null 2>&1; then
			printf '%s\n' "$(color red "Error: Missing required command: $c")" >&2
			exit 1
		fi
	}

	patch_json() {
		local endpoint="$1"
		local json="$2"
		local out=""

		if [ "$DRY_RUN" -eq 1 ]; then
			printf '%s' ""
			return 0
		fi

		out="$(printf '%s' "$json" | gh api -X PATCH "$endpoint" --input - --silent 2>&1)" || {
			printf '%s' "$out"
			return 1
		}

		printf '%s' ""
		return 0
	}

	section "Checking tools and configuration"

	need_cmd gh
	need_cmd jq

	printf "Old user : %s\n" "$(color cyan "$OLD_USER")"
	printf "New user : %s\n" "$(color cyan "$NEW_USER")"
	if [ "$DRY_RUN" -eq 1 ]; then
		printf "Mode     : %s\n\n" "$(color yellow "dry-run")"
	else
		printf "Mode     : %s\n\n" "$(color green "apply")"
	fi

	local tmp_issues tmp_comments
	tmp_issues="$(mktemp)"
	tmp_comments="$(mktemp)"
	trap 'rm -f "$tmp_issues" "$tmp_comments"' EXIT

	section "Searching issues and pull requests"

	if ! gh api --paginate -X GET "search/issues" \
		-f q="$QUERY" \
		-f per_page=100 \
		| jq -c '
			.items[]?
			| {
				number: .number,
				repo: (.repository_url | sub("^https://api.github.com/repos/"; "")),
				html_url: .html_url
			}
		' >"$tmp_issues"
	then
		printf '%s\n' "$(color red "Error: Search request failed.")" >&2
		exit 1
	fi

	local issue_count
	issue_count="$(wc -l <"$tmp_issues" | tr -d ' ')"
	if [ "${issue_count:-0}" -eq 0 ]; then
		printf '%s\n' "$(color yellow "No matching issues or pull requests found.")"
		exit 0
	fi

	printf "Found: %s\n\n" "$(color green "$issue_count")"

	local scanned_issues=0 updated_issues=0 scanned_comments=0 updated_comments=0 errors=0

	section "Processing results"

	while IFS= read -r issue; do
		scanned_issues=$((scanned_issues + 1))

		local issue_number repo_name issue_url
		issue_number="$(printf '%s' "$issue" | jq -r '.number')"
		repo_name="$(printf '%s' "$issue" | jq -r '.repo')"
		issue_url="$(printf '%s' "$issue" | jq -r '.html_url')"

		printf '%s\n' "$(color bold "Issue #${issue_number} in ${repo_name}")"
		printf 'Link: %s\n' "$(color dim "$issue_url")"

		: >"$tmp_comments"
		if ! gh api --paginate -X GET "repos/${repo_name}/issues/${issue_number}/comments" \
			-f per_page=100 \
			| jq -c '.[] | {id: .id, body: .body}' >"$tmp_comments"
		then
			printf '%s\n' "$(color red "  Error: Failed to fetch comments.")" >&2
			errors=$((errors + 1))
			printf '\n'
			continue
		fi

		if [ ! -s "$tmp_comments" ]; then
			printf '%s\n' "$(color dim "  Comments: none")"
		else
			printf '%s\n' "$(color dim "  Comments: scanning...")"
			while IFS= read -r comment; do
				scanned_comments=$((scanned_comments + 1))

				local comment_id comment_body new_body payload err
				comment_id="$(printf '%s' "$comment" | jq -r '.id')"
				comment_body="$(printf '%s' "$comment" | jq -r '.body')"

				if [[ "$comment_body" == *"$OLD_USER"* ]]; then
					new_body="${comment_body//$OLD_USER/$NEW_USER}"
					payload="$(jq -n --arg body "$new_body" '{body: $body}')"

					if [ "$DRY_RUN" -eq 1 ]; then
						printf '  %s %s\n' "$(color yellow "• Would update comment")" "$(color cyan "$comment_id")"
					else
						err="$(patch_json "repos/${repo_name}/issues/comments/${comment_id}" "$payload")" || true
						if [ "$err" = "" ]; then
							updated_comments=$((updated_comments + 1))
							printf '  %s %s\n' "$(color green "✓ Updated comment")" "$(color cyan "$comment_id")"
						else
							errors=$((errors + 1))
							printf '  %s %s\n' "$(color red "✗ Failed to update comment")" "$(color cyan "$comment_id")" >&2
							printf '    %s\n' "$(color dim "$err")" >&2
						fi
					fi
				fi
			done <"$tmp_comments"
		fi

		local issue_json issue_body new_issue_body payload err
		if ! issue_json="$(gh api -X GET "repos/${repo_name}/issues/${issue_number}" 2>/dev/null)"; then
			printf '%s\n' "$(color red "  Error: Failed to fetch issue body.")" >&2
			errors=$((errors + 1))
			printf '\n'
			continue
		fi

		issue_body="$(printf '%s' "$issue_json" | jq -r '.body // ""')"

		if [[ "$issue_body" == *"$OLD_USER"* ]]; then
			new_issue_body="${issue_body//$OLD_USER/$NEW_USER}"
			payload="$(jq -n --arg body "$new_issue_body" '{body: $body}')"

			if [ "$DRY_RUN" -eq 1 ]; then
				printf '%s\n' "$(color yellow "  • Would update issue body")"
			else
				err="$(patch_json "repos/${repo_name}/issues/${issue_number}" "$payload")" || true
				if [ "$err" = "" ]; then
					updated_issues=$((updated_issues + 1))
					printf '%s\n' "$(color green "  ✓ Updated issue body")"
				else
					errors=$((errors + 1))
					printf '%s\n' "$(color red "  ✗ Failed to update issue body")" >&2
					printf '    %s\n' "$(color dim "$err")" >&2
				fi
			fi
		fi

		printf '\n'
	done <"$tmp_issues"

	section "Summary"

	printf "Issues scanned   : %s\n" "$(color cyan "$scanned_issues")"
	printf "Issues updated   : %s\n" "$(color cyan "$updated_issues")"
	printf "Comments scanned : %s\n" "$(color cyan "$scanned_comments")"
	printf "Comments updated : %s\n" "$(color cyan "$updated_comments")"
	if [ "$errors" -gt 0 ]; then
		printf "Errors          : %s\n" "$(color red "$errors")"
		exit 1
	else
		printf "Errors          : %s\n" "$(color green "0")"
	fi
}

main "$@"
