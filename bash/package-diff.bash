#!/usr/bin/env bash
# package-diff.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# Compare two packages or archives (RPM, DEB, TAR). Returns 0 if identical,
# or 1 if they differ or if any error occurs.
#
# Features:
#   - Cross-format comparison (RPM vs TAR, DEB vs RPM, etc.)
#   - Checksum-based file comparison
#   - Detects content changes, whitespace-only changes, and binary changes
#   - Compares package scripts:
#       DEB: control/preinst/postinst/prerm/postrm
#       RPM: pretrans/prein/postin/preun/postun/posttrans/triggers
#   - Optional package metadata display (dependencies, provides, etc.)
#   - Colored side-by-side diff with icdiff (falls back to unified diff)
#
# Usage:
#   ./package-diff.bash --old <package1> --new <package2> [options]
#
# Examples:
#   ./package-diff.bash -o old.rpm -n new.rpm
#   ./package-diff.bash -o pkg.tar.gz -n pkg.deb
#   ./package-diff.bash -o v1.rpm -n v2.rpm -s

set -euo pipefail
umask 077

# Script info
SCRIPT_NAME=$(basename "$0")
readonly SCRIPT_NAME

# Runtime options
USE_COLOR=0
CONTEXT_LINES=3
CLEANUP_PATHS=()
DIFF_CMD=""
DIFF_FORCED=0
EXCLUDES=()

# Enable colors if stdout is a TTY and NO_COLOR is not set
init_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		USE_COLOR=1
	fi
}

# Print colored text: color <name> <string>
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

# Print a section header with bordered title
section() {
	local title="$1"
	local bar
	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '\n%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

# Print a subsection heading
subsection() {
	local title="$1"
	printf '\n%s\n' "$(color cyan "► $title")"
}

# Return success if command exists
have_cmd() {
	command -v "$1" &>/dev/null
}

# Get absolute path of a file/directory
abspath() {
	if have_cmd realpath; then
		realpath "$1"
	elif have_cmd readlink; then
		readlink -f "$1" 2>/dev/null || printf '%s\n' "$1"
	else
		printf '%s\n' "$1"
	fi
}

# Format bytes as human-readable size
human_size() {
	local size="$1"
	if have_cmd numfmt; then
		numfmt --to=iec "$size" 2>/dev/null || printf '%s bytes' "$size"
	else
		printf '%s bytes' "$size"
	fi
}

# Return file size in bytes (cross-platform)
file_size() {
	local file="$1"
	stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null
}

# Cleanup temporary files and directories on exit
cleanup() {
	local path
	for path in "${CLEANUP_PATHS[@]}"; do
		[ -e "$path" ] && rm -rf "$path"
	done
}
trap cleanup EXIT INT TERM

# Show usage information
usage() {
	cat >&2 <<-EOF
Usage: $SCRIPT_NAME [options] --old <package1> --new <package2>

Compare two packages or archives (RPM, DEB, TAR). Returns 0 if identical, or 1
if they differ or if any error occurs.

Options:
    -o, --old              Old package file (required)
    -n, --new              New package file to compare against (required)
    -c, --context          Number of context lines in diff output (default: 3)
    -d, --diff-tool        Force diff command: 'diff' or 'icdiff'
    -e, --exclude          Exclude files matching glob pattern from diffing
    -s, --summary          Hide metadata and per-file diffs
    -V, --verbose          Show per-file comparison progress and extra details
    -N, --no-color         Disable colored output
    -h, --help             Show this help message

Examples:
    $SCRIPT_NAME -o old-4.2-1.rpm -n new-4.3-2.rpm -e '*.css' -e '*.js'
    $SCRIPT_NAME -o old.tar.gz -n new.deb -V
    $SCRIPT_NAME -o old_8.0.6-1_all.deb -n new_8.0.7-1_all.deb -s -d diff
	EOF
	exit 1
}

# Detect package type from filename extension
detect_package_type() {
	local file="$1"
	local name
	name=$(basename "$file" | tr '[:upper:]' '[:lower:]')

	case "$name" in
		*.rpm)              printf 'rpm' ;;
		*.deb)              printf 'deb' ;;
		*.tar.gz|*.tgz)     printf 'tar.gz' ;;
		*.tar.bz2|*.tbz2)   printf 'tar.bz2' ;;
		*.tar.xz|*.txz)     printf 'tar.xz' ;;
		*.tar)              printf 'tar' ;;
		*)                  printf 'unknown' ;;
	esac
}

# Check required extraction tools for a package type
check_tools() {
	local pkg_type="$1"
	local missing=()

	case "$pkg_type" in
		rpm)
			have_cmd rpm2cpio || missing+=("rpm2cpio")
			have_cmd cpio     || missing+=("cpio")
			;;
		deb)
			# dpkg-deb preferred, ar+tar as fallback
			if ! have_cmd dpkg-deb; then
				have_cmd ar  || missing+=("ar (binutils)")
				have_cmd tar || missing+=("tar")
			fi
			;;
		tar|tar.gz|tar.bz2|tar.xz)
			have_cmd tar || missing+=("tar")
			;;
	esac

	if [ "${#missing[@]}" -gt 0 ]; then
		printf '%s\n' "$(color red "Error: Missing tools for $pkg_type: ${missing[*]}")" >&2
		return 1
	fi
	return 0
}

# Extract package contents to a directory
extract_package() {
	local pkg_file="$1"
	local dest_dir="$2"
	local pkg_type="$3"
	local verbose="${4:-0}"

	mkdir -p "$dest_dir"

	case "$pkg_type" in
		rpm)
			[ "$verbose" -eq 1 ] && printf "  Using rpm2cpio | cpio\n"
			(cd "$dest_dir" && rpm2cpio "$pkg_file" | cpio -idm --quiet 2>/dev/null)
			;;
		deb)
			if have_cmd dpkg-deb; then
				[ "$verbose" -eq 1 ] && printf "  Using dpkg-deb -x\n"
				dpkg-deb -x "$pkg_file" "$dest_dir"
			else
				[ "$verbose" -eq 1 ] && printf "  Using ar + tar\n"
				(
					cd "$dest_dir"
					ar x "$pkg_file" 2>/dev/null
					local data_archive
					data_archive=$(find . -maxdepth 1 -name 'data.tar*' -print -quit)
					if [ -n "$data_archive" ]; then
						tar -xf "$data_archive" 2>/dev/null
					fi
					rm -f ./control.tar* ./data.tar* ./debian-binary 2>/dev/null
				)
			fi
			;;
		tar.gz)
			[ "$verbose" -eq 1 ] && printf "  Using tar -xzf\n"
			tar -xzf "$pkg_file" -C "$dest_dir" 2>/dev/null
			;;
		tar.bz2)
			[ "$verbose" -eq 1 ] && printf "  Using tar -xjf\n"
			tar -xjf "$pkg_file" -C "$dest_dir" 2>/dev/null
			;;
		tar.xz)
			[ "$verbose" -eq 1 ] && printf "  Using tar -xJf\n"
			tar -xJf "$pkg_file" -C "$dest_dir" 2>/dev/null
			;;
		tar)
			[ "$verbose" -eq 1 ] && printf "  Using tar -xf\n"
			tar -xf "$pkg_file" -C "$dest_dir" 2>/dev/null
			;;
		*)
			printf '%s\n' "$(color red "Error: Unknown package type: $pkg_type")" >&2
			return 1
			;;
	esac
}

# Extract DEB control files (control, preinst, postinst, prerm, postrm, etc.)
extract_deb_scripts() {
	local pkg_file="$1"
	local dest_dir="$2"
	local verbose="${3:-0}"

	mkdir -p "$dest_dir"

	if have_cmd dpkg-deb; then
		[ "$verbose" -eq 1 ] && printf "  Extracting DEB control files with dpkg-deb --control\n"
		dpkg-deb --control "$pkg_file" "$dest_dir" 2>/dev/null || true
	else
		[ "$verbose" -eq 1 ] && printf "  Extracting DEB control files with ar + tar\n"
		local tmpdir
		tmpdir=$(mktemp -d)
		CLEANUP_PATHS+=("$tmpdir")
		(
			cd "$tmpdir"
			ar x "$pkg_file" 2>/dev/null
			local control_archive
			control_archive=$(find . -maxdepth 1 -name 'control.tar*' -print -quit)
			if [ -n "$control_archive" ]; then
				tar -xf "$control_archive" -C "$dest_dir" 2>/dev/null
			fi
		)
	fi

	return 0
}

# Extract RPM scriptlets (pretrans, pre, post, preun, postun, posttrans, triggers)
extract_rpm_scripts() {
	local pkg_file="$1"
	local dest_dir="$2"
	local verbose="${3:-0}"

	mkdir -p "$dest_dir"

	have_cmd rpm || return 0

	[ "$verbose" -eq 1 ] && printf "  Extracting RPM scriptlets with rpm -qp\n"

	# Define scriptlet types and their rpm query tags
	local -a script_types=(
		"pretrans:PRETRANS"
		"prein:PREIN"
		"postin:POSTIN"
		"preun:PREUN"
		"postun:POSTUN"
		"posttrans:POSTTRANS"
		"verifyscript:VERIFYSCRIPT"
	)

	local entry name tag content prog
	for entry in "${script_types[@]}"; do
		name="${entry%%:*}"
		tag="${entry##*:}"

		# Get script content
		content=$(rpm -qp --qf "%{$tag}\n" "$pkg_file" 2>/dev/null || true)

		# Skip if empty or "(none)"
		if [ -n "$content" ] && [ "$content" != "(none)" ]; then
			# Get interpreter if available
			prog=$(rpm -qp --qf "%{${tag}PROG}\n" "$pkg_file" 2>/dev/null || true)
			{
				if [ -n "$prog" ] && [ "$prog" != "(none)" ]; then
					printf '#!%s\n' "$prog"
				fi
				printf '%s\n' "$content"
			} > "$dest_dir/$name"
		fi
	done

	# Extract trigger scripts (more complex format)
	local triggers
	triggers=$(rpm -qp --triggers "$pkg_file" 2>/dev/null || true)
	if [ -n "$triggers" ] && [ "$triggers" != "(none)" ]; then
		printf '%s\n' "$triggers" > "$dest_dir/triggers"
	fi

	return 0
}

# List all regular files under directory as sorted relative paths
get_file_list() {
	local dir="$1"
	(cd "$dir" && find . -type f -print 2>/dev/null | sed 's|^\./||' | sort)
}

# Compute hash from stdin using best available hasher
hash_stream() {
	if have_cmd sha256sum; then
		sha256sum | awk '{print $1}'
	elif have_cmd shasum; then
		shasum -a 256 | awk '{print $1}'
	elif have_cmd md5sum; then
		md5sum | awk '{print $1}'
	elif have_cmd md5; then
		md5 -q
	else
		# Last resort: simple byte count
		awk '{s+=length($0)} END {print s+0}'
	fi
}

# Calculate checksum for a file
get_checksum() {
	local file="$1"
	[ -f "$file" ] || { printf '0'; return; }
	hash_stream < "$file"
}

# Heuristic: return 0 if file appears to be binary
is_binary() {
	local file="$1"
	[ -f "$file" ] || return 1

	# Use file command if available
	if have_cmd file; then
		local desc
		desc=$(file -b "$file" 2>/dev/null || true)

		# Clearly text
		if printf '%s' "$desc" | grep -qi 'text'; then
			return 1
		fi

		# Known binary types
		if printf '%s' "$desc" | grep -qiE \
			'ELF|Mach-O|PE32|MS-DOS|shared object|archive|image data|audio|video|compressed'; then
			return 0
		fi
	fi

	# Fallback: check for NUL bytes (binary indicator)
	if LC_ALL=C grep -q $'\x00' "$file" 2>/dev/null; then
		return 0
	fi

	return 1
}

# Check if two files differ only in whitespace
is_whitespace_only_change() {
	local file1="$1" file2="$2"

	[ -f "$file1" ] && [ -f "$file2" ] || return 1

	local norm1 norm2
	norm1=$(tr -d '[:space:]' < "$file1" | hash_stream)
	norm2=$(tr -d '[:space:]' < "$file2" | hash_stream)

	[ "$norm1" = "$norm2" ]
}

# Check if a file is excluded from diffs
is_excluded_file() {
	local file="$1" pat
	for pat in "${EXCLUDES[@]}"; do
		case "$file" in
			$pat) return 0 ;;
		esac
	done
	return 1
}

# Select diff tool: respect forced choice or auto-detect (prefer icdiff)
select_diff_cmd() {
	if [ "$DIFF_FORCED" -eq 1 ]; then
		if ! have_cmd "$DIFF_CMD"; then
			printf '%s\n' "$(color red "Error: Requested diff '$DIFF_CMD' not found")" >&2
			exit 1
		fi
		return
	fi

	if have_cmd icdiff; then
		DIFF_CMD="icdiff"
	elif have_cmd diff; then
		DIFF_CMD="diff"
	else
		DIFF_CMD=""
	fi
}

# Display diff for a single file using selected diff tool
show_file_diff() {
	local origin_dir="$1" target_dir="$2" file="$3"

	printf '\n%s\n' "$(color bold "━━━ $file ━━━")"
	printf '%s\n' "$(color dim "--- origin: $file")"
	printf '%s\n' "$(color dim "+++ target: $file")"
	printf '\n'

	if [ "$DIFF_CMD" = "icdiff" ]; then
		local cols_opt=()
		if have_cmd tput; then
			local cols
			cols=$(tput cols 2>/dev/null || echo 80)
			[ "$cols" -gt 0 ] && cols_opt=(--cols="$cols")
		fi
		icdiff --no-headers --line-numbers "${cols_opt[@]}" \
			"$origin_dir/$file" "$target_dir/$file" 2>/dev/null || true
	else
		# Unified diff with colored output
		diff -u -U "$CONTEXT_LINES" "$origin_dir/$file" "$target_dir/$file" 2>/dev/null | \
			tail -n +3 | while IFS= read -r line; do
				case "$line" in
					@@*)  printf '%s\n' "$(color cyan "$line")" ;;
					-*)   printf '%s\n' "$(color red "$line")" ;;
					+*)   printf '%s\n' "$(color green "$line")" ;;
					*)    printf '%s\n' "$line" ;;
				esac
			done || true
	fi
}

# Show DEB package metadata
show_deb_metadata() {
	local file="$1"
	local info=""

	if have_cmd dpkg-deb; then
		info=$(dpkg-deb -I "$file" 2>/dev/null || true)
	elif have_cmd dpkg; then
		info=$(dpkg -I "$file" 2>/dev/null || true)
	fi

	[ -z "$info" ] && return 0

	printf '  Metadata:\n'
	printf '%s\n' "$info" | while IFS= read -r line; do
		printf '%s\n' "$(color dim "    $line")"
	done

	return 0
}

# Show RPM package metadata including dependencies
show_rpm_metadata() {
	local file="$1"

	have_cmd rpm || return 0

	local info reqs prov obs conf
	info=$(rpm -qip "$file" 2>/dev/null || rpm -qp --info "$file" 2>/dev/null || true)
	reqs=$(rpm -qpR "$file" 2>/dev/null || true)
	prov=$(rpm -qp --provides "$file" 2>/dev/null || true)
	obs=$(rpm -qp --obsoletes "$file" 2>/dev/null || true)
	conf=$(rpm -qp --conflicts "$file" 2>/dev/null || true)

	[ -z "$info$reqs$prov$obs$conf" ] && return 0

	printf '  Metadata:\n'

	if [ -n "$info" ]; then
		printf '%s\n' "$info" | while IFS= read -r line; do
			printf '%s\n' "$(color dim "    $line")"
		done
	fi

	if [ -n "$reqs" ]; then
		printf '%s\n' "$(color dim "    Requires:")"
		printf '%s\n' "$reqs" | while IFS= read -r line; do
			printf '%s\n' "$(color dim "      $line")"
		done
	fi

	if [ -n "$prov" ]; then
		printf '%s\n' "$(color dim "    Provides:")"
		printf '%s\n' "$prov" | while IFS= read -r line; do
			printf '%s\n' "$(color dim "      $line")"
		done
	fi

	if [ -n "$obs" ]; then
		printf '%s\n' "$(color dim "    Obsoletes:")"
		printf '%s\n' "$obs" | while IFS= read -r line; do
			printf '%s\n' "$(color dim "      $line")"
		done
	fi

	if [ -n "$conf" ]; then
		printf '%s\n' "$(color dim "    Conflicts:")"
		printf '%s\n' "$conf" | while IFS= read -r line; do
			printf '%s\n' "$(color dim "      $line")"
		done
	fi

	return 0
}

# Display package info block with metadata
show_package_info() {
	local label="$1" file="$2" pkg_type="$3" size="$4" summary="$5"

	printf "%-14s %s\n" "$label:"    "$(color cyan "$(basename "$file")")"
	printf "%-14s %s\n" "  Type:"    "$(color dim "$pkg_type")"
	printf "%-14s %s\n" "  Size:"    "$(color dim "$(human_size "$size")")"
	printf "%-14s %s\n" "  Path:"    "$(color dim "$file")"

	# Show metadata unless summary mode
	if [ "$summary" -eq 0 ]; then
		case "$pkg_type" in
			deb) show_deb_metadata "$file" ;;
			rpm) show_rpm_metadata "$file" ;;
		esac
	fi
}

# Compare package scripts/maintainer files between two packages
# Returns: sets global arrays for script comparison results
compare_package_scripts() {
	local origin_file="$1" origin_type="$2"
	local target_file="$3" target_type="$4"
	local verbose="$5"

	# Reset global arrays for results
	SCRIPT_IDENTICAL=()
	SCRIPT_CHANGED=()
	SCRIPT_ADDED=()
	SCRIPT_REMOVED=()

	local origin_scripts_dir target_scripts_dir
	origin_scripts_dir=$(mktemp -d)
	target_scripts_dir=$(mktemp -d)
	CLEANUP_PATHS+=("$origin_scripts_dir" "$target_scripts_dir")

	# Store for use in diff display
	ORIGIN_SCRIPTS_DIR="$origin_scripts_dir"
	TARGET_SCRIPTS_DIR="$target_scripts_dir"

	# Extract scripts based on package type
	printf "Extracting old package scripts...\n"
	case "$origin_type" in
		deb) extract_deb_scripts "$origin_file" "$origin_scripts_dir" "$verbose" ;;
		rpm) extract_rpm_scripts "$origin_file" "$origin_scripts_dir" "$verbose" ;;
	esac
	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Done")"

	printf "Extracting new package scripts...\n"
	case "$target_type" in
		deb) extract_deb_scripts "$target_file" "$target_scripts_dir" "$verbose" ;;
		rpm) extract_rpm_scripts "$target_file" "$target_scripts_dir" "$verbose" ;;
	esac
	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Done")"

	# Get script file lists
	local origin_list target_list
	origin_list=$(mktemp)
	target_list=$(mktemp)
	CLEANUP_PATHS+=("$origin_list" "$target_list")

	(cd "$origin_scripts_dir" && find . -type f -print 2>/dev/null | sed 's|^\./||' | sort) > "$origin_list"
	(cd "$target_scripts_dir" && find . -type f -print 2>/dev/null | sed 's|^\./||' | sort) > "$target_list"

	# Find common, added, removed
	local common_list added_list removed_list
	common_list=$(mktemp)
	added_list=$(mktemp)
	removed_list=$(mktemp)
	CLEANUP_PATHS+=("$common_list" "$added_list" "$removed_list")

	comm -12 "$origin_list" "$target_list" > "$common_list"
	comm -13 "$origin_list" "$target_list" > "$added_list"
	comm -23 "$origin_list" "$target_list" > "$removed_list"

	# Populate added/removed arrays
	while IFS= read -r file; do
		[ -n "$file" ] && SCRIPT_ADDED+=("$file")
	done < "$added_list"

	while IFS= read -r file; do
		[ -n "$file" ] && SCRIPT_REMOVED+=("$file")
	done < "$removed_list"

	# Compare common scripts
	printf "Comparing scripts...\n"
	local file origin_sum target_sum
	while IFS= read -r file; do
		[ -z "$file" ] && continue

		origin_sum=$(get_checksum "$origin_scripts_dir/$file")
		target_sum=$(get_checksum "$target_scripts_dir/$file")

		if [ "$origin_sum" = "$target_sum" ]; then
			SCRIPT_IDENTICAL+=("$file")
		else
			SCRIPT_CHANGED+=("$file")
		fi
	done < "$common_list"

	local script_total=$((${#SCRIPT_IDENTICAL[@]} + ${#SCRIPT_CHANGED[@]}))
	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Compared $script_total scripts")"

	return 0
}

# Main comparison logic
do_compare() {
	local origin_file="$1" target_file="$2" summary="$3" verbose="$4"

	local origin_type target_type origin_size target_size
	local origin_dir target_dir

	# Detect package types
	section "Package Information"

	origin_type=$(detect_package_type "$origin_file")
	target_type=$(detect_package_type "$target_file")

	if [ "$origin_type" = "unknown" ]; then
		printf '%s\n' "$(color red "Error: Unknown format: $origin_file")" >&2
		exit 1
	fi
	if [ "$target_type" = "unknown" ]; then
		printf '%s\n' "$(color red "Error: Unknown format: $target_file")" >&2
		exit 1
	fi

	origin_size=$(file_size "$origin_file")
	target_size=$(file_size "$target_file")

	printf '\n'
	show_package_info "Old file" "$origin_file" "$origin_type" "$origin_size" "$summary"
	printf '\n'
	show_package_info "New file" "$target_file" "$target_type" "$target_size" "$summary"

	# Check prerequisites
	section "Checking Prerequisites"
	printf '\n'

	local tools_ok=1

	printf "%-30s " "Tools for $origin_type:"
	if check_tools "$origin_type"; then
		printf '%s\n' "$(color green "✓")"
	else
		printf '%s\n' "$(color red "✗")"
		tools_ok=0
	fi

	if [ "$target_type" != "$origin_type" ]; then
		printf "%-30s " "Tools for $target_type:"
		if check_tools "$target_type"; then
			printf '%s\n' "$(color green "✓")"
		else
			printf '%s\n' "$(color red "✗")"
			tools_ok=0
		fi
	fi

	select_diff_cmd
	if [ -n "$DIFF_CMD" ]; then
		local diff_note="" diff_label
		if [ "$DIFF_CMD" = "diff" ] && [ "$DIFF_FORCED" -eq 0 ]; then
			diff_note=" (install icdiff for side-by-side diffs)"
		fi
		diff_label=$(printf 'Diff tool [%s]:' "$DIFF_CMD")
		printf "%-30s %s%s\n" "$diff_label" "$(color green "✓")" "$(color dim "$diff_note")"
	else
		printf '%-30s %s\n' "Diff tool:" "$(color red "✗ missing (need diff or icdiff)")"
		tools_ok=0
	fi

	[ "$tools_ok" -eq 0 ] && { printf '\n%s\n' "$(color red "Error: Missing required tools")" >&2; exit 1; }

	# Extract packages
	section "Extracting Packages"
	printf '\n'

	origin_dir=$(mktemp -d)
	target_dir=$(mktemp -d)
	CLEANUP_PATHS+=("$origin_dir" "$target_dir")

	printf "Extracting old package...\n"
	if ! extract_package "$(abspath "$origin_file")" "$origin_dir" "$origin_type" "$verbose"; then
		printf '%s\n' "$(color red "Error: Failed to extract old package")" >&2
		exit 1
	fi
	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Extracted to temp directory")"

	printf "Extracting new package...\n"
	if ! extract_package "$(abspath "$target_file")" "$target_dir" "$target_type" "$verbose"; then
		printf '%s\n' "$(color red "Error: Failed to extract new package")" >&2
		exit 1
	fi
	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Extracted to temp directory")"

	# Analyze file lists
	section "Analyzing Contents"
	printf '\n'

	local origin_files target_files common_files added_files removed_files
	origin_files=$(mktemp)
	target_files=$(mktemp)
	common_files=$(mktemp)
	added_files=$(mktemp)
	removed_files=$(mktemp)
	CLEANUP_PATHS+=("$origin_files" "$target_files" "$common_files" "$added_files" "$removed_files")

	get_file_list "$origin_dir" > "$origin_files"
	get_file_list "$target_dir" > "$target_files"

	local origin_count target_count
	origin_count=$(wc -l < "$origin_files" | tr -d ' ')
	target_count=$(wc -l < "$target_files" | tr -d ' ')

	printf "Files in old: %s\n" "$(color cyan "$origin_count")"
	printf "Files in new: %s\n" "$(color cyan "$target_count")"

	comm -12 "$origin_files" "$target_files" > "$common_files"
	comm -13 "$origin_files" "$target_files" > "$added_files"
	comm -23 "$origin_files" "$target_files" > "$removed_files"

	local common_count added_count removed_count
	common_count=$(wc -l < "$common_files" | tr -d ' ')
	added_count=$(wc -l < "$added_files" | tr -d ' ')
	removed_count=$(wc -l < "$removed_files" | tr -d ' ')

	printf '\n'
	printf "Common files:  %s\n" "$(color cyan "$common_count")"
	printf "Added files:   %s\n" "$(color green "$added_count")"
	printf "Removed files: %s\n" "$(color red "$removed_count")"

	# Track total size added/removed
	local added_bytes=0
	local removed_bytes=0

	# Show added/removed files with sizes
	if [ "$added_count" -gt 0 ]; then
		subsection "Files added in new package ($added_count)"
		while IFS= read -r file; do
			[ -z "$file" ] && continue
			local sz
			sz=$(file_size "$target_dir/$file")
			added_bytes=$((added_bytes + sz))
			printf "  %s %s [%s]\n" \
				"$(color green "+")" \
				"$(color dim "$file")" \
				"$(color dim "$(human_size "$sz")")"
		done < "$added_files"
	fi

	if [ "$removed_count" -gt 0 ]; then
		subsection "Files removed from new package ($removed_count)"
		while IFS= read -r file; do
			[ -z "$file" ] && continue
			local sz
			sz=$(file_size "$origin_dir/$file")
			removed_bytes=$((removed_bytes + sz))
			printf "  %s %s [%s]\n" \
				"$(color red "-")" \
				"$(color dim "$file")" \
				"$(color dim "$(human_size "$sz")")"
		done < "$removed_files"
	fi

	# Compare common files
	section "Comparing Common Files"
	printf '\n'
	printf "Computing checksums and comparing...\n\n"

	local -a identical_files=()
	local -a changed_files=()
	local -a whitespace_only_files=()
	local -a binary_changed_files=()
	local total_compared=0

	while IFS= read -r file; do
		[ -z "$file" ] && continue
		((++total_compared))

		local origin_path="$origin_dir/$file"
		local target_path="$target_dir/$file"
		local origin_sum target_sum

		origin_sum=$(get_checksum "$origin_path")
		target_sum=$(get_checksum "$target_path")

		if [ "$origin_sum" = "$target_sum" ]; then
			identical_files+=("$file")
			[ "$verbose" -eq 1 ] && printf "  %s %s\n" "$(color green "=")" "$(color dim "$file")"
		elif is_binary "$origin_path" || is_binary "$target_path"; then
			binary_changed_files+=("$file")
			[ "$verbose" -eq 1 ] && printf "  %s %s %s\n" "$(color magenta "B")" "$(color cyan "$file")" "$(color dim "(binary)")"
		elif is_whitespace_only_change "$origin_path" "$target_path"; then
			whitespace_only_files+=("$file")
			[ "$verbose" -eq 1 ] && printf "  %s %s %s\n" "$(color yellow "W")" "$(color cyan "$file")" "$(color dim "(whitespace)")"
		else
			changed_files+=("$file")
			[ "$verbose" -eq 1 ] && printf "  %s %s\n" "$(color red "≠")" "$(color cyan "$file")"
		fi
	done < "$common_files"

	printf "  %s %s\n" "$(color green "✓")" "$(color dim "Compared $total_compared files")"

	# Summary
	section "Comparison Summary"
	printf '\n'

	local identical_count=${#identical_files[@]}
	local changed_count=${#changed_files[@]}
	local whitespace_count=${#whitespace_only_files[@]}
	local binary_count=${#binary_changed_files[@]}

	printf "%-28s %s\n" "Total files compared:"    "$(color dim "$total_compared")"
	printf "%-28s %s\n" "Identical files:"         "$(color dim "$identical_count")"
	printf "%-28s %s\n" "Content changes:"         "$(color dim "$changed_count")"
	printf "%-28s %s\n" "Whitespace-only changes:" "$(color dim "$whitespace_count")"
	printf "%-28s %s\n" "Binary file changes:"     "$(color dim "$binary_count")"
	printf "%-28s %s\n" "Files added:"             "$(color dim "$added_count")"
	printf "%-28s %s\n" "Files removed:"           "$(color dim "$removed_count")"
	printf "%-28s %s\n" "Size added:"              "$(color dim "$(human_size "$added_bytes")")"
	printf "%-28s %s\n" "Size removed:"            "$(color dim "$(human_size "$removed_bytes")")"

	if [ "$total_compared" -gt 0 ]; then
		local pct_identical pct_changed
		pct_identical=$((identical_count * 100 / total_compared))
		pct_changed=$(((changed_count + whitespace_count + binary_count) * 100 / total_compared))
		printf '\n'
		printf "Similarity: %s%% identical, %s%% changed\n" \
			"$(color green "$pct_identical")" "$(color yellow "$pct_changed")"
	fi

	# List changed files by category
	if [ "$changed_count" -gt 0 ]; then
		subsection "Files with content changes ($changed_count)"
		for file in "${changed_files[@]}"; do
			printf "  %s %s\n" "$(color red "•")" "$file"
		done
	fi

	if [ "$whitespace_count" -gt 0 ]; then
		subsection "Files with whitespace-only changes ($whitespace_count)"
		for file in "${whitespace_only_files[@]}"; do
			printf "  %s %s\n" "$(color yellow "•")" "$file"
		done
	fi

	if [ "$binary_count" -gt 0 ]; then
		subsection "Binary files changed ($binary_count)"
		for file in "${binary_changed_files[@]}"; do
			printf "  %s %s\n" "$(color magenta "•")" "$file"
		done
	fi

	# Show detailed diffs (respect excludes)
	local -a excluded_diff_files=()

	if [ "$summary" -eq 0 ] && [ "$changed_count" -gt 0 ]; then
		section "Detailed Diffs"
		for file in "${changed_files[@]}"; do
			if is_excluded_file "$file"; then
				excluded_diff_files+=("$file")
				continue
			fi
			show_file_diff "$origin_dir" "$target_dir" "$file"
		done
	fi

	# Show whitespace diffs in verbose mode (respect excludes)
	if [ "$verbose" -eq 1 ] && [ "$summary" -eq 0 ] && [ "$whitespace_count" -gt 0 ]; then
		section "Whitespace Diffs"
		for file in "${whitespace_only_files[@]}"; do
			if is_excluded_file "$file"; then
				excluded_diff_files+=("$file")
				continue
			fi
			show_file_diff "$origin_dir" "$target_dir" "$file"
		done
	fi

	# List files whose diffs were skipped by exclude patterns
	if [ "${#excluded_diff_files[@]}" -gt 0 ]; then
		subsection "Files with changes (diff skipped by exclude patterns: ${#excluded_diff_files[@]})"
		for file in "${excluded_diff_files[@]}"; do
			printf "  %s %s\n" "$(color yellow "•")" "$(color dim "$file")"
		done
	fi

	# Compare package scripts (DEB control files, RPM scriptlets)
	local scripts_total_changes=0
	if [ "$origin_type" = "deb" ] || [ "$origin_type" = "rpm" ] || \
	   [ "$target_type" = "deb" ] || [ "$target_type" = "rpm" ]; then

		section "Package Scripts"
		printf '\n'

		# Global arrays set by compare_package_scripts
		SCRIPT_IDENTICAL=()
		SCRIPT_CHANGED=()
		SCRIPT_ADDED=()
		SCRIPT_REMOVED=()
		ORIGIN_SCRIPTS_DIR=""
		TARGET_SCRIPTS_DIR=""

		compare_package_scripts "$origin_file" "$origin_type" "$target_file" "$target_type" "$verbose"

		local script_identical_count=${#SCRIPT_IDENTICAL[@]}
		local script_changed_count=${#SCRIPT_CHANGED[@]}
		local script_added_count=${#SCRIPT_ADDED[@]}
		local script_removed_count=${#SCRIPT_REMOVED[@]}
		local script_total=$((script_identical_count + script_changed_count))

		printf '\n'
		printf "%-28s %s\n" "Total scripts compared:"  "$(color dim "$script_total")"
		printf "%-28s %s\n" "Identical scripts:"       "$(color green "$script_identical_count")"
		printf "%-28s %s\n" "Changed scripts:"         "$(color red "$script_changed_count")"
		printf "%-28s %s\n" "Scripts added:"           "$(color green "$script_added_count")"
		printf "%-28s %s\n" "Scripts removed:"         "$(color red "$script_removed_count")"

		# List script changes
		if [ "$script_added_count" -gt 0 ]; then
			subsection "Scripts added in new package ($script_added_count)"
			for file in "${SCRIPT_ADDED[@]}"; do
				printf "  %s %s\n" "$(color green "+")" "$file"
			done
		fi

		if [ "$script_removed_count" -gt 0 ]; then
			subsection "Scripts removed from old package ($script_removed_count)"
			for file in "${SCRIPT_REMOVED[@]}"; do
				printf "  %s %s\n" "$(color red "-")" "$file"
			done
		fi

		if [ "$script_changed_count" -gt 0 ]; then
			subsection "Scripts with changes ($script_changed_count)"
			for file in "${SCRIPT_CHANGED[@]}"; do
				printf "  %s %s\n" "$(color red "•")" "$file"
			done
		fi

		# Show script diffs
		if [ "$summary" -eq 0 ] && [ "$script_changed_count" -gt 0 ]; then
			subsection "Script Diffs"
			for file in "${SCRIPT_CHANGED[@]}"; do
				show_file_diff "$ORIGIN_SCRIPTS_DIR" "$TARGET_SCRIPTS_DIR" "$file"
			done
		fi

		# Show content of added scripts to see what's new
		if [ "$verbose" -eq 1 ] && [ "$summary" -eq 0 ] && [ "$script_added_count" -gt 0 ]; then
			subsection "New Script Contents"
			for file in "${SCRIPT_ADDED[@]}"; do
				printf '\n%s\n' "$(color bold "━━━ $file (added) ━━━")"
				printf '\n'
				while IFS= read -r line; do
					printf '%s\n' "$(color green "+ $line")"
				done < "$TARGET_SCRIPTS_DIR/$file"
			done
		fi

		scripts_total_changes=$((script_changed_count + script_added_count + script_removed_count))
	fi

	# Final result
	section "Result"
	printf '\n'

	local total_changes=$((changed_count + whitespace_count + binary_count + added_count + removed_count + scripts_total_changes))

	if [ "$total_changes" -eq 0 ]; then
		printf '%s\n' "$(color green "✓ Packages are identical")"
	else
		local word="change"
		[ "$total_changes" -ne 1 ] && word="changes"
		printf '%s\n' "$(color yellow "⚠ Packages differ: $total_changes total $word")"
		if [ "$scripts_total_changes" -gt 0 ]; then
			printf '%s\n' "$(color dim "  (including changes to package scripts: $scripts_total_changes)")"
		fi
	fi

	printf '\n%s\n' "$(color dim "Completed at $(date '+%Y-%m-%d %H:%M:%S')")"

	[ "$total_changes" -eq 0 ]
}

# Main entry point
main() {
	local origin_file="" target_file=""
	local summary=0 verbose=0

	init_color

	while [ "$#" -gt 0 ]; do
		case "$1" in
			-o|--old)
				[ -z "${2:-}" ] && usage
				origin_file="$2"
				shift 2
				;;
			-n|--new)
				[ -z "${2:-}" ] && usage
				target_file="$2"
				shift 2
				;;
			-c|--context)
				[ -z "${2:-}" ] && usage
				CONTEXT_LINES="$2"
				shift 2
				;;
			-d|--diff-tool)
				[ -z "${2:-}" ] && usage
				case "$2" in
					icdiff|diff)
						DIFF_CMD="$2"
						DIFF_FORCED=1
						;;
					*)
						printf '%s\n' "$(color red "Error: Invalid diff command: $2 (use 'diff' or 'icdiff')")" >&2
						exit 1
						;;
				esac
				shift 2
				;;
			-e|--exclude)
				[ -z "${2:-}" ] && usage
				EXCLUDES+=("$2")
				shift 2
				;;
			-s|--summary)
				summary=1
				shift
				;;
			-V|--verbose)
				verbose=1
				shift
				;;
			-N|--no-color)
				USE_COLOR=0
				shift
				;;
			-h|--help)
				usage
				;;
			*)
				printf '%s\n\n' "$(color red "Unknown option: $1")" >&2
				usage
				;;
		esac
	done

	# Validate required arguments
	if [ -z "$origin_file" ]; then
		printf '%s\n\n' "$(color red "Error: Old package is required (-o)")" >&2
		usage
	fi
	if [ -z "$target_file" ]; then
		printf '%s\n\n' "$(color red "Error: New package is required (-n)")" >&2
		usage
	fi

	# Validate files exist
	if [ ! -f "$origin_file" ]; then
		printf '%s\n' "$(color red "Error: Old file not found: $origin_file")" >&2
		exit 1
	fi
	if [ ! -f "$target_file" ]; then
		printf '%s\n' "$(color red "Error: New file not found: $target_file")" >&2
		exit 1
	fi

	do_compare "$origin_file" "$target_file" "$summary" "$verbose"
}

main "$@"
