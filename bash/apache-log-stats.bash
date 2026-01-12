#!/usr/bin/env bash
# apache-log-stats.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script parses Apache access and error logs to extract useful statistics.
#
# Description:
# Streaming parser for Apache access and error logs. Extracts top IPs, URLs,
# status codes, methods, 404s, 5xx errors, busiest hours, bandwidth stats.
# Error logs show levels, modules, client IPs, AH codes, and recent critical
# errors. Supports rotated .gz/.tar.gz files. Optional GeoIP and progress meter.
#
# Usage:
#   ./apache-log-stats.bash -i <log-file> [options]
#   ./apache-log-stats.bash -i <log-file> [-i <log-file> ...] [options]
#   ./apache-log-stats.bash -i <log-file> -R [n]
#   ./apache-log-stats.bash -i <log-file> --full --progress
#
# Examples:
#   # Parse access log (auto-detected)
#   ./apache-log-stats.bash -i /var/log/apache2/access.log
#   ./apache-log-stats.bash -i site1_access_log -i site2_access_log
#
#   # Parse with all rotated logs included
#   ./apache-log-stats.bash -i /var/log/virtualmin/site_access_log -R
#
#   # Include only newest 3 rotated logs
#   ./apache-log-stats.bash -i /var/log/virtualmin/site_access_log -R 3
#
#   # Full mode with progress meter
#   ./apache-log-stats.bash -i /var/log/apache2/access.log --full --progress
#
#   # Parse error log explicitly
#   ./apache-log-stats.bash -i /var/log/apache2/error.log -t error
#
#   # Strip query strings and show top 50
#   ./apache-log-stats.bash -i /var/log/apache2/access.log --strip-query -n 50
#
#   # Disable GeoIP and colors (for scripting)
#   ./apache-log-stats.bash -i /var/log/apache2/access.log --no-geoip --no-color
#
# Exit codes:
#   0  success
#   1  error (usage, missing deps, file not found)
#   2  no lines parsed (empty log stream)

set -euo pipefail
umask 077
shopt -s nullglob

# Color output on/off toggle set by init_color
USE_COLOR=0

# Enable colors only when stdout is a TTY and NO_COLOR is not set
init_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		USE_COLOR=1
	fi
}

# Print a string in a given color or plain if colors are off
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

# Print a boxed section header
section() {
	local title="$1"
	local bar

	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

# Print a simple subsection header
subsection() {
	local title="$1"

	printf '\n%s\n' "$(color yellow "$title")"
	printf '%s\n' \
		"$(color gray "$(printf '%*s' ${#title} '' | tr ' ' '-')")"
}

# Right-pad to a fixed width, then apply color (keeps columns aligned)
pad_color() {
	local width="$1" col="$2" s="$3"
	local padded

	padded=$(printf "%*s" "$width" "$s")
	color "$col" "$padded"
}

# Left-pad to a fixed width, then apply color (keeps columns aligned)
pad_color_left() {
	local width="$1" col="$2" s="$3"
	local padded

	padded=$(printf "%-*s" "$width" "$s")
	color "$col" "$padded"
}

# Require a command to exist, else exit with a message
need_cmd() {
	local c="$1"

	if ! command -v "$c" &>/dev/null; then
		printf '%s\n' "$(color red "Error: missing command: $c")" >&2
		exit 1
	fi
}

# Return success if a command exists
have_cmd() {
	command -v "$1" &>/dev/null
}

# Detect GNU stat vs BSD stat (different flags)
is_gnu_stat() {
	stat --version &>/dev/null
}

# Get file size in bytes, portable across GNU/BSD stat
file_size() {
	local file="$1"

	if is_gnu_stat; then
		stat -c%s "$file" 2>/dev/null
	else
		stat -f%z "$file" 2>/dev/null
	fi
}

# Get file mtime as a readable timestamp, portable across GNU/BSD stat
file_mtime() {
	local file="$1"

	if is_gnu_stat; then
		stat -c "%y" "$file" 2>/dev/null | cut -d'.' -f1
	else
		stat -f "%Sm" -t "%Y-%m-%d %H:%M:%S" "$file" 2>/dev/null
	fi
}

# Get file mtime as epoch seconds (used for sorting rotated logs)
file_mtime_epoch() {
	local file="$1"

	if is_gnu_stat; then
		stat -c "%Y" "$file" 2>/dev/null || printf '0'
	else
		stat -f "%m" "$file" 2>/dev/null || printf '0'
	fi
}

# Human-readable size for file sizes (prefers numfmt)
human_bytes() {
	local n="$1"

	if have_cmd numfmt; then
		numfmt --to=si --format="%.1f" "$n" 2>/dev/null \
			| sed 's/\.0\([a-zA-Z]\)/\1/'
		return
	fi

	printf '%s' "$n"
}

# Human-readable count (prefers numfmt)
human_count() {
	local n="$1"

	if have_cmd numfmt; then
		numfmt --to=si --format="%.1f" "$n" 2>/dev/null \
			| sed 's/\.0\([a-zA-Z]\)/\1/' \
			| tr 'K' 'k'
		return
	fi

	if [ "$n" -lt 1000 ]; then
		printf '%s' "$n"
	elif [ "$n" -lt 1000000 ]; then
		printf '%sk' $(( (n + 500) / 1000 ))
	elif [ "$n" -lt 1000000000 ]; then
		printf '%sM' $(( (n + 500000) / 1000000 ))
	else
		printf '%sG' $(( (n + 500000000) / 1000000000 ))
	fi
}

# Remove a temporary directory (used with trap)
cleanup_tmp() {
	local d="$1"

	[ -n "$d" ] && [ -d "$d" ] && rm -rf "$d"
}

# Print help and exit
usage() {
	cat >&2 <<-EOF
	Usage: $(basename "$0") -i <log-file> [-i <log-file> ...] [options]

	Options:
	  -i, --input          Log file to parse (repeatable; preserves order)
	  -t, --type           access | error | auto (default: auto)
	  -n, --number         Number of rows to show (default: 25)

	  -R, --rotated [n]    Include rotated siblings per input:

	      --strip-query    Drop query from URLs
	      --full           Show heavy tables (URL-as-is, UA, referrer)
	      --progress       Progress meter to stderr (slower)
	      --no-geoip       Disable GeoIP output
	      --no-color       Disable colors
	  -h, --help           Show help

	Exit codes:
	  0 success
	  2 no lines parsed
	  1 error
	EOF
	exit 1
}

# Guess log type from filename
guess_type_from_name() {
	local f="$1"

	case "$f" in
		*_access_log*|*access.log*|*access_log*) printf 'access' ;;
		*_error_log*|*error.log*|*error_log*)   printf 'error' ;;
		*) printf '' ;;
	esac
}

# Guess log type by sniffing the first line (works for plain/gz/tar.gz)
guess_type_from_content() {
	local f="$1"
	local line=""

	if [[ "$f" =~ \.tar\.gz$|\.tgz$ ]]; then
		line=$(tar -xOzf "$f" 2>/dev/null | head -n1 || true)
	elif [[ "$f" =~ \.gz$ ]]; then
		line=$(gzip -cd "$f" 2>/dev/null | head -n1 || true)
	else
		line=$(head -n1 "$f" 2>/dev/null || true)
	fi

	if [[ "$line" == *\"GET\ *HTTP/*\"* ]] \
		|| [[ "$line" == *\"POST\ *HTTP/*\"* ]] \
		|| [[ "$line" == *\"HEAD\ *HTTP/*\"* ]]; then
		printf 'access'
		return
	fi

	if [[ "$line" == \[*\]\ \[*\]* ]]; then
		printf 'error'
		return
	fi

	printf ''
}

# Collect a main log plus rotated siblings, newest-first selection by mtime.
collect_files_for_input() {
	local input="$1"
	local rotated_depth="$2"
	local files=()

	files+=("$input")

	if [ "$rotated_depth" -eq 0 ]; then
		printf '%s\n' "${files[@]}"
		return
	fi

	local dir base f
	dir=$(dirname "$input")
	base=$(basename "$input")

	local -a rotated=()
	for f in "$dir/$base"-*.gz "$dir/$base"-*.tar.gz "$dir/$base"-*.tgz; do
		[ -e "$f" ] && rotated+=("$f")
	done

	if [ "${#rotated[@]}" -eq 0 ]; then
		printf '%s\n' "${files[@]}"
		return
	fi

	if [ "$rotated_depth" -eq -1 ]; then
		while IFS= read -r f; do
			files+=("$f")
		done < <(
			for f in "${rotated[@]}"; do
				printf '%s\t%s\n' \
					"$(file_mtime_epoch "$f")" "$f"
			done | sort -rn | awk -F'\t' '{print $2}'
		)
	else
		while IFS= read -r f; do
			files+=("$f")
		done < <(
			for f in "${rotated[@]}"; do
				printf '%s\t%s\n' \
					"$(file_mtime_epoch "$f")" "$f"
			done | sort -rn | head -n "$rotated_depth" \
				| awk -F'\t' '{print $2}'
		)
	fi

	printf '%s\n' "${files[@]}"
}

# Stream a file to stdout (plain/gz/tar.gz), without writing temp files; uses
# pigz if available for faster multi-core gzip decompression
stream_file() {
	local f="$1"

	if [[ "$f" =~ \.tar\.gz$|\.tgz$ ]]; then
		if have_cmd pigz; then
			tar --use-compress-program=pigz -xOf "$f" \
				2>/dev/null || true
		else
			tar -xOzf "$f" 2>/dev/null || true
		fi
		return
	fi

	if [[ "$f" =~ \.gz$ ]]; then
		if have_cmd pigz; then
			pigz -dc "$f" 2>/dev/null || true
		else
			gzip -cd "$f" 2>/dev/null || true
		fi
		return
	fi

	cat "$f" 2>/dev/null || true
}

# Print input files with sizes and mtimes, plus a total on-disk size
print_file_list() {
	local -a files=("$@")
	local total_disk=0
	local f sz

	section "Input files"
	for f in "${files[@]}"; do
		if [ -f "$f" ]; then
			sz=$(file_size "$f" || printf '0')
			total_disk=$(( total_disk + sz ))
			printf "  %s  %s  %s\n" \
				"$(pad_color 8 cyan "$(human_bytes "$sz")")" \
				"$(color dim "$(file_mtime "$f")")" \
				"$(color dim "$(basename "$f")")"
		else
			printf "  %s  %s\n" \
				"$(color yellow "(missing)")" \
				"$(color dim "$(basename "$f")")"
		fi
	done

	printf "\nTotal on disk: %s\n\n" \
		"$(color green "$(human_bytes "$total_disk")")"
}

# Translate @@SECTION@@ / @@SUB@@ markers into nice output
format_marked_output() {
	while IFS= read -r line; do
		case "$line" in
			'@@SECTION@@ '*)
				section "${line#@@SECTION@@ }"
				;;
			'@@SUB@@ '*)
				subsection "${line#@@SUB@@ }"
				;;
			*)
				printf '%s\n' "$line"
				;;
		esac
	done
}

# Optional progress meter for large logs; prefers pv (pretty), else uses a small
# gawk counter
progress_wrap() {
	local every="${PROGRESS_EVERY:-500000}"

	if have_cmd pv; then
		pv -l -i 1 -B 4m
		printf '\n' >&2
		return
	fi

	gawk -v EVERY="$every" '
	{
		c++
		if (c % EVERY == 0) {
			printf "\r%s lines...", c > "/dev/stderr"
		}
		print
	}
	END {
		if (c > 0) {
			printf "\r%s lines...\n", c > "/dev/stderr"
		}
	}
	'
}

# Parse Apache access logs and emit report text with @@ markers; writes a meta
# file with top IPs (count<tab>ip) for GeoIP lookup.
run_access_stats() {
	local top_n="$1"
	local strip_query="$2"
	local meta_file="$3"
	local full="$4"

	need_cmd gawk

	# Use the C locale for faster regex and character classes
	LC_ALL=C gawk \
		-v TOP="$top_n" \
		-v STRIPQ="$strip_query" \
		-v META="$meta_file" \
		-v FULL="$full" '
function trim_dot0(s) {
	if (s ~ /\.0[kMGTP]$/) sub(/\.0/, "", s)
	return s
}
function hn(n,   s) {
	if (n < 1000) return n ""
	if (n < 1000000) s = sprintf("%.1fk", n/1000.0)
	else if (n < 1000000000) s = sprintf("%.1fM", n/1000000.0)
	else if (n < 1000000000000) s = sprintf("%.1fG", n/1000000000.0)
	else if (n < 1000000000000000)
		s = sprintf("%.1fT", n/1000000000000.0)
	else s = sprintf("%.1fP", n/1000000000000000.0)
	return trim_dot0(s)
}
function hb(n,   s) {
	if (n < 1000) return n ""
	if (n < 1000000) s = sprintf("%.1fk", n/1000.0)
	else if (n < 1000000000) s = sprintf("%.1fM", n/1000000.0)
	else if (n < 1000000000000) s = sprintf("%.1fG", n/1000000000.0)
	else if (n < 1000000000000000)
		s = sprintf("%.1fT", n/1000000000000.0)
	else s = sprintf("%.1fP", n/1000000000000000.0)
	return trim_dot0(s)
}
function mon_num(m) {
	return (m=="Jan")?1:(m=="Feb")?2:(m=="Mar")?3:(m=="Apr")?4:
		(m=="May")?5:(m=="Jun")?6:(m=="Jul")?7:(m=="Aug")?8:
		(m=="Sep")?9:(m=="Oct")?10:(m=="Nov")?11:(m=="Dec")?12:0
}
function epoch_from_timepair(t0, tz0,   tt,d,monS,y,h,mi,s,mon,rest) {
	tt = t0 " " tz0
	gsub(/^\[/, "", tt)
	gsub(/\]$/, "", tt)

	split(tt, rest, ":")
	split(rest[1], dmy, "/")
	d = dmy[1]; monS = dmy[2]; y = dmy[3]
	h = rest[2]; mi = rest[3]; s = rest[4]
	sub(/[^0-9].*$/, "", s)

	mon = mon_num(monS)
	if (!mon) return 0
	return mktime(sprintf("%d %d %d %d %d %d", y, mon, d, h, mi, s))
}
function emit_top_ips(arr, n,   k,c,i) {
	i = 0
	PROCINFO["sorted_in"] = "@val_num_desc"
	for (k in arr) {
		c = arr[k]
		printf "%d\t%s\n", c, k >> META
		if (++i >= n) break
	}
	delete PROCINFO["sorted_in"]
}
function print_table(title, arr, n,   k,c,i) {
	printf "@@SUB@@ %s\n", title
	i = 0
	PROCINFO["sorted_in"] = "@val_num_desc"
	for (k in arr) {
		c = arr[k]
		printf "  %8s  %s\n", hn(c), k
		if (++i >= n) break
	}
	delete PROCINFO["sorted_in"]
	if (i == 0) printf "  (none)\n"
}

{
	# Split on quotes to get request/referrer/ua cheaply
	# q[1]=pre, q[2]=request, q[3]=post, q[4]=ref, q[6]=ua
	total++
	nq = split($0, q, "\"")

	# Tokenize pre-quote to find IP and timestamp fields.
	np = split(q[1], p, /[ \t]+/)
	ip = p[1]
	if (ip == "") ip = "-"

	# Locate the timestamp token by pattern (more robust than fixed positions)
	t0 = ""
	tz0 = ""
	for (i = 1; i <= np; i++) {
		if (p[i] ~ /^\[[0-9]{1,2}\/[A-Za-z]{3}\/[0-9]{4}:/) {
			t0 = p[i]
			if (i+1 <= np) tz0 = p[i+1]
			break
		}
	}

	ips[ip]++

	# Keep first/last timestamp seen for a simple time span estimate
	if (t0 != "" && tz0 != "") {
		if (first_ts == "") first_ts = t0 " " tz0
		last_ts = t0 " " tz0

		tt = t0
		gsub(/^\[/, "", tt)
		split(tt, a, ":")
		split(a[1], dmy, "/")
		mon = mon_num(dmy[2])
		hour = sprintf("%s-%02d-%02d %02d", dmy[3], mon, dmy[1], a[2])
		per_hour[hour]++
	}

	# Parse request: METHOD URI PROTO
	req = q[2]
	split(req, r, /[ \t]+/)
	method = r[1]
	uri_full = r[2]
	if (method == "") method = "-"
	if (uri_full == "") uri_full = "-"
	methods[method]++

	# Optionally strip query part to reduce URL cardinality
	uri = uri_full
	if (STRIPQ == 1) sub(/\?.*$/, "", uri)

	# Parse status and bytes from the post-request chunk
	status = "-"
	bytes = 0
	if (match(q[3], /[[:space:]]*([0-9]{3})[[:space:]]+([0-9-]+)/, m)) {
		status = m[1]
		bytes = m[2]
	}

	statuses[status]++
	if (status ~ /^[0-9][0-9][0-9]$/) {
		sclass = substr(status, 1, 1) "xx"
		classes[sclass]++
	}

	if (bytes == "-" || bytes == "") bytes = 0
	bytes += 0

	total_bytes += bytes
	bytes_ip[ip] += bytes

	# Response size stats (ignore 0-sized to keep min/max sane)
	if (bytes > 0) {
		count_bytes++
		if (min_bytes == 0 || bytes < min_bytes) min_bytes = bytes
		if (bytes > max_bytes) max_bytes = bytes
	}

	# URL stats (always for stripped URL)
	uris[uri]++
	if (FULL == 1) uris_full[uri_full]++

	if (status == "404") nf[uri]++
	if (status ~ /^5/) sx[uri]++

	# Heavy tables are full-mode only.
	if (FULL == 1) {
		ref = q[4]
		ua = q[6]
		if (ref != "" && ref != "-") refs[ref]++
		if (ua != "" && ua != "-") uas[ua]++
	}
}

END {
	printf "@@SECTION@@ Access log\n"

	printf "@@SUB@@ Summary\n"
	printf "  Requests:          %s\n", hn(total)

	uip=0; for (k in ips) uip++
	uuri=0; for (k in uris) uuri++
	printf "  Unique IPs:        %s\n", hn(uip)
	printf "  Unique URLs:       %s\n", hn(uuri)
	printf "  Bytes sent:        %s\n", hb(total_bytes)

	# Derive a simple req/sec estimate from first/last timestamps
	if (first_ts != "" && last_ts != "") {
		split(first_ts, fts, " ")
		split(last_ts, lts, " ")
		min_ep = epoch_from_timepair(fts[1], fts[2])
		max_ep = epoch_from_timepair(lts[1], lts[2])

		t1 = first_ts
		t2 = last_ts
		gsub(/^\[/, "", t1); gsub(/\]$/, "", t1)
		gsub(/^\[/, "", t2); gsub(/\]$/, "", t2)

		span = max_ep - min_ep
		if (span < 1) span = 1
		rps = total / span

		printf "  Time span:         %s — %s\n", t1, t2
		printf "  Avg req/sec:       %.2f\n", rps
	}

	print_table("Top IPs", ips, TOP)
	emit_top_ips(ips, TOP)

	print_table("Top URLs", uris, TOP)
	if (FULL == 1) print_table("Top URLs (as-is)", uris_full, TOP)

	print_table("Top status codes", statuses, TOP)

	printf "@@SUB@@ Status classes\n"
	PROCINFO["sorted_in"] = "@val_num_desc"
	for (k in classes) printf "  %8s  %s\n", hn(classes[k]), k
	delete PROCINFO["sorted_in"]

	print_table("Top methods", methods, TOP)
	print_table("Top 404 URLs", nf, TOP)
	print_table("Top 5xx URLs", sx, TOP)

	print_table("Busiest hours", per_hour, (TOP < 12 ? TOP : 12))
	print_table("Top IPs by bandwidth (bytes summed)", bytes_ip, TOP)

	printf "@@SUB@@ Response size\n"
	printf "  Total:   %s\n", hb(total_bytes)
	if (count_bytes > 0) {
		printf "  Avg:     %s\n", hb(int(total_bytes / count_bytes))
		printf "  Min:     %s\n", hb(min_bytes)
		printf "  Max:     %s\n", hb(max_bytes)
	}

	if (FULL == 1) {
		uua=0; for (k in uas) uua++
		uref=0; for (k in refs) uref++

		printf "\n@@SUB@@ Unique extra fields\n"
		printf "  Unique UAs:        %s\n", hn(uua)
		printf "  Unique referrers:  %s\n", hn(uref)

		print_table("Top user-agents", uas, TOP)
		print_table("Top referrers", refs, TOP)
	}
}
'
}

# Parse Apache error logs and emit report text with @@ markers
run_error_stats() {
	local top_n="$1"

	need_cmd gawk

	LC_ALL=C gawk -v TOP="$top_n" '
function trim_dot0(s) {
	if (s ~ /\.0[kMGTP]$/) sub(/\.0/, "", s)
	return s
}
function hn(n,   s) {
	if (n < 1000) return n ""
	if (n < 1000000) s = sprintf("%.1fk", n/1000.0)
	else if (n < 1000000000) s = sprintf("%.1fM", n/1000000.0)
	else if (n < 1000000000000) s = sprintf("%.1fG", n/1000000000.0)
	else if (n < 1000000000000000)
		s = sprintf("%.1fT", n/1000000000000.0)
	else s = sprintf("%.1fP", n/1000000000000000.0)
	return trim_dot0(s)
}
function mon_num(m) {
	return (m=="Jan")?1:(m=="Feb")?2:(m=="Mar")?3:(m=="Apr")?4:
		(m=="May")?5:(m=="Jun")?6:(m=="Jul")?7:(m=="Aug")?8:
		(m=="Sep")?9:(m=="Oct")?10:(m=="Nov")?11:(m=="Dec")?12:0
}
function epoch_from_error(line,   mon,dd,hh,mi,ss,y) {
	if (match(line,
		/^\[[A-Za-z]{3} ([A-Za-z]{3}) ([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2})\.[0-9]+ ([0-9]{4})\]/, a)) {
		mon = mon_num(a[1]); dd = a[2]
		hh = a[3]; mi = a[4]; ss = a[5]; y = a[6]
		return mktime(sprintf("%d %d %d %d %d %d", y, mon, dd, hh, mi, ss))
	}
	if (match(line,
		/^\[[A-Za-z]{3} ([A-Za-z]{3}) ([0-9]{1,2}) ([0-9]{2}):([0-9]{2}):([0-9]{2}) ([0-9]{4})\]/, b)) {
		mon = mon_num(b[1]); dd = b[2]
		hh = b[3]; mi = b[4]; ss = b[5]; y = b[6]
		return mktime(sprintf("%d %d %d %d %d %d", y, mon, dd, hh, mi, ss))
	}
	return 0
}
function print_table(title, arr, n,   k,c,i) {
	printf "@@SUB@@ %s\n", title
	i = 0
	PROCINFO["sorted_in"] = "@val_num_desc"
	for (k in arr) {
		c = arr[k]
		printf "  %8s  %s\n", hn(c), k
		if (++i >= n) break
	}
	delete PROCINFO["sorted_in"]
	if (i == 0) printf "  (none)\n"
}

{
	total++

	# Track min/max timestamps for time span
	ep = epoch_from_error($0)
	if (ep > 0) {
		if (min_ep == 0 || ep < min_ep)
			{ min_ep = ep; min_t = substr($0, 2, index($0, "]")-2) }
		if (max_ep == 0 || ep > max_ep)
			{ max_ep = ep; max_t = substr($0, 2, index($0, "]")-2) }
	}

	# Capture [level] and [module:level] forms
	if (match($0, /\] \[([^:\]]+)(:([^\]]+))?\]/, m)) {
		if (m[3] != "") { mod = m[1]; lvl = m[3] }
		else { mod = "(none)"; lvl = m[1] }
		modules[mod]++
		levels[lvl]++
	}

	# Extract client IP and AH codes (if present)
	if (match($0, /\[client ([0-9A-Fa-f:\.]+)\b/, c)) clients[c[1]]++
	if (match($0, /AH[0-9]{5}/, a)) ah[a[0]]++

	# Create a short "message start" by stripping leading [..] blocks
	msg = $0
	while (match(msg, /^\[[^]]+\] /)) sub(/^\[[^]]+\] /, "", msg)
	gsub(/[ \t]+/, " ", msg)
	if (length(msg) > 160) msg = substr(msg, 1, 160) "..."
	msgs[msg]++
}

END {
	printf "@@SECTION@@ Error log\n"

	printf "@@SUB@@ Summary\n"
	printf "  Lines:             %s\n", hn(total)
	if (min_ep > 0 && max_ep > 0)
		printf "  Time span:         %s — %s\n", min_t, max_t

	print_table("Levels", levels, TOP)
	print_table("Modules", modules, TOP)
	print_table("Client IPs", clients, TOP)
	print_table("AH codes", ah, TOP)
	print_table("Common message starts", msgs, TOP)
}
'
}

# Find a GeoIP2 country database file (.mmdb), or return empty
geoip2_db_file() {
	if [ -n "${GEOIP_DB:-}" ] && [ -r "$GEOIP_DB" ]; then
		printf '%s' "$GEOIP_DB"
		return
	fi

	# Common path on EL systems
	local f="/usr/share/GeoIP/GeoLite2-Country.mmdb"
	if [ -r "$f" ]; then
		printf '%s' "$f"
		return
	fi

	for f in /usr/share/GeoIP/*.mmdb /var/lib/GeoIP/*.mmdb; do
		if [ -r "$f" ] && [[ "$f" == *Country*.mmdb ]]; then
			printf '%s' "$f"
			return
		fi
	done

	printf ''
}

# Extract the first quoted string from mmdblookup output
mmdb_first_string() {
	awk -F'"' 'NF>=2 {print $2; exit}'
}

# GeoIP2 lookup via mmdblookup (returns "CC<TAB>Name")
geoip2_lookup_ip() {
	local ip="$1"
	local db

	db=$(geoip2_db_file)
	if [ -z "$db" ] || ! have_cmd mmdblookup; then
		printf '??\tUnknown'
		return
	fi

	local cc name
	cc=$(mmdblookup --file "$db" --ip "$ip" country iso_code \
		2>/dev/null | mmdb_first_string || true)
	name=$(mmdblookup --file "$db" --ip "$ip" country names en \
		2>/dev/null | mmdb_first_string || true)

	[ -z "$cc" ] && cc="??"
	[ -z "$name" ] && name="Unknown"
	printf '%s\t%s' "$cc" "$name"
}

# Parse legacy geoiplookup output into "CC<TAB>Name"
geoip_parse() {
	local out="$1"

	out=${out#*: }
	local cc="${out%%,*}"
	local name="${out#*,}"
	name="${name# }"

	[ -z "$cc" ] && cc="??"
	[ "$cc" = "--" ] && cc="??"
	[ -z "$name" ] && name="Unknown"
	[ "$name" = "N/A" ] && name="Unknown"

	printf '%s\t%s' "$cc" "$name"
}

# GeoIP lookup wrapper: prefer geoiplookup, fallback to GeoIP2 mmdblookup
geoip_lookup_ip() {
	local ip="$1"
	local out=""

	if [[ "$ip" == *:* ]] && have_cmd geoiplookup6; then
		out=$(geoiplookup6 "$ip" 2>/dev/null || true)
	elif have_cmd geoiplookup; then
		out=$(geoiplookup "$ip" 2>/dev/null || true)
	fi

	if [ -n "$out" ]; then
		geoip_parse "$out"
		return
	fi

	geoip2_lookup_ip "$ip"
}

# Print GeoIP sections for the top IP list (fast and useful) by reading the
# count<tab>ip from the meta file produced by run_access_stats
print_geoip_sections() {
	local meta_file="$1"

	# Require either legacy GeoIP or GeoIP2 support
	if ! have_cmd geoiplookup && ! have_cmd geoiplookup6; then
		if ! have_cmd mmdblookup; then
			return
		fi
		if [ -z "$(geoip2_db_file)" ]; then
			return
		fi
	fi

	[ ! -s "$meta_file" ] && return

	declare -A GEO_CC
	declare -A GEO_NAME
	declare -A COUNTRY_SUM
	declare -A COUNTRY_NAME

	local count ip cc_name cc name
	local max_ip_len=0

	# First pass to cache Geo results and measure max IP width
	while IFS=$'\t' read -r count ip; do
		[ -z "${count:-}" ] && continue
		[ -z "${ip:-}" ] && continue

		if [ "${#ip}" -gt "$max_ip_len" ]; then
			max_ip_len="${#ip}"
		fi

		if [ -n "${GEO_CC[$ip]+x}" ]; then
			continue
		fi

		cc_name=$(geoip_lookup_ip "$ip")
		cc="${cc_name%%$'\t'*}"
		name="${cc_name#*$'\t'}"
		GEO_CC["$ip"]="$cc"
		GEO_NAME["$ip"]="$name"
	done < "$meta_file"

	# Second pass to sum countries from the top IP list
	while IFS=$'\t' read -r count ip; do
		[ -z "${count:-}" ] && continue
		[ -z "${ip:-}" ] && continue

		cc="${GEO_CC[$ip]}"
		name="${GEO_NAME[$ip]}"
		COUNTRY_SUM["$cc"]=$(( ${COUNTRY_SUM["$cc"]:-0} + count ))
		COUNTRY_NAME["$cc"]="$name"
	done < "$meta_file"

	section "GeoIP (top IPs)"
	while IFS=$'\t' read -r count ip; do
		[ -z "${count:-}" ] && continue
		[ -z "${ip:-}" ] && continue

		cc="${GEO_CC[$ip]}"
		name="${GEO_NAME[$ip]}"

		printf "  %s  %s  %s %s\n" \
			"$(pad_color 8 green "$(human_count "$count")")" \
			"$(pad_color_left "$max_ip_len" dim "$ip")" \
			"$(pad_color 2 cyan "$cc")" \
			"$(color dim "$name")"
	done < "$meta_file"

	printf "\n"

	section "GeoIP (top countries from top IPs)"
	{
		for cc in "${!COUNTRY_SUM[@]}"; do
			printf '%s\t%s\t%s\n' \
				"${COUNTRY_SUM[$cc]}" "$cc" "${COUNTRY_NAME[$cc]}"
		done
	} | sort -rn | while IFS=$'\t' read -r sum cc name; do
		printf "  %s  %s %s\n" \
			"$(pad_color 8 green "$(human_count "$sum")")" \
			"$(pad_color 2 cyan "$cc")" \
			"$(color dim "$name")"
	done

	printf "\n%s\n" \
		"$(color dim "Note: GeoIP sums use only the top-IP list.")"
}

# Main entry to parse args, build file list, stream logs, print report
main() {
	init_color

	local type="auto"
	local number=25
	local rotated_depth=0
	local strip_query=0
	local show_progress=0
	local geoip_disabled=0
	local full=0

	local -a inputs=()

	# Parse CLI args. -i/--input can be repeated and keeps order
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-i|--input)
				shift
				[ "${1:-}" = "" ] && usage
				inputs+=("$1")
				;;
			-t|--type)
				shift
				[ "${1:-}" = "" ] && usage
				type="$1"
				;;
			-n|--number)
				shift
				[ "${1:-}" = "" ] && usage
				number="$1"
				;;
			-R|--rotated)
				if [ "${2:-}" != "" ] && [[ "${2:-}" =~ ^[0-9]+$ ]]; then
					rotated_depth="$2"
					shift
				else
					rotated_depth=-1
				fi
				;;
			--strip-query)
				strip_query=1
				;;
			--full)
				full=1
				;;
			--progress)
				show_progress=1
				;;
			--no-geoip)
				geoip_disabled=1
				;;
			--no-color)
				USE_COLOR=0
				NO_COLOR=1
				;;
			-h|--help)
				usage
				;;
			*)
				printf '%s\n' \
					"$(color red "Error: unknown option: $1")" >&2
				usage
				;;
		esac
		shift
	done

	# Auto-enable progress only for interactive runs
	if [ "$show_progress" -eq 0 ] && [ -t 2 ] && [ -z "${NO_COLOR:-}" ]; then
		show_progress=1
	fi

	[ "${#inputs[@]}" -eq 0 ] && usage

	need_cmd gzip
	need_cmd gawk

	# Validate inputs before doing any work.
	local in
	for in in "${inputs[@]}"; do
		if [ ! -f "$in" ]; then
			printf '%s\n' \
				"$(color red "Error: file not found: $in")" >&2
			exit 1
		fi
	done

	# Auto-detect type from the first input if not forced
	if [ "$type" = "auto" ]; then
		local guessed=""

		guessed=$(guess_type_from_name "${inputs[0]}" || true)
		if [ "$guessed" = "" ]; then
			guessed=$(guess_type_from_content "${inputs[0]}" || true)
		fi
		type="${guessed:-access}"
	fi

	if [ "$type" != "access" ] && [ "$type" != "error" ]; then
		printf '%s\n' \
			"$(color red "Error: bad type: $type")" >&2
		exit 1
	fi

	if ! [[ "$number" =~ ^[0-9]+$ ]] || [ "$number" -lt 1 ]; then
		printf '%s\n' \
			"$(color red "Error: bad --number value: $number")" >&2
		exit 1
	fi

	# In access lite mode, default to stripping query unless user asked
	if [ "$type" = "access" ] && [ "$full" -eq 0 ] \
		&& [ "$strip_query" -eq 0 ]; then
		strip_query=1
	fi

	# Build final file list in input order, then add rotated siblings per
	# input
	local -a files=()
	local detected
	for in in "${inputs[@]}"; do
		detected=$(guess_type_from_name "$in" || true)
		if [ "$detected" = "" ]; then
			detected=$(guess_type_from_content "$in" || true)
		fi
		if [ "$detected" != "" ] && [ "$detected" != "$type" ]; then
			printf '%s\n' "$(color red "Error: mixed log types")" >&2
			printf '%s\n' \
				"$(color dim "Tip: run access and error logs separately.")" \
				>&2
			exit 1
		fi

		while IFS= read -r f; do
			files+=("$f")
		done < <(collect_files_for_input "$in" "$rotated_depth")
	done

	# tar is needed only if we actually see tarballs
	local f
	for f in "${files[@]}"; do
		if [[ "$f" =~ \.tar\.gz$|\.tgz$ ]]; then
			need_cmd tar
			break
		fi
	done

	# Use a temp dir for small meta files (top IP list and line count)
	local tmp_dir
	tmp_dir=$(mktemp -d)
	trap 'cleanup_tmp "'"$tmp_dir"'"' EXIT

	local meta_top_ips="$tmp_dir/top_ips.tsv"
	local line_count_file="$tmp_dir/lines.txt"

	section "Apache log stats"
	printf "Type:        %s\n" "$(color cyan "$type")"
	printf "Top number:  %s\n" "$(color cyan "$number")"
	printf "Inputs:      %s\n" "$(color cyan "${#inputs[@]}")"

	if [ "$rotated_depth" -eq 0 ]; then
		printf "Rotated:     %s\n" "$(color cyan "none")"
	elif [ "$rotated_depth" -eq -1 ]; then
		printf "Rotated:     %s\n" "$(color cyan "all")"
	else
		local file_label="file"
		[ "$rotated_depth" -gt 1 ] && file_label="files"
		printf "Rotated:     %s\n" "$(color cyan "yes, $rotated_depth $file_label")"
	fi
	local strip_desc="disabled"
	if [ "$strip_query" -eq 1 ]; then
		strip_desc="enabled"
	fi
	printf "Progress:    %s\n" "$(color cyan "$strip_desc")"

	if [ "$type" = "access" ]; then
		if [ "$strip_query" -eq 1 ]; then
			printf "Query:       %s\n" "$(color cyan "no")"
		else
			printf "Query:       %s\n" "$(color cyan "yes")"
		fi

		printf "Mode:        %s\n" \
			"$(color cyan "$( [ "$full" -eq 1 ] && echo full || echo lite )")"
	fi

	# GeoIP can work via geoiplookup or via mmdblookup+db
	local geoip_possible=0
	if [ "$geoip_disabled" -eq 0 ] && (
		have_cmd geoiplookup || have_cmd geoiplookup6 \
		|| ( have_cmd mmdblookup && [ -n "$(geoip2_db_file)" ] )
	); then
		geoip_possible=1
	fi
	local geoip_desc="disabled"
	if [ "$geoip_possible" -eq 1 ]; then
		geoip_desc="enabled"
	fi
	printf "GeoIP:       %s\n\n" "$(color cyan "$geoip_desc")"

	print_file_list "${files[@]}"

	section "Parsing"
	printf "%s\n\n" "$(color dim "Reading and analyzing logs...")"

	# Stream all selected files once and tee counts lines in parallel
	if [ "$type" = "access" ]; then
		(
			for f in "${files[@]}"; do
				stream_file "$f"
			done
		) | tee >(wc -l | tr -d " " > "$line_count_file") \
			| {
				if [ "$show_progress" -eq 1 ]; then
					progress_wrap
				else
					cat
				fi
			} | run_access_stats \
				"$number" "$strip_query" "$meta_top_ips" "$full" \
			| format_marked_output
	else
		(
			for f in "${files[@]}"; do
				stream_file "$f"
			done
		) | tee >(wc -l | tr -d " " > "$line_count_file") \
			| {
				if [ "$show_progress" -eq 1 ]; then
					progress_wrap
				else
					cat
				fi
			} | run_error_stats "$number" \
			| format_marked_output
	fi

	# Use the tee-produced counter to detect empty streams
	local parsed_lines
	parsed_lines=$(cat "$line_count_file" 2>/dev/null || printf '0')
	if ! [[ "$parsed_lines" =~ ^[0-9]+$ ]]; then
		parsed_lines=0
	fi

	if [ "$parsed_lines" -eq 0 ]; then
		printf '\n%s\n' \
			"$(color yellow "No lines parsed (empty log stream).")" >&2
		exit 2
	fi

	printf "\n"
	section "Done"
	printf "  Parsed lines: %s\n" \
		"$(color green "$(human_count "$parsed_lines")")"
	printf "\n"

	# GeoIP uses the meta file written by run_access_stats.
	if [ "$type" = "access" ] && [ "$geoip_possible" -eq 1 ]; then
		print_geoip_sections "$meta_top_ips"
	fi

	printf "\n"
}

main "$@"
