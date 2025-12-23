#!/usr/bin/env bash
# age.bash (https://github.com/iliaross/script-stash)
# Copyright Ilia Ross <ilia@ross.gdn>
# Licensed under the MIT License
#
# This script encrypts or decrypts files using age with SSH public key
# recipients.
#
# Description:
# - Recipients:
#   All .pub files in ~/.age directory are used as recipients.
#   Each recipient can independently decrypt the resulting .age file
#   with their private key.
#
# - Input:
#   The file you want to encrypt or decrypt.
#
# - Output:
#   The encrypted file. If not specified, uses <input>.age
#   For decryption, strips .age extension or uses specified output.
#
# Usage:
#   ./age.bash -i <input-file> [-o <output>]
#   ./age.bash -d -i <encrypted.age> [-o <output>] [-k <private-key>]
#   ./age.bash -l
#
# Examples:
#   # List available recipient keys
#   ./age.bash -l
#
#   # Encrypt for all recipients in ~/.age
#   ./age.bash -i secrets.tar.bz2
#
#   # Encrypt for specific recipients only
#   ./age.bash -i secrets.tar.bz2 -k john -k dave
#
#   # Encrypt for all except specific recipients
#   ./age.bash -i secrets.tar.bz2 -x anna
#
#   # Decrypt using default SSH key
#   ./age.bash -d -i secrets.tar.bz2.age
#
#   # Decrypt with specific private key
#   ./age.bash -d -i secrets.tar.bz2.age -k ~/.ssh/id_ed25519

set -euo pipefail
umask 077

# Constants
readonly KEYS_DIR="${AGE_KEYS_DIR:-$HOME/.age}"
readonly DEFAULT_PRIVATE_KEYS=(
	"$HOME/.ssh/id_ed25519"
	"$HOME/.ssh/id_rsa"
	"$HOME/.ssh/id_ecdsa"
	"$HOME/.ssh/id_dsa"
)

# Globals for color support
USE_COLOR=0

# Initialize color support
init_color() {
	if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
		USE_COLOR=1
	fi
}

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

section() {
	local title="$1"
	local bar
	bar=$(printf '%*s' $(( ${#title} + 4 )) '' | tr ' ' '-')
	printf '%s\n%s\n%s\n' \
		"$(color gray "$bar")" \
		"$(color bold "| $title |")" \
		"$(color gray "$bar")"
}

human_size() {
	local size="$1"
	if command -v numfmt &>/dev/null; then
		numfmt --to=iec "$size" 2>/dev/null || printf '%s bytes' "$size"
	else
		printf '%s bytes' "$size"
	fi
}

file_size() {
	local file="$1"
	stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null
}

usage() {
	cat >&2 <<-EOF
	Usage: $(basename "$0") [options] -i <input-file>
	       $(basename "$0") -l

	Modes:
	  (default)       Encrypt input file for recipients in ~/.age
	  -d, --decrypt   Decrypt input file using SSH private key
	  -l, --list      List available recipient public keys

	Options:
	  -i, --input     Input file to encrypt/decrypt (required except -l)
	  -o, --output    Output file name (default: <input>.age or strip .age)
	  -k, --key       Encrypt: use only these recipients (can repeat)
	                  Decrypt: private key to use (default: ~/.ssh/id_*)
	  -x, --exclude   Exclude these recipients from encryption (can repeat)
	  -h, --help      Show this help message

	Environment:
	  AGE_KEYS_DIR    Directory containing .pub files (default: ~/.age)

	Examples:
	  $(basename "$0") -l
	  $(basename "$0") -i secrets.tar.bz2
	  $(basename "$0") -i secrets.tar.bz2 -k john -k dave
	  $(basename "$0") -i secrets.tar.bz2 -x anna
	  $(basename "$0") -d -i secrets.tar.bz2.age
	  $(basename "$0") -d -i secrets.tar.bz2.age -k ~/.ssh/id_ed25519
	EOF
	exit 1
}

# Validate public key file; returns 0 if valid, outputs key type on success
validate_pubkey() {
	local pubkey="$1"
	local first_line key_type

	# Check file is readable and non-empty
	if [ ! -r "$pubkey" ] || [ ! -s "$pubkey" ]; then
		return 1
	fi

	first_line=$(head -n1 "$pubkey" 2>/dev/null) || return 1

	# Check for age native keys
	if [[ "$first_line" =~ ^age1[a-z0-9]{58}$ ]]; then
		printf 'age'
		return 0
	fi

	# For SSH keys, use ssh-keygen to validate
	if ssh-keygen -l -f "$pubkey" &>/dev/null; then
		key_type=$(awk '{print $1}' <<< "$first_line")
		printf '%s' "$key_type"
		return 0
	fi

	return 1
}

# Check keys directory exists
check_keys_dir() {
	if [ ! -d "$KEYS_DIR" ]; then
		printf '%s\n' "$(color red "Error: Keys directory not found: $KEYS_DIR")" >&2
		exit 1
	fi
}

# Normalize key name (strip .pub if present, resolve path)
normalize_key_name() {
	local key="$1"
	key="${key%.pub}"
	basename "$key"
}

# Check if key name is in array
key_in_array() {
	local needle="$1"
	shift
	local item
	for item in "$@"; do
		if [ "$item" = "$needle" ]; then
			return 0
		fi
	done
	return 1
}

# List mode
do_list() {
	check_keys_dir

	section "Available recipient keys"
	printf "Keys directory: %s\n\n" "$(color cyan "$KEYS_DIR")"

	local count=0
	local max_name_len=0
	local keys=()
	local pubkey name len key_type

	# First pass: collect keys and find max name length
	while IFS= read -r pubkey; do
		[ -z "$pubkey" ] && continue
		keys+=("$pubkey")
		name=$(basename "$pubkey" .pub)
		len=${#name}
		if [ "$len" -gt "$max_name_len" ]; then
			max_name_len="$len"
		fi
	done < <(find "$KEYS_DIR" -maxdepth 1 -type f -name '*.pub' 2>/dev/null | sort)

	if [ "${#keys[@]}" -eq 0 ]; then
		printf '%s\n' "$(color yellow "No .pub files found in $KEYS_DIR")"
		exit 0
	fi

	# Second pass: display keys
	for pubkey in "${keys[@]}"; do
		name=$(basename "$pubkey" .pub)
		if key_type=$(validate_pubkey "$pubkey"); then
			printf "  %-*s  %s\n" "$max_name_len" "$(color cyan "$name")" "$(color dim "($key_type)")"
			((++count))
		else
			printf "  %-*s  %s\n" "$max_name_len" "$name" "$(color yellow "(invalid)")"
		fi
	done

	printf '\n%s\n' "$(color dim "Total: $count recipient(s)")"
	exit 0
}

# Decrypt mode
do_decrypt() {
	local input_file="$1"
	local output_file="$2"
	local private_key="$3"
	local input_size key_to_use key output_size

	section "Checking prerequisites"

	if ! command -v age &>/dev/null; then
		printf '%s\n' "$(color red "Error: 'age' command not found")" >&2
		printf '%s\n' "$(color dim "Install with: 'apt install age' (Debian/Ubuntu) or 'dnf install age' (EL) or 'brew install age' (macOS)")" >&2
		exit 1
	fi

	printf "age version: %s\n\n" "$(color cyan "$(age --version 2>&1 | head -n1)")"

	# Validate input file
	section "Validating encrypted file"

	if [ ! -f "$input_file" ]; then
		printf '%s\n' "$(color red "Error: Input file not found: $input_file")" >&2
		exit 1
	fi

	input_size=$(file_size "$input_file")

	printf "Input file : %s\n" "$(color cyan "$input_file")"
	printf "File size  : %s\n" "$(color dim "$(human_size "$input_size")")"

	# Default output: strip .age extension
	if [ -z "$output_file" ]; then
		if [[ "$input_file" == *.age ]]; then
			output_file="${input_file%.age}"
		else
			output_file="${input_file}.decrypted"
		fi
	fi

	printf "Output file: %s\n\n" "$(color cyan "$output_file")"

	# Check if output file exists
	if [ -f "$output_file" ]; then
		printf '%s\n' "$(color yellow "Warning: Output file already exists")" >&2
		printf '%s' "Overwrite? [y/N] "
		read -r confirm
		if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
			printf '%s\n' "$(color red "Aborted.")"
			exit 1
		fi
		printf '\n'
	fi

	# Find private key
	section "Locating private key"

	key_to_use=""

	if [ -n "$private_key" ]; then
		if [ ! -f "$private_key" ]; then
			printf '%s\n' "$(color red "Error: Private key not found: $private_key")" >&2
			exit 1
		fi
		key_to_use="$private_key"
		printf "Using specified key: %s\n\n" "$(color cyan "$key_to_use")"
	else
		printf "Searching for SSH private keys...\n\n"

		for key in "${DEFAULT_PRIVATE_KEYS[@]}"; do
			if [ -f "$key" ]; then
				printf "  %s : %s\n" "$(color cyan "$(basename "$key")")" "$(color green "found")"
				if [ -z "$key_to_use" ]; then
					key_to_use="$key"
				fi
			else
				printf "  %s : %s\n" "$(color dim "$(basename "$key")")" "$(color dim "not found")"
			fi
		done

		printf '\n'

		if [ -z "$key_to_use" ]; then
			printf '%s\n' "$(color red "Error: No SSH private key found")" >&2
			printf '%s\n' "$(color dim "Specify one with: -k <private-key>")" >&2
			exit 1
		fi

		printf "Selected: %s\n\n" "$(color green "$key_to_use")"
	fi

	# Execute decryption
	section "Decrypting file"

	printf "Command: %s\n\n" "$(color dim "age -d -i $key_to_use -o $output_file $input_file")"

	if age -d -i "$key_to_use" -o "$output_file" "$input_file"; then
		output_size=$(file_size "$output_file")

		section "Decryption complete"

		printf "Output file : %s\n" "$(color green "$output_file")"
		printf "Output size : %s\n\n" "$(color dim "$(human_size "$output_size")")"

		printf '%s\n' "$(color dim "Verify with: shasum -a 256 $output_file")"
	else
		printf '%s\n' "$(color red "Error: Decryption failed")" >&2
		printf '%s\n' "$(color dim "This key may not be a valid recipient for this file")" >&2
		exit 1
	fi
}

# Encrypt mode
do_encrypt() {
	local input_file="$1"
	local output_file="$2"
	shift 2
	local -a selected_keys=()
	local -a excluded_keys=()

	# Parse selected and excluded keys from remaining args
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--selected)
				shift
				while [ "$#" -gt 0 ] && [ "$1" != "--excluded" ]; do
					selected_keys+=("$(normalize_key_name "$1")")
					shift
				done
				;;
			--excluded)
				shift
				while [ "$#" -gt 0 ] && [ "$1" != "--selected" ]; do
					excluded_keys+=("$(normalize_key_name "$1")")
					shift
				done
				;;
			*)
				shift
				;;
		esac
	done

	local input_size output_size overhead
	local -a all_keys=()
	local -a valid_recipients=()
	local max_name_len=0
	local pubkey name len key_type
	local -a age_args=()

	check_keys_dir

	section "Checking prerequisites"

	if ! command -v age &>/dev/null; then
		printf '%s\n' "$(color red "Error: 'age' command not found")" >&2
		printf '%s\n' "$(color dim "Install with: 'apt install age' (Debian/Ubuntu) or 'dnf install age' (EL) or 'brew install age' (macOS)")" >&2
		exit 1
	fi

	printf "age version: %s\n\n" "$(color cyan "$(age --version 2>&1 | head -n1)")"

	# Validate input file
	section "Validating input file"

	if [ ! -f "$input_file" ]; then
		printf '%s\n' "$(color red "Error: Input file not found: $input_file")" >&2
		exit 1
	fi

	input_size=$(file_size "$input_file")

	printf "Input file : %s\n" "$(color cyan "$input_file")"
	printf "File size  : %s\n" "$(color dim "$(human_size "$input_size")")"

	# Default output file name
	if [ -z "$output_file" ]; then
		output_file="${input_file}.age"
	fi

	printf "Output file: %s\n\n" "$(color cyan "$output_file")"

	# Check if output file exists
	if [ -f "$output_file" ]; then
		printf '%s\n' "$(color yellow "Warning: Output file already exists")" >&2
		printf '%s' "Overwrite? [y/N] "
		read -r confirm
		if [ "$confirm" != "y" ] && [ "$confirm" != "Y" ]; then
			printf '%s\n' "$(color red "Aborted.")"
			exit 1
		fi
		printf '\n'
	fi

	# Collect and validate recipients
	if [ "${#selected_keys[@]}" -gt 0 ]; then
		section "Loading selected recipients"
	else
		section "Loading recipients from $KEYS_DIR"
	fi

	# First pass: collect keys and find max name length
	while IFS= read -r pubkey; do
		[ -z "$pubkey" ] && continue
		all_keys+=("$pubkey")
		name=$(basename "$pubkey" .pub)
		len=${#name}
		if [ "$len" -gt "$max_name_len" ]; then
			max_name_len="$len"
		fi
	done < <(find "$KEYS_DIR" -maxdepth 1 -type f -name '*.pub' 2>/dev/null | sort)

	if [ "${#all_keys[@]}" -eq 0 ]; then
		printf '%s\n' "$(color red "Error: No .pub files found in $KEYS_DIR")" >&2
		exit 1
	fi

	printf '\n'

	# Second pass: validate and filter
	for pubkey in "${all_keys[@]}"; do
		name=$(basename "$pubkey" .pub)

		# Check if key should be included
		if [ "${#selected_keys[@]}" -gt 0 ]; then
			if ! key_in_array "$name" "${selected_keys[@]}"; then
				printf "  %-*s : %s\n" "$max_name_len" "$name" "$(color dim "SKIPPED")"
				continue
			fi
		elif [ "${#excluded_keys[@]}" -gt 0 ]; then
			if key_in_array "$name" "${excluded_keys[@]}"; then
				printf "  %-*s : %s\n" "$max_name_len" "$name" "$(color yellow "EXCLUDED")"
				continue
			fi
		fi

		# Validate the public key
		if ! key_type=$(validate_pubkey "$pubkey"); then
			printf "  %-*s : %s\n" "$max_name_len" "$name" "$(color yellow "INVALID")"
			continue
		fi

		printf "  %-*s : %s %s\n" "$max_name_len" "$name" "$(color green "OK")" "$(color dim "($key_type)")"
		valid_recipients+=("$pubkey")
	done

	printf '\n'

	# Check for missing selected keys
	if [ "${#selected_keys[@]}" -gt 0 ]; then
		for name in "${selected_keys[@]}"; do
			local found=0
			for pubkey in "${valid_recipients[@]}"; do
				if [ "$(basename "$pubkey" .pub)" = "$name" ]; then
					found=1
					break
				fi
			done
			if [ "$found" -eq 0 ]; then
				printf '%s\n' "$(color yellow "Warning: Selected key not found")" >&2
			fi
		done
	fi

	if [ "${#valid_recipients[@]}" -eq 0 ]; then
		printf '%s\n' "$(color red "Error: No valid recipient public keys found")" >&2
		exit 1
	fi

	printf "Valid recipients: %s\n\n" "$(color cyan "${#valid_recipients[@]}")"

	# Build age command
	section "Encrypting file"

	for pubkey in "${valid_recipients[@]}"; do
		age_args+=("-R" "$pubkey")
	done
	age_args+=("-o" "$output_file")
	age_args+=("$input_file")

	printf "Command: %s\n\n" "$(color dim "age ${age_args[*]}")"

	# Execute encryption
	if age "${age_args[@]}"; then
		output_size=$(file_size "$output_file")
		overhead=$((output_size - input_size))

		section "Encryption complete"

		printf "Output file : %s\n" "$(color green "$output_file")"
		printf "Output size : %s\n" "$(color dim "$(human_size "$output_size")")"
		printf "Overhead    : %s bytes (header + per-recipient keys)\n\n" "$(color dim "$overhead")"

		printf "Recipients who can decrypt:\n"
		for pubkey in "${valid_recipients[@]}"; do
			printf "  • %s\n" "$(color cyan "$(basename "$pubkey" .pub)")"
		done

		printf '\n%s\n' "$(color dim "Decrypt with: $(basename "$0") -d -i $output_file")"
	else
		printf '%s\n' "$(color red "Error: Encryption failed")" >&2
		exit 1
	fi
}

# Main
main() {
	local input_file=""
	local output_file=""
	local mode="encrypt"
	local list_only=0
	local -a keys=()
	local -a excludes=()

	init_color

	# Parse arguments
	while [ "$#" -gt 0 ]; do
		case "$1" in
			-i|--input)
				[ -z "${2:-}" ] && usage
				input_file="$2"
				shift 2
				;;
			-o|--output)
				[ -z "${2:-}" ] && usage
				output_file="$2"
				shift 2
				;;
			-k|--key)
				[ -z "${2:-}" ] && usage
				keys+=("$2")
				shift 2
				;;
			-x|--exclude)
				[ -z "${2:-}" ] && usage
				excludes+=("$2")
				shift 2
				;;
			-d|--decrypt)
				mode="decrypt"
				shift
				;;
			-l|--list)
				list_only=1
				shift
				;;
			-h|--help)
				usage
				;;
			*)
				printf 'Unknown option: %s\n' "$1" >&2
				usage
				;;
		esac
	done

	# List mode
	if [ "$list_only" -eq 1 ]; then
		do_list
	fi

	# Validate input file is provided for encrypt/decrypt
	if [ -z "$input_file" ]; then
		printf 'Error: Input file is required\n\n' >&2
		usage
	fi

	if [ "$mode" = "decrypt" ]; then
		local private_key="${keys[0]:-}"
		do_decrypt "$input_file" "$output_file" "$private_key"
	else
		local -a encrypt_args=("$input_file" "$output_file")
		if [ "${#keys[@]}" -gt 0 ]; then
			encrypt_args+=("--selected")
			encrypt_args+=("${keys[@]}")
		fi
		if [ "${#excludes[@]}" -gt 0 ]; then
			encrypt_args+=("--excluded")
			encrypt_args+=("${excludes[@]}")
		fi
		do_encrypt "${encrypt_args[@]}"
	fi
}

main "$@"
