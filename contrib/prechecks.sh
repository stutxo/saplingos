#!/usr/bin/env sh

# We don't allow any line that starts with a whitespace
rust_no_spaces_for_indent() {
	ok=0

	for filename in $(git ls-files --cached --others --exclude-standard -- 'sdk/*.rs' 'protocol/*.rs' 'rpc/*.rs' 'testing/*.rs'); do
		[ -f "$filename" ] || continue
		gen=$(echo "$filename" | git check-attr --stdin linguist-generated)
		case "$gen" in
			*"linguist-generated: set"*)
				continue ;;
		esac

		output=$(grep -n '^ ' "$filename")
		status_code=$?

		if [ $status_code -eq 0 ]; then
			echo "Format error in '$filename'"
			echo "$output"

			ok=2
		elif [ $status_code -eq 2 ]; then
			echo "An error occurred"
			echo "$output"

			ok=2
		fi
	done

	exit $ok
}

# We don't allow lines that only have whitespace
rust_no_whitespace_on_empty_lines() {
	ok=0

	for filename in $(git ls-files --cached --others --exclude-standard -- 'sdk/*.rs' 'protocol/*.rs' 'rpc/*.rs' 'testing/*.rs'); do
		[ -f "$filename" ] || continue
		gen=$(echo "$filename" | git check-attr --stdin linguist-generated)
		case "$gen" in
			*"linguist-generated: set"*)
				continue ;;
		esac

		output=$(grep -nE '^[[:space:]]+$' "$filename")
		status_code=$?

		if [ $status_code -eq 0 ]; then
			echo "Format error in '$filename'"
			echo "$output"

			ok=2
		elif [ $status_code -eq 2 ]; then
			echo "An error occurred"
			echo "$output"

			ok=2
		fi
	done

	exit $ok
}

# Check if the function exists and execute it
if command -v "$1" > /dev/null 2>&1; then
	"$@"
else
	echo "Function '$1' not found!"

	exit 2
fi
