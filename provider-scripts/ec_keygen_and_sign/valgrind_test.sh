#!/bin/bash
set -euo pipefail

# Directory setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Go through all .sh files in this directory (excluding this script and config.sh itself)
for script in "$SCRIPT_DIR"/*.sh; do
    [[ "$(basename "$script")" == "valgrind_test.sh" ]] && continue        # Skip self
    [[ "$(basename "$script")" == "config.sh" ]] && continue  # Skip top-level config.sh
    [[ -f "$script" ]] || continue

    log_file="$LOG_DIR/$(basename "${script%.sh}").log"
    echo "=== Running $script ===" | tee "$log_file"

    # Read each line (skip comments and empty lines)
    while IFS= read -r line || [[ -n "$line" ]]; do
        # Trim whitespace
        line="$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^# ]] && continue

        echo -e "\n> $line" | tee -a "$log_file"

        # Allow "rm" commands to fail silently
        if [[ "$line" =~ ^rm[[:space:]] ]]; then
            set +e
            eval "$line" >>"$log_file" 2>&1 || true
            set -e
            continue
        fi

        # Source config.sh in current shell (so vars persist)
        if [[ "$line" =~ ^source[[:space:]]+config\.sh ]]; then
            source "$SCRIPT_DIR/config.sh"
            continue
        fi

        # Ignore any set -e in the script
        if [[ "$line" =~ ^set[[:space:]]+-e ]]; then
            echo "⚠️ Ignoring set -e in script" | tee -a "$log_file"
            continue
        fi

        # Run under valgrind if line contains "trustm_provider"
        if [[ "$line" == *"trustm_provider"* ]]; then
            set +e
            read -r -a cmd <<< "$line"
            eval "valgrind --leak-check=full --show-leak-kinds=all --show-reachable=no --track-origins=yes \
            --error-exitcode=1 \
            --log-file=\"$LOG_DIR/valgrind_$(basename "${script%.sh}").log\" $line"
	    set -e
        else
            set +e
            eval "$line" >>"$log_file" 2>&1
            exit_code=$?
            set -e
            if [[ $exit_code -ne 0 ]]; then
                echo "❌ Command failed (exit $exit_code): $line" | tee -a "$log_file"
                exit 1
            fi
        fi
    done < "$script"

    echo "=== Finished $script ===" | tee -a "$log_file"
done

echo " All scripts processed. Logs saved to: $LOG_DIR"

