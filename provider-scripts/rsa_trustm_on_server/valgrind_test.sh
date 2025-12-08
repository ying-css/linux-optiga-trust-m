#!/bin/bash
set -euo pipefail

# Directory setup
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="$SCRIPT_DIR/logs"
mkdir -p "$LOG_DIR"

# Go through all .sh files in this directory excluding self and config 
for script in "$SCRIPT_DIR"/*.sh; do
    [[ "$(basename "$script")" == "valgrind_test.sh" ]] && continue        # Skip self
    [[ "$(basename "$script")" == "config.sh" ]] && continue               # Skip top-level config.sh
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

	# allow rm commands to fail (typically in step0 for cleanup if the .pem doesnt already exist)
	if [[ "$line" =~ ^rm[[:space:]] ]]; then
            set +e
            eval "$line" >>"$log_file" 2>&1 || true
            set -e
            continue
        fi


        if [[ "$line" =~ ^source[[:space:]]+config\.sh ]]; then
            source "$SCRIPT_DIR/config.sh"
            continue
        fi

        # ignore set -e
        if [[ "$line" =~ ^set[[:space:]]+-e ]]; then
            echo "Ignoring set -e in script" | tee -a "$log_file"
            continue
        fi

        # Valgrind handling for trustm_provider-related commands
        if [[ "$line" == *"trustm_provider"* ]]; then
           read -r -a cmd <<< "$line"

	    # Detect and remove lxterminal wrapper if present
            if [[ "$line" =~ ^lxterminal[[:space:]]+-e[[:space:]]*\"([^\"]+)\" ]]; then
                inner_cmd="${BASH_REMATCH[1]}"
                echo "Detected lxterminal — running directly: $inner_cmd" | tee -a "$log_file"
                line="$inner_cmd"
            fi

            # --- OpenSSL server handling ---
            if [[ "$line" == *"openssl s_server"* ]]; then
                echo "Starting OpenSSL server under Valgrind..." | tee -a "$log_file"

                SERVER_IN="$LOG_DIR/server_in.$$"
                mkfifo "$SERVER_IN"

                {
                    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
                        --error-exitcode=1 \
                        --log-file="$LOG_DIR/valgrind_server_$(basename "${script%.sh}").log" \
                        $line <"$SERVER_IN" >"$LOG_DIR/server_stdout.log" 2>&1
                } &
                SERVER_PID=$!
                echo "Server running with PID $SERVER_PID" | tee -a "$log_file"

                sleep 3 # Give server time to start
                continue
            fi

            # --- OpenSSL client handling ---
            if [[ "$line" == *"openssl s_client"* ]]; then
                echo "Running OpenSSL client under Valgrind..." | tee -a "$log_file"

                CLIENT_IN="$LOG_DIR/client_in.$$"
                mkfifo "$CLIENT_IN"

                {
                    valgrind --leak-check=full --show-leak-kinds=all --track-origins=yes \
                        --error-exitcode=1 \
                        --log-file="$LOG_DIR/valgrind_client_$(basename "${script%.sh}").log" \
                        $line <"$CLIENT_IN" >"$LOG_DIR/client_stdout.log" 2>&1
                } &
                CLIENT_PID=$!
                echo "Client running with PID $CLIENT_PID" | tee -a "$log_file"

                # Wait before sending 'Q'
                client_runtime=5
                echo "Waiting $client_runtime seconds before sending 'Q' to client..." | tee -a "$log_file"
                sleep "$client_runtime"

                echo "Sending 'Q' to client..." | tee -a "$log_file"
                echo "Q" >"$CLIENT_IN"
                sleep 1

                echo "Stopping client (PID $CLIENT_PID)..." | tee -a "$log_file"
                kill "$CLIENT_PID" 2>/dev/null || true
                wait "$CLIENT_PID" 2>/dev/null || true
                rm -f "$CLIENT_IN"
                unset CLIENT_PID

                # Wait before shutting down server
                delay_seconds=2
                echo "Waiting $delay_seconds seconds before closing server..." | tee -a "$log_file"
                sleep "$delay_seconds"

                # Send "Q" to server if running for clean close
                if [[ -n "${SERVER_PID:-}" ]]; then
                    echo "Sending 'Q' to OpenSSL server..." | tee -a "$log_file"
                    echo "Q" >"$SERVER_IN"
                    sleep 1
                    echo "Stopping server (PID $SERVER_PID)..." | tee -a "$log_file"
                    kill "$SERVER_PID" 2>/dev/null || true
                    wait "$SERVER_PID" 2>/dev/null || true
                    rm -f "$SERVER_IN"
                    unset SERVER_PID
                fi

                continue
            fi

            # --- Default trustm_provider command under Valgrind ---
                     eval "valgrind --leak-check=full --show-leak-kinds=all --show-reachable=no \
                --track-origins=yes --error-exitcode=1 \
                --log-file=\"$LOG_DIR/valgrind_$(basename "${script%.sh}").log\" $line"
            set -e

	    continue
        fi

        # default execution for non-valgrind commands
        set +e
        eval "$line" >>"$log_file" 2>&1
        exit_code=$?
        set -e
        if [[ $exit_code -ne 0 ]]; then
            echo "Command failed (exit $exit_code): $line" | tee -a "$log_file"
            exit 1
        fi

    done < "$script"

    echo "=== Finished $script ===" | tee -a "$log_file"
done

echo "All scripts processed. Logs saved to: $LOG_DIR"

