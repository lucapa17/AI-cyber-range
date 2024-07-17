input_directory="/app/query"
output_directory="/app/logs"

exit_func() {
    echo "Exiting...\n"
    exit 0
}
trap exit_func SIGINT

sleep 10
while true; do
    files=("$input_directory"/*)
    if [ ${#files[@]} -gt 0 ]; then
        for file in "${files[@]}"; do
            # Extract the filename without the path
            if [[ $file == *"checked"* ]]; then
                continue
            fi
            filename=$(basename "$file")
            echo "Found a new file!"
            echo "Processing file: $filename"
            # Define the log file path
            log_file="$output_directory/$filename"
            python toucanstrike/toucanstrike.py < "$file" 2>&1 | tee "$log_file"
            mv "$file" "${file%.txt}_checked.txt"
            echo "Completed."
            echo "Looking for a new file..."
        done
    fi
    # Add a delay before checking for files again
    sleep 5
done