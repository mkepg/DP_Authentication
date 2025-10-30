#!/bin/bash

# Get the timestamp string for 5 minutes ago (minute precision)
TIMESTAMP=$(date -d '5 minutes ago' '+%Y-%m-%d %H:%M')

# Extract all lines from auth.log that match the timestamp AND contain "ERROR"
ERROR_LINES=$(grep "$TIMESTAMP" logs/auth.log | grep "ERROR")

# Count how many lines were found
ERROR_COUNT=$(echo "$ERROR_LINES" | grep -c .)

# Output the count
echo "Errors in the last 5 minutes: $ERROR_COUNT"

# Output each error line (if any)
if [ $ERROR_COUNT -gt 0 ]; then
    echo "Matching error lines:"
    echo "$ERROR_LINES"
else
    echo "No errors found."
fi
#if [ $ERROR_COUNT -gt 5 ]; then
#	# todo send to telegram
#fi
