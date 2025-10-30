#!/bin/bash

echo "📊 Authentication Service Performance Analysis Report"
echo "===================================================="
echo ""
echo "SLOW OPERATIONS (over 1000ms):"
grep "SLOW OPERATION" logs/auth.log | \
  awk -F'SLOW OPERATION: ' '{print $2}' | \
  sort | uniq -c | sort -nr

echo ""
echo "AVERAGE OPERATION TIMES:"
echo "User Registration: $(grep "User creation completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"
echo "User Update: $(grep "User update completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"
echo "Token Generation: $(grep "Token generation completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"
echo "OAuth Processing: $(grep "OAuth success processing completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"

echo ""
echo "SLOW API CALLS:"
grep "SLOW API" logs/auth.log | \
  awk -F'SLOW API: ' '{print $2}' | \
  sort | uniq -c | sort -nr

echo ""
echo "PASSWORD PKCE AUTHENTICATION:"
grep "Password PKCE authentication completed" logs/auth.log | \
  awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "Average: %.2fms\n", sum/count}'

echo ""
echo "USER REGISTRATION SUCCESS RATE:"
TOTAL_REGISTERS=$(grep "REGISTER request" logs/auth.log | wc -l)
SUCCESSFUL_REGISTERS=$(grep "REGISTER success" logs/auth.log | wc -l)
if [ $TOTAL_REGISTERS -gt 0 ]; then
    SUCCESS_RATE=$((SUCCESSFUL_REGISTERS * 100 / TOTAL_REGISTERS))
    echo "Success Rate: $SUCCESS_RATE% ($SUCCESSFUL_REGISTERS/$TOTAL_REGISTERS)"
else
    echo "No registration attempts found"
fi

echo ""
echo "TOKEN OPERATIONS:"
echo "Token Generation: $(grep "Token generation completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"
echo "OAuth Token Flow: $(grep "OAuth success processing completed" logs/auth.log | awk -F'in ' '{print $2}' | awk -F'ms' '{sum+=$1; count++} END {if(count>0) printf "%.2fms", sum/count}')"
