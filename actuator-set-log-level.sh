#!/bin/bash

if [ $# -lt 1 ]; then
  echo "Usage: $0 <log_level> [package_group]"
  echo "Valid levels: TRACE, DEBUG, INFO, WARN, ERROR, OFF"
  echo "Package groups:"
  echo "  myapp      - Your application only (com.mm_mk.Authentication)"
  echo "  spring     - Spring Framework"
  echo "  security   - Spring Security"
  echo "  database   - Hibernate & JDBC"
  echo "  web        - Tomcat & web layers"
  echo "  all        - All important packages (recommended)"
  echo ""
  echo "Examples:"
  echo "  $0 DEBUG all        # Set all important packages to DEBUG"
  echo "  $0 ERROR myapp      # Set only your app to ERROR"
  echo "  $0 INFO spring      # Set Spring to INFO"
  exit 1
fi

# Configuration
BASE_URL="http://localhost:9000/actuator/loggers"
USERNAME="admin"
PASSWORD="admin123"
LOG_LEVEL=$1
GROUP=${2:-"all"}

# Validate log level
VALID_LEVELS=("TRACE" "DEBUG" "INFO" "WARN" "ERROR" "OFF")
if [[ ! " ${VALID_LEVELS[@]} " =~ " ${LOG_LEVEL} " ]]; then
  echo "Error: Invalid log level '$LOG_LEVEL'"
  echo "Valid levels: ${VALID_LEVELS[*]}"
  exit 1
fi

# Define important packages by group
declare -A PACKAGE_GROUPS=(
  ["myapp"]="com.mm_mk.Authentication"
  ["spring"]="org.springframework.security org.springframework.web org.springframework.boot org.springframework.transaction"
  ["security"]="org.springframework.security"
  ["database"]="org.hibernate.SQL org.hibernate.type.descriptor.sql org.springframework.jdbc.core"
  ["web"]="org.apache.tomcat org.apache.catalina"
  ["rabbitmq"]="org.springframework.amqp org.springframework.amqp.rabbit com.rabbitmq"
  ["all"]="com.mm_mk.Authentication org.springframework.security org.springframework.web org.springframework.boot org.springframework.transaction org.hibernate.SQL org.hibernate.type.descriptor.sql org.springframework.jdbc.core org.apache.tomcat org.apache.catalina org.springframework.amqp org.springframework.amqp.rabbit com.rabbitmq"
)

# Get packages for the selected group
if [[ -z "${PACKAGE_GROUPS[$GROUP]}" ]]; then
  echo "Error: Unknown package group '$GROUP'"
  echo "Available groups: ${!PACKAGE_GROUPS[@]}"
  exit 1
fi

PACKAGES=(${PACKAGE_GROUPS[$GROUP]})

echo "Setting log level to: $LOG_LEVEL"
echo "Target group: $GROUP"
echo "Packages: ${PACKAGES[*]}"
echo "=========================================="

SUCCESS_COUNT=0
TOTAL_COUNT=0

for package in "${PACKAGES[@]}"; do
    echo -n "Setting $package... "
    RESPONSE=$(curl -s -w "%{http_code}" -u "$USERNAME:$PASSWORD" -X POST "$BASE_URL/$package" \
      -H "Content-Type: application/json" \
      -d "{\"configuredLevel\":\"$LOG_LEVEL\"}")

    HTTP_CODE=${RESPONSE: -3}
    ((TOTAL_COUNT++))

    if [ "$HTTP_CODE" -eq 204 ]; then
        echo "✅"
        ((SUCCESS_COUNT++))
    elif [ "$HTTP_CODE" -eq 404 ]; then
        echo "⚠️  (Logger not found)"
    elif [ "$HTTP_CODE" -eq 401 ]; then
        echo "❌ (Unauthorized - check credentials)"
    else
        echo "❌ (HTTP $HTTP_CODE)"
    fi
done

echo "=========================================="
echo "✅ Updated $SUCCESS_COUNT/$TOTAL_COUNT packages to $LOG_LEVEL"
