#!/bin/bash

URL="http://localhost:9000/actuator/loggers"
USERNAME="admin"
PASSWORD="admin123"

echo "Targeted Log Levels:"
echo "===================="

TARGET_PACKAGES=(
    "com.mm_mk.Authentication"
    "org.springframework.security"
    "org.springframework.web"
    "org.springframework.boot"
    "org.springframework.transaction"
    "org.hibernate.SQL"
    "org.hibernate.type.descriptor.sql"
    "org.springframework.jdbc.core"
    "org.apache.tomcat"
    "org.apache.catalina"
    "ROOT"
)

echo "PACKAGE".ljust\(40\) " | LEVEL"
echo "---------------------------------------- | -----"

for package in "${TARGET_PACKAGES[@]}"; do
    response=$(curl -s -u "$USERNAME:$PASSWORD" "$URL/$package")
    level=$(echo "$response" | grep -o '"configuredLevel":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$level" ]; then
        level="DEFAULT"
    fi

    printf "%-40s | %s\n" "$package" "$level"
done
