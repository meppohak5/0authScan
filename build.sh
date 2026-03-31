#!/usr/bin/env bash
# ============================================================
# build.sh — Build oauth-check-burp-extension.jar
# Author: Mayur Patil (meppo)
# ============================================================
set -e

SRC_DIR="src"
CLASS_DIR="classes"
JAR_NAME="oauth-check-burp-extension.jar"
SOURCES_FILE="/tmp/oauth_sources.txt"

echo "[*] Cleaning previous build..."
rm -rf "$CLASS_DIR"
mkdir -p "$CLASS_DIR"

echo "[*] Collecting source files..."
find "$SRC_DIR" -name "*.java" > "$SOURCES_FILE"
echo "    Found $(wc -l < "$SOURCES_FILE") source files"

echo "[*] Compiling..."
javac -source 11 -target 11 \
      -sourcepath "$SRC_DIR" \
      -d "$CLASS_DIR" \
      @"$SOURCES_FILE"

echo "[*] Packaging JAR..."
jar cfm "$JAR_NAME" manifest.mf -C "$CLASS_DIR" com/

echo ""
echo "✅  Build complete: $JAR_NAME ($(du -sh "$JAR_NAME" | cut -f1))"
echo ""
echo "    Load in Burp Suite:"
echo "    Extensions → Add → Java → select $JAR_NAME"
