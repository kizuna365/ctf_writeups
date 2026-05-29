#!/bin/bash
# 自分が書いた .py ファイル（pwntools パターンを含むもの）を git add する

set -e

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_ROOT"

echo "=== 自分が書いた .py ファイルを検索中 ==="

FILES=$(grep -rl "from pwn import \*" . --include="*.py" \
    | xargs grep -l "elf = context\.binary = ELF" 2>/dev/null \
    | sort)

if [ -z "$FILES" ]; then
    echo "対象ファイルが見つかりませんでした。"
    exit 0
fi

COUNT=$(echo "$FILES" | wc -l)
echo "対象: ${COUNT} ファイル"
echo ""
echo "$FILES"
echo ""

git add -f $FILES
git add .gitignore add_my_scripts.sh

echo ""
echo "=== ステージング完了 ==="
echo "git commit -m 'message' で commit してください"
