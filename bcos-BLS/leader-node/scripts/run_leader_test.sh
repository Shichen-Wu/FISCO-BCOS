#!/bin/bash
set -euo pipefail

BINARY="../build/leader_node"
mkdir -p output

echo "=============================================="
echo "  Leader 节点 - 全规模测试 (256组)"
echo "=============================================="

"$BINARY" \
    --total-groups 256 \
    --min-threshold 205 \
    --block-hash "0xdeadbeefcafe0000000000000000000000000000000000000000000000000001" \
    --generate-test-data \
    --output-dir ./output \
    2>&1 | tee output/leader_run.log

echo ""
echo "日志已保存到 output/leader_run.log"
echo "公钥已保存到 output/group_pubkeys.json"
