#!/bin/bash
# ============================================================================
# Leader 节点监控脚本
# ============================================================================

LEADER_URL="${1:-http://localhost:9000}"

echo "========================================"
echo "  BLS Leader 节点监控"
echo "  URL: $LEADER_URL"
echo "========================================"

while true; do
    clear
    echo "===== $(date '+%Y-%m-%d %H:%M:%S') ====="

    # 公钥注册进度
    PUBKEY_RESP=$(curl -s "$LEADER_URL/pubkey_count" 2>/dev/null)
    echo "公钥注册: $PUBKEY_RESP"

    # 最新区块 hash
    HASH_RESP=$(curl -s "$LEADER_URL/latest_block_hash" 2>/dev/null)
    echo "最新区块: $HASH_RESP"

    # 已收集签名数
    COUNT_RESP=$(curl -s "$LEADER_URL/collected_count" 2>/dev/null)
    echo "收集签名: $COUNT_RESP"

    echo ""
    sleep 3
done
