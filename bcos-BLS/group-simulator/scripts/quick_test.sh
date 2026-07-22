#!/bin/bash
#
# 小规模快速测试脚本 (用于验证代码正确性)
# 用法: ./quick_test.sh
#

set -euo pipefail

BINARY="${1:-../build/group_simulator}"

if [ ! -f "$BINARY" ]; then
    echo "错误: 找不到可执行文件 $BINARY"
    echo "请先构建: cd .. && mkdir build && cd build && cmake .. && make"
    exit 1
fi

echo "=============================================="
echo "  快速测试: 1组 × 100节点 × 85%门限"
echo "=============================================="

# 测试1: 小规模功能验证
echo ""
echo "=== Test 1: 100节点, 85门限, 10聚合器 ==="
"$BINARY" \
    --group-id 1 \
    --num-nodes 100 \
    --threshold 85 \
    --num-aggregators 10 \
    --block-hash "0xdeadbeefcafe0001"

# 测试2: 更小的规模，快速验证
echo ""
echo "=== Test 2: 20节点, 17门限, 4聚合器 ==="
"$BINARY" \
    --group-id 2 \
    --num-nodes 20 \
    --threshold 17 \
    --num-aggregators 4 \
    --block-hash "0xdeadbeefcafe0002"

# 测试3: 4000节点规模 (如果BLS库编译成功)
echo ""
echo "=== Test 3: 4000节点, 3400门限, 10聚合器 (全规模) ==="
"$BINARY" \
    --group-id 3 \
    --num-nodes 4000 \
    --threshold 3400 \
    --num-aggregators 10 \
    --block-hash "0xdeadbeefcafe0003"

echo ""
echo "=============================================="
echo "  测试完成"
echo "=============================================="
