#!/bin/bash
#
# 运行所有256组模拟的调度脚本
# 用法: ./run_all_groups.sh [选项]
#
# 选项:
#   --num-groups N     组数 (默认: 256)
#   --nodes-per-group N 每组节点数 (默认: 4000)
#   --threshold N      门限阈值 (默认: 3400)
#   --block-hash HASH  区块哈希 (hex)
#   --parallel N       并行组数 (默认: 4)
#   --binary PATH      可执行文件路径 (默认: ../build/group_simulator)
#

set -euo pipefail

# 默认参数
NUM_GROUPS=256
NODES_PER_GROUP=4000
THRESHOLD=3400
BLOCK_HASH=""
PARALLEL=4
BINARY="../build/group_simulator"
OUTPUT_DIR="./output"

# 解析参数
while [[ $# -gt 0 ]]; do
    case "$1" in
        --num-groups)       NUM_GROUPS="$2"; shift 2 ;;
        --nodes-per-group)  NODES_PER_GROUP="$2"; shift 2 ;;
        --threshold)        THRESHOLD="$2"; shift 2 ;;
        --block-hash)       BLOCK_HASH="$2"; shift 2 ;;
        --parallel)         PARALLEL="$2"; shift 2 ;;
        --binary)           BINARY="$2"; shift 2 ;;
        --output-dir)       OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "用法: $0 [选项]"
            echo "  --num-groups N      组数 (默认: 256)"
            echo "  --nodes-per-group N 每组节点数 (默认: 4000)"
            echo "  --threshold N       门限阈值 (默认: 3400)"
            echo "  --block-hash HASH   区块哈希 (hex)"
            echo "  --parallel N        并行组数 (默认: 4)"
            echo "  --binary PATH       可执行文件路径"
            echo "  --output-dir DIR    输出目录 (默认: ./output)"
            exit 0
            ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
done

# 检查
if [ ! -f "$BINARY" ]; then
    echo "错误: 找不到可执行文件 $BINARY"
    echo "请先构建项目: cd .. && mkdir build && cd build && cmake .. && make"
    exit 1
fi

mkdir -p "$OUTPUT_DIR"

echo "=============================================="
echo "  百万节点签名方案 - 组模拟批量运行"
echo "=============================================="
echo "组数:          $NUM_GROUPS"
echo "每组节点数:    $NODES_PER_GROUP"
echo "门限阈值:      $THRESHOLD"
echo "并行度:        $PARALLEL"
echo "可执行文件:    $BINARY"
echo "输出目录:      $OUTPUT_DIR"
echo "=============================================="

START_TIME=$(date +%s)

# 构建批量命令
BATCH_CMD="$BINARY"
if [ -n "$BLOCK_HASH" ]; then
    BATCH_CMD="$BATCH_CMD --block-hash $BLOCK_HASH"
fi
BATCH_CMD="$BATCH_CMD --num-nodes $NODES_PER_GROUP --threshold $THRESHOLD"

# 使用 xargs 并行运行
run_group() {
    local gid=$1
    local log_file="$OUTPUT_DIR/group_${gid}.log"
    echo "[$(date '+%H:%M:%S')] 启动组 $gid ..."
    $BATCH_CMD --group-id "$gid" > "$log_file" 2>&1
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        echo "[$(date '+%H:%M:%S')] 组 $gid 失败 (exit=$exit_code)"
    else
        echo "[$(date '+%H:%M:%S')] 组 $gid 完成"
    fi
    return $exit_code
}

export -f run_group
export BATCH_CMD

# 生成组ID列表
seq 1 "$NUM_GROUPS" | xargs -P "$PARALLEL" -I {} bash -c 'run_group {}'

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo "=============================================="
echo "  批量运行完成"
echo "=============================================="
echo "总耗时: ${DURATION}s"
echo "输出目录: $OUTPUT_DIR"
echo "组日志数: $(ls "$OUTPUT_DIR"/group_*.log 2>/dev/null | wc -l)"
echo "=============================================="

# 统计成功率
SUCCESS_COUNT=$(grep -l "门限签名内验: 通过" "$OUTPUT_DIR"/group_*.log 2>/dev/null | wc -l)
echo "验签通过组数: $SUCCESS_COUNT / $NUM_GROUPS"
