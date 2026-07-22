#!/bin/bash
# ============================================================================
# 组模拟器启动脚本 (每台 64 台机器上运行)
# 用法: ./start_group_simulators.sh <机器编号: 1-64> <Leader IP:Port>
#
# 分片方案: 机器 N 负责组 (4N-3) 到 (4N)
#   机器 1  → 组 1, 2, 3, 4
#   机器 2  → 组 5, 6, 7, 8
#   ...
#   机器 64 → 组 253, 254, 255, 256
#
# 每个组模拟器进程:
#   - 4000 个模拟签名节点
#   - 门限阈值 3400 (85%)
#   - 10 个聚合器
# ============================================================================

set -e

MACHINE_ID=${1:?请指定机器编号 (1-64)}
LEADER_HOST=${2:?请指定Leader地址 (格式: IP:Port)}

# 解析 Leader 地址
LEADER_IP=$(echo "$LEADER_HOST" | cut -d: -f1)
LEADER_PORT=$(echo "$LEADER_HOST" | cut -d: -f2)

BASE_GROUP=$(( (MACHINE_ID - 1) * 4 + 1 ))
SIMULATOR_BIN="${SCRIPT_DIR:-./build}/group_simulator"
LOG_DIR="${LOG_DIR:-./logs}"

mkdir -p "$LOG_DIR"

echo "========================================"
echo "  BLS 组模拟器启动脚本"
echo "========================================"
echo "机器编号:     $MACHINE_ID"
echo "Leader地址:   $LEADER_IP:$LEADER_PORT"
echo "负责组:       $BASE_GROUP ~ $((BASE_GROUP + 3))"
echo "可执行文件:   $SIMULATOR_BIN"
echo "日志目录:     $LOG_DIR"
echo "========================================"

# 检查可执行文件
if [ ! -f group_simulator ]; then
    echo "错误: 当前目录下未找到 group_simulator 文件"
    exit 1
fi

# 参数说明:
#   --network-mode        启用 HTTP 网络通信
#   --group-id N          组 ID
#   --num-nodes 4000      组内模拟节点数
#   --threshold 3400      门限阈值 (85%)
#   --num-aggregators 10  聚合器数量
#   --leader-address IP   Leader HTTP 服务器地址
#   --leader-port PORT    Leader HTTP 服务器端口

for i in 0 1 2 3; do
    GID=$((BASE_GROUP + i))
    LOG_FILE="$LOG_DIR/group_${GID}.log"

    echo "  启动组 $GID ..."

    nohup ./group_simulator \
        --network-mode \
        --group-id "$GID" \
        --num-nodes 4000 \
        --threshold 3400 \
        --num-aggregators 10 \
        --leader-address "$LEADER_IP" \
        --leader-port "$LEADER_PORT" \
        > "$LOG_FILE" 2>&1 &

    echo "    PID: $! (日志: $LOG_FILE)"

    # stagger startup slightly to avoid thundering herd on DKG
    sleep 1
done

echo ""
echo "机器 $MACHINE_ID 启动完成"
echo "查看日志: tail -f $LOG_DIR/group_*.log"
