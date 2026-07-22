#!/bin/bash
# ============================================================================
# Batch deployment: distribute group_simulator to 64 machines and start
#
# Prerequisites:
#   1. group_simulator binary built at group-simulator/build/group_simulator
#   2. 64 machine IPs listed in machines.txt (one per line)
#   3. SSH password-less login configured to all 64 machines
#   4. Leader node already running (note its public IP)
#
# Usage: ./deploy_groups.sh <Leader IP> [Leader Port]
# ============================================================================
set -euo pipefail

LEADER_IP=${1:?Usage: $0 <Leader IP> [Leader Port]}
LEADER_PORT=${2:-9000}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SIMULATOR_BIN="$SCRIPT_DIR/../group-simulator/build/group_simulator"
MACHINES_FILE="$SCRIPT_DIR/machines.txt"
REMOTE_DIR="/opt/bls-group"

[ -f "$SIMULATOR_BIN" ] || { echo "Error: $SIMULATOR_BIN not found"; exit 1; }
[ -f "$MACHINES_FILE" ] || { echo "Error: $MACHINES_FILE not found"; exit 1; }

TOTAL=$(wc -l < "$MACHINES_FILE" | tr -d ' ')
echo "Leader: $LEADER_IP:$LEADER_PORT, Machines: $TOTAL"
echo "[Step 1] Distributing files..."

MACHINE_NUM=0
while IFS= read -r host; do
    [ -z "$host" ] && continue
    MACHINE_NUM=$((MACHINE_NUM + 1))
    echo "  machine $MACHINE_NUM ($host)..."
    ssh "$host" "mkdir -p $REMOTE_DIR/logs" 2>/dev/null || continue
    scp -q "$SIMULATOR_BIN" "$SCRIPT_DIR/start_group_simulators.sh" "$host:$REMOTE_DIR/" 2>/dev/null
    ssh "$host" "chmod +x $REMOTE_DIR/group_simulator $REMOTE_DIR/start_group_simulators.sh" 2>/dev/null
done < "$MACHINES_FILE"

echo "[Step 2] Starting group simulators..."
MACHINE_NUM=0
while IFS= read -r host; do
    [ -z "$host" ] && continue
    MACHINE_NUM=$((MACHINE_NUM + 1))
    ssh "$host" "cd $REMOTE_DIR && nohup bash start_group_simulators.sh $MACHINE_NUM $LEADER_IP:$LEADER_PORT &> /dev/null" 2>/dev/null &
    sleep 1
done < "$MACHINES_FILE"
wait

echo "Done. Monitor: watch -n 3 'curl -s http://$LEADER_IP:$LEADER_PORT/pubkey_count'"
