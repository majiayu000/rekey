#!/bin/zsh
# usage: drive.sh TASK K
W=/private/tmp/claude-502/onecli.KqIT
source $W/prompts.sh
T=$1; K=$2; eval "P=\$P_$T"
D=$W/runs/$T-k$K; rm -rf $D; mkdir -p $D; cd $D
s=$(python3 -c 'import time;print(int(time.time()*1000))')
PATH=$W/agentbin:$PATH command claude -p --model sonnet --strict-mcp-config --mcp-config $W/empty-mcp.json \
  --allowedTools 'Bash(onecli *)' --max-turns 20 --output-format stream-json --verbose "$P" > $D/stream.jsonl 2> $D/stderr.txt
echo $? > $D/rc; e=$(python3 -c 'import time;print(int(time.time()*1000))'); echo $((e-s)) > $D/wall_ms
