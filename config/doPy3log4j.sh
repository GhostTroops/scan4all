#!/bin/bash
# 请先安装好 python3、tmux
# brew install tmux
# brew install python3

tmux ls|grep "scan4all_log4j" || tmux new -s scan4all_log4j -d
tmux send -t "scan4all_log4j" "" Enter
tmux send -t "scan4all_log4j" "" Enter
tmux send -t "scan4all_log4j" "cd ${HOME}/MyWork/log4j-scan" Enter
tmux send -t "scan4all_log4j" "`which py3||which python3` --run-all-tests --waf-bypass --disable-http-redirects -u \"${1}\" --resulturl=\"$2\"" Enter
tmux send -t "scan4all_log4j" "" Enter
