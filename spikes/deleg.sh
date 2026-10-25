#!/bin/sh
# Run inside the sandbox. Each attempt asks something outside to write a marker
# file, which the jail itself cannot write; the harness checks the markers.
M=/Users/liamwisehart/mosjail-spike/markers
launchctl submit -l mj.submit -- /bin/sh -c "id > $M/submit" 2>&1 | sed 's/^/  submit: /'
cat > /dev/null <<X
X
launchctl bootstrap gui/501 $M/../mj.plist 2>&1 | sed 's/^/  bootstrap: /'
osascript -e "tell application \"System Events\" to do shell script \"id > $M/sysevents\"" 2>&1 | sed 's/^/  osascript: /'
open -g -j -a /System/Applications/Calculator.app 2>&1 | sed 's/^/  open: /'
mdfind -name probe.c 2>&1 | head -2 | sed 's/^/  mdfind: /'
echo jailed | pbcopy 2>&1 | sed 's/^/  pbcopy: /'
security find-generic-password -s nonexistent-mj 2>&1 | head -1 | sed 's/^/  security: /'
