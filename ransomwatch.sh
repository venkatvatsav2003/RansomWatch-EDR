#!/usr/bin/env bash

HONEYPOT_DIR="./honeypot"
ALERT_THRESHOLD=7.5
mkdir -p "$HONEYPOT_DIR"

echo "RansomWatch EDR"
echo "Monitoring: $HONEYPOT_DIR"
echo "Entropy threshold: $ALERT_THRESHOLD"
echo ""

declare -A seen

while true; do
    while IFS= read -r -d '' file; do
        mtime=$(stat -c "%Y" "$file" 2>/dev/null || echo "0")
        last=${seen[$file]:-0}
        if [ "$mtime" -gt "$last" ]; then
            seen[$file]=$mtime
            entropy=$(od -An -tu1 "$file" | awk '
                { for(i=1;i<=NF;i++) freq[$i]++; total++ }
                END {
                    if(total==0) exit;
                    for(k in freq) {
                        p=freq[k]/total;
                        if(p>0) e-=p*log(p)/log(2)
                    }
                    print e
                }')
            if [ "$(echo "$entropy > $ALERT_THRESHOLD" | bc -l 2>/dev/null)" -eq 1 ]; then
                echo "[ALERT] $file (entropy: $entropy) - Possible ransomware encryption!"
            elif [ "$(echo "$entropy > 0" | bc -l 2>/dev/null)" -eq 1 ]; then
                echo "[OK] $file (entropy: $entropy)"
            fi
        fi
    done < <(find "$HONEYPOT_DIR" -type f -print0 2>/dev/null)
    sleep 2
done
