for file in *; do
   echo; echo
   echo "[+] Processing: $file"
   r2 -e scr.color=0 -A -q -c 'afl' "$file" | awk '{print $1, "$file!"$4}' > "zout/$file.txt"
done
