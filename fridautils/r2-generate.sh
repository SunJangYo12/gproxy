for file in *; do
   echo; echo
   echo "[+] Processing: $file"
   r2 -e scr.color=0 -A -q -c 'afl' "$file" | awk -v f="$file" '{print $1, f"!"$4}' > "zout/$file.txt"
done
