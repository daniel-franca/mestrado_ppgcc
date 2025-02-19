#!/bin/bash
#
## CSV separator
IFS=","
#
# OUTPUT
OUTPUT_CSV="results.csv"
#
# CSV Headers
echo "CVE,Distro,Package,Support,Resolved" > $OUTPUT_CSV \
## Get Ubuntu´s codename
ubuntu_codename=$(lsb_release -cs)
echo $ubuntu_codename
#
## Reading Ubuntu´s PRO CSV file and find dates from CVEs
while read f1 f2 f3 f4 f5
do
   if [[ $ubuntu_codename == $f2 ]]; then
      #Package
      echo $f3
      #Verson
      echo $f4
      apt install -y $f3
      resolved=$(zgrep -A 1000 -e "$f4" /usr/share/doc/$f3/changelog.Debian.gz |grep -e '-- ' | head -n 1 | cut -d ">" -f 2-)
      # Saving file
      echo $f1,$f2,$f3,$f4,$resolved >> $OUTPUT_CSV
   fi
done < ubuntu_pro.csv
