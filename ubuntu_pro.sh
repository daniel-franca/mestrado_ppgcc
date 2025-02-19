#!/bin/bash
#
## CSV separator
IFS=","
#
# OUTPUT
OUTPUT_CSV="results.csv"
#
# CSV Headers
echo "CVE,Package,Distro,Support,MinDate,Resolved" > $OUTPUT_CSV \
## Get Ubuntu´s codename
ubuntu_codename=$(lsb_release -cs)
echo $ubuntu_codename
#
## Reading Ubuntu´s PRO CSV file and find dates from CVEs
while read f1 f2 f3 f4 f5
do
   if [[ $ubuntu_codename == $f2 ]]; then
      #Package
      echo $f1
      #Verson
      echo $f3
      apt install -y $f1
      resolved=$(zgrep -A 1000 -e "$f3" /usr/share/doc/$f1/changelog.Debian.gz |grep -e '-- ' | head -n 1 | cut -d ">" -f 2-)
      # Saving file
      echo $f5,$f1,$f2,$f3,$f4,$resolved >> $OUTPUT_CSV
   fi
done < ubuntu_pro.csv
