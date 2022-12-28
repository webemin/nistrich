#! /bin/bash

declare -i arg_count=0

while getopts 'hil:' OPTION; do
  case "$OPTION" in
    h)
      echo "-h for help"
      echo "-i for only one ip address"
      echo "-l for ip list"
      arg_count=$(( arg_count + 1 ))
      exit
      ;;
    i)
      echo $2 | nrich - -o json | cat >> ./sc/output.json
      arg_count=$(( arg_count + 1 ))
      if ! [ $arg_count -eq 1 ]; then echo "One argument expected. For help -h"; exit; fi
      ;;
    l)
      nrich -o json $2 | cat >> ./sc/output.json
      arg_count=$(( arg_count + 1 ))
      if ! [ $arg_count -eq 1 ]; then echo "One argument expected. For help -h"; exit; fi
      ;;
    ?)
      echo "example script usage: ./nishtrich -l <iplist.txt>" >&2
      exit
      ;;
  esac

done
shift "$(($OPTIND -1))"

sleep 1
cd sc
python3 nistrich.py
sleep 1
mv output.json ../files
mv cve_ip_list.txt ../files
mv *.csv ../results
