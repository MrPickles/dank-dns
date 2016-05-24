#!/bin/bash

rep=( cpmd hkcn nyny sekr sewa )

for r in "${rep[@]}"
do
  for i in {1..2}
  do 
    ./qps.js -s 2016-03-07 -e 2016-03-08 -i 60 -r $r
    echo "--- $i of $r ---"
  done
done
