#!/bin/bash

# This script shows sample usage for running QPS with the given js scripts.
# You can also choose to run these as NPM scripts.

rep=( cpmd hkcn nyny sekr sewa )

for r in "${rep[@]}"
do
  for i in {1..2}
  do 
    node qps.js -s 2016-03-07 -e 2016-03-08 -i 60 -r $r
    echo "--- $i of $r ---"
  done
done
