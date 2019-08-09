#!/bin/sh

HeadCommit=`git rev-parse HEAD`
RCWHexDump=$HeadCommit"-HexDump"


find . -iname "*.bin" | sort > RCWBINs
find . -iname "*.bin.swapped" | sort >> RCWBINs

while read line
do
  echo "$line" >> $RCWHexDump
  hexdump -v $line >> $RCWHexDump
  echo "" >> $RCWHexDump
  echo "" >> $RCWHexDump
done < RCWBINs

rm -rf RCWBINs
