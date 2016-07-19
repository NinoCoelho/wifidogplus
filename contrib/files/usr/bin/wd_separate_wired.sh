#! /bin/sh
# cjpthree add 20160314

insmod ebtables
insmod ebtable_broute
insmod ebt_mark

ebtables -t broute -D BROUTING -i eth2.1 -j mark --mark-set 1
ebtables -t broute -A BROUTING -i eth2.1 -j mark --mark-set 1

