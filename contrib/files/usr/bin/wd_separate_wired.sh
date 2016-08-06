#! /bin/sh
# cjpthree add 20160314

ebtables -t broute -D BROUTING -i eth2.1 -j mark --mark-set 1
rmmod ebt_mark
rmmod ebtable_broute
rmmod ebtables

insmod ebtables
insmod ebtable_broute
insmod ebt_mark

ebtables -t broute -A BROUTING -i eth2.1 -j mark --mark-set 1
