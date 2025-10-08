make clean
make
echo "BUILD SUCCESS!"
curl -T ../../bin/plugins/prx_final/test2.prx ftp://192.168.0.106:2121/data/GoldHEN/plugins/test2.prx
