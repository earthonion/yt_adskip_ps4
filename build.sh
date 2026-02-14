make clean
make
echo "BUILD SUCCESS!"
curl -T ../../bin/plugins/prx_final/yt_adblock.prx ftp://192.168.0.106:2121/data/GoldHEN/plugins/yt_adblock.prx
curl -T inject.js ftp://192.168.0.106:2121/data/inject.js
