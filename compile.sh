#/bin/sh
echo "<<<------------[1]. START NDK-BUILD CLEAN--------------->>>" 
ndk-build clean

echo "<<<------------[2]. START NDK-BUILD--------------------->>>" 
ndk-build

echo "<<<------------[3]. START MV AMC To SmartPhone---------->>>" 
adb push /prog/pmamca/obj/local/armeabi/amca /data/local/tmp
