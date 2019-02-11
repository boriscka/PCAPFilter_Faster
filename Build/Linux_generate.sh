repdir=$PWD
mkdir ../bin
cd ../bin
cmake $repdir -DCMAKE_BUILD_TYPE=Release
make -j 6
