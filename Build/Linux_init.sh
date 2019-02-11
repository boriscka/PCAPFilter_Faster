#sudo sysctl -w vm.nr_hugepages=1024
sudo $RTE_SDK/share/dpdk/tools/dpdk-devbind.py -s
sudo $RTE_SDK/share/dpdk/tools/dpdk-devbind.py --force --bind=igb_uio enp0s8
sudo $RTE_SDK/share/dpdk/tools/dpdk-devbind.py --force --bind=igb_uio enp0s9
sudo $RTE_SDK/share/dpdk/tools/dpdk-devbind.py -s
