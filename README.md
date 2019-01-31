# lab_6
netfilter
1.5 - Building your own Lightweight Firewall in the Ubuntu Kernel. This firewall will provide three basic options for dropping packets. These are, in the order of processing:
* Source interface
* Destination IP address
* Destination TCP port

1.Open folder
2.Run “make”Command to enable the module
3. sudo insmod Firewall.koCommand to see output of the module
4.dmesg | tail

To close the module, use command
5.sudo rmmod Firewall


