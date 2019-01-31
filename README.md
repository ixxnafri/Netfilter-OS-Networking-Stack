Markup :  ## lab_6 ##
Markup :  #### netfilter ####

1.5 - Building your own Lightweight Firewall in the Ubuntu Kernel. This firewall will provide three basic options for dropping packets. These are, in the order of processing:
* Source interface
* Destination IP address
* Destination TCP port

1. Open folder
2. Run “make”Command to enable the module
3. sudo insmod Firewall.koCommand to see output of the module
4. dmesg | tail

To close the module, use command
5.sudo rmmod Firewall


Section 
2A.Essentially in this part I decided to build a kernel module which calls a hook function on intercepted IP/TCP Packets which detects which TCP flags are set.

1. Open folder
2. Run “make”Command to enable the module
3. sudo insmod Question2.ko Command to see output of the module
4.dmesg | tail
5.sudo nmap -sX localhost - (Xmas Scan/SYN Scan/FIN Scan/NULL Scan)

To close the module, use command6.sudo rmmod Question2B.It is then detect the kind of scan being performed, and logs it in the kernel logs.

