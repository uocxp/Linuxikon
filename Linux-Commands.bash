
// SSH
- install openssh-server
- start service
- nano authorized_keys 
- paste ur public key there !! if pbK was with 
  Putty generated add 'ssh-rsa' before the key
{
$ ssh-copy-id user@host 
# adds your ssh key to host for user to enable a keyed or passwordless login
||
$ grep <name> authorized_keys > name.pub			
# exports  the lines with <name> into <name.pub>   
}
-  chmod 600 ~/.ssh/authorized_keys   
  
  

echo $BASH_VERSION 
# displays bash version

$ echo $SHELL 
# displays the shell you're using

$ lsb_release -a
# check ubuntu distribution version



$ pkill <pid>
# kill a process
$ .bashrc alias ll, alias rm freigeben
# ll for ls -l, rm -i for rm (rm -i : remove with bestätigung)
$ rm *a 
# remove all files that begin with a
$ /bin/rm 
# remove without bestätigung
$ . ~/.bashrc um bashrc zu relaoden

// User Management
$ whoami
# tells which user 
$ cd /etc/sudoers
# sudoers file
- 
$ sudo adduser "user"
# add a user
- after adding a "new user", the new user doesnt have sudo authorization 
- to add "new user" to sudoers :
{
$ sudo nano /etc/sudoers
## Allow root to run any commands anywhere 
root	ALL=(ALL) 	ALL
"new user"	ALL=(ALL) 	ALL 
}
$ cd /etc/hostname
# change hostname bzw user@<hostname>$
$ sudo userdel username
# To remove/delete a user (it's doesn't reomove user dir)
$ sudo rm -r /home/username
# delete the home directory for the deleted user account


// Navigation

$ ctrl+shift+t
# open new Tab in Terminal
$ pwd
# show current directory
$ cd ..
# go back
$ cd -
# return to the last directory
$ ls -a 
# lists all files, including hidden files
$ ls a*
# list all files that stats with a*
$ls a?3
# ? means any character
$ cp "path/To/My File" /media/Dir/. 
$ mv "path/To/My File" /media/Dir/. 
# Copy/cut single file.
$ cp -r "path/To/My Dir" /media/Dir/. 
$ mv "path/To/My Dir" /media/Dir/. 
# Copy/cut a whole Directory (=Folder).
$ cp "path/To/My File 1" "path/To/My File 2" /media/Dir/. 
$ mv "path/To/My File 1" "path/To/My File 2" /media/Dir/. 
# Copy/cut two files.
$ shift + Bild oben
# scroll in the Terminal
$ ctrl + u 
# delete whole line on Terminal
$ ctrl + y
# undo delete 
$ alt + .
# paste last word
$ ps -u yourusername 
# lists your processes
$ top 
# displays your currently active processes

// Network
# edit
$ ip -a
# show all ip address associated on on all network interfaces
$ sudo ip link set dev eth0 down
# deaktive interface eth0
$ sudo dhclient eth0
# run eth0 with a dynamic ip bzw dhcp
$ sudo ip link set dev eth0 up
# activate interface eth0
$ ip a add {ip_addr/mask} dev {interface}
# Assigns the IP address to the interface
## ip a add 192.168.1.200/24 dev eth0
$ sudo ip route add default via <ip>
# assigns default gateway
## sudo ip route add default via 192.168.1.1
$ ip a show eth0
# Only show eth0 interface 
### these these changes will not survive a reboot, since the information is not stored anyhwere
### To configure a interface permanently you'll need to edit the interfaces file, /etc/network/interfaces.
$ sudo vi /etc/network/interfaces
{
## To configure a dynamic IP address
auto eth0
iface eth0 inet dhcp

## Or configure a static IP
auto eth0
iface eth0 inet static
  address 192.168.1.14
  gateway 192.168.1.1
  netmask 255.255.255.0
  network 192.168.1.0
  broadcast 192.168.1.255

For these settings to take effect you need to restart your networking services.

sudo /etc/init.d/networking restart
} 
-- Setting up DNS
$ sudo vi /etc/resolv.conf
{
search example.com
domain example.com
nameserver <dns server ip>
}

$ whois <domain>           
# gets whois information for domain
$ dig <domain>             
# gets DNS information for domain
$ dig -x <host>            
# reverses lookup host
$ wget <file> 
# downloads file
$ ss
#
$ netstat
# 
$ tcpdump
#
$ hostname
#
$ traceroute <ip or dns name>
#


// System Info
$ who
# To see who is currently logged in to the Linux server,
$ last
# The last command tells us the login history of users
$ last reboot 
# when was the system last rebooted
$ lastlog 
# To see when did someone last log in to the system

// logging
$ less +F /var/log/messages
$ tail -50 -f /var/log/messages
#mit dem Schalter -f (follow) wird die Ausgabe so lange kontinuierlich 
#aktualisiert.Diese Funktion macht tail als Live-Monitor für sich laufend 
#ändernde Dateien (z. B. Logs) geeignet.
--Default Log File Location--
$ ls -l /var/log   

--The rsyslog Daemon--
$cat /etc/rsyslog.conf
# At the heart of the logging mechanism is the rsyslog daemon.
# This service is responsible for listening to log messages from
# different parts of a Linux system and routing the message to an
# appropriate log file in the /var/log directory. It can also forward
# log messages to another Linux server.
//Disk
$ lsblk
# list blocks
$ fdisk -l
# list disks
$ df
# shows disk usage 

// manipulate
$ touch "new file"
# creates empty file

$ service --status-all
# list of all Services if active or inactive
$ df -h
# free disk space


$ rm "new file"
# remove "new file"
$ mkdir "new folder"
# create "new folder"
$ rmdir "new folder"
# remove "new folder"
$ rm -rf "unempty directory"
# remove unempty directory
$ mv /home/user/<oldname> /home/user/<newname>
# rename directory

// search & display
$ ctrl + shift + f
# search function in Terminal Ubuntu
$ grep
# serach for text in multiple Files can be pipelined with other commands
$ find 
# search for Files (subtree)
$ locate
# search in locate datenbank
$ more
# show file contents from top then scroll down can be pipelined
# exp with ps (ps -ef | more)
$ less
# show file contents from top then scroll down & up can be pipelined
$ cat
# display file contents. Prefered pipelined with | more or less
$ apt-cache search "keyword"
# search for a package in Repo
$ dpkg -l
# List all packages	
$ ls -i
# shows info. expl: inode hardlink  

// Packages
$ nano /etc/apt/sources.list
# edit packetquellen
$ apt-get  update 
# update packages information
$ apt-get upgrade
# update installed packages
$ apt-get upgrade --dry-run
# shows what will be updated without really updating
# works too for apt-get install
$ apt-get install unattended-upgrades
# installs security updates only 	
$ apt-get dist-upgrade
# upgrades linux distribution version
$ apt-get remove "package"
# uninstall program belässt aber die konfiguration
$ apt-get purge "package"
# uninstall program and remove configuration
$ apt-get autoremove
# remove unpacked packages from the cache
$ apt-cache search "keyword"
# search for a package in Repo
$ dpkg -l
# List all packages
$ chmod +x "file name"
# sudo for file then can one ./"filename" without Problems



// Link
$ ln "file" "shortcut "
# create a hardlink (shortcut like Windows)
# same inode
$ ln -s "file" "softlink shortcut"
# create a softlink quasi a Pointer to the file
# different inode
$ ln -s "folder" "shortcut folder"	
# create Folder- bzw Dir shortcut bzw softlink.
# Folder shortcut doesn't work with hardlink


// Permissions
$ chmod 					
# edit file permissions. to show Permissions ls -l
$ chmod +x "file name"		
# sudo for file then can one ./"filename" without Problems

// Others
$ shutdown -h +10			
# shutdown in 10 min
$ service --status-all		
# check status for multiple services
$ service "ssh" restart		
# restarts service "ssh"


--------- Fedora -------------
$hostnamectrl status				
# info about client
$ dnf update
$ dnf search <package>
$ dnf remove <package>
cd /etc/yum.repos.d/			
# repo directory
$ systemctl start sshd			
# start openssh server
$ systemctl status "service"		
# checks if service on
//logs
$ journalctl -r /usr/sbin/sshd 
$ journalctl -e /var/log			
# ssh logs 

$ cd /etc/sysconfig/network-scripts/	
# network insterfaces fedora
$ what out when editing an interface that the DEVICE = 'interfacename'
- if(interfacename == "ifcfg-eno16777736") DEVICE=eno16777736
DEVICE=eno16777736
BOOTPROTO=dhcp
ONBOOT=yes
- after editing interface 
	-systemctl restart network.service
$ static ip
{
DEVICE=eno16777736
BOOTPROTO="static"
ONBOOT="yes"
IPADDR=<192.168.0.200>
NETMASK=<255.255.255.0>
GATEWAY=<192.168.0.1>
}
$ hostnamectl set-hostname --static <hostname>		# set hostname

----------- Bash -------------
$ echo "128.83.155.1 pluto.cns.utexas.edu" >> /etc/hosts		
# fast way to write into file
$ cmd > file 													
# Redirect the standard output (stdout) of cmd to a File.
$ cmd >> file													
# Append (no overwrite) stdout of cmd to a File.
$ cmd 2> file 													
# Redirect the standard error (stderr) of cmd to a File. 2 is the default fd for stderr.
