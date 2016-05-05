
// SSH
- install openssh-server
- start service
- nano authorized_keys 
- paste ur public key there !! if pbK was with 
  Putty generated add 'ssh-rsa' before the key
-  chmod 600 ~/.ssh/authorized_keys 

$ echo "128.83.155.1 pluto.cns.utexas.edu" >> /etc/hosts
# fast way to write into file
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

//loging
$ less +F /var/log/messages
$ tail -50   -f /var/log/messages


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
# search for Files
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
# Fodler shortcut doesn't word with hardlink


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
# package manager dnf
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
$ pass auf when editing an interface that the DEVICE='interfacename'
- if(interfacename == "ifcfg-eno16777736") DEVICE=eno16777736
DEVICE=eno16777736
BOOTPROTO=dhcp
ONBOOT=yes
- after editing interface 
	-systemctl restart network.service




