## extended bash https://www.youtube.com/watch?v=uqHjc7hlqd0

##Debian

### SSH

#### on remote server
# install openssh-server
$ sudo apt install openssh-server
# start the ssh-server
$ sudo systemctl start ssh


#### on the client host
# ceate a ssh-key pair

$ ssh-keygen -t ed25519 -a 100
# or
$ ssh-keygen -t rsa -b 4096 -o -a 100
# push the public key to the server
$ ssh-copy-id -f -i <id_rsa.pub> <user>@<host> 


$ ssh-keygen -f "/home/ali/.ssh/known_hosts" -R <ipOfHost>
# remove the hash of Host key from known_hosts

# new fresh debian server
{
  - if .ssh folder not found -> ssh localhost
  - fastest way to copy public key is using mc -> Right -> Shell link
  - create first a user on the other server since remoting using root-user ist not possible
or
$ ssh-copy-id -f -i <id_rsa.pub> user@host
# public key must bi located in "id_rsa.pub"
# adds your ssh key to host for user to enable a keyed or passwordless login
$ grep <name> authorized_keys > id_rsa.pub
# exports  the lines with <name> into <id_rsa.pub>
}


## SSH agent
$ ssh-add ~/.ssh/id_rsa
# add a key to the agent
$ ssh-add -D
# remove all keys from agent

$ echo $BASH_VERSION
# displays bash version
$ echo $SHELL
# displays the shell you're using
$ lsb_release -a
# check ubuntu distribution version
$ cat /etc/os-release
# Operating System Info


$ pkill <pid>
# kill a process
$ .bashrc alias ll, alias rm freigeben
# ll for ls -l, rm -i for rm (rm -i : remove with bestätigung)
$ rm a*
# remove all files that begin with a
$ /bin/rm
# remove without confirmation
$ . ~/.bashrc um bashrc zu reloaden

## User Management
------------------
$ whoami
# tells which user
$ nano /etc/sudoers
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
$ vim /etc/hostname
# change hostname bzw user@<hostname>$ ;Domainname in windows
$ sudo userdel username
# To remove/delete a user (it's doesn't reomove user dir)
$ sudo rm -r /home/username
# delete the home directory for the deleted user account

$ getent passwd
# show  users
$ /etc/group
# list all unix groups

## Navigation
-------------
$ ctrl+shift+t
# open new Tab in Terminal
$ pwd
# show current directory
$ cd ..
# go back
$ cd -
# return to the last directory
$ cd /
# change directory to top level directory
$ ls -a
# lists all files, including hidden files
$ ls a*
# list all files that start with a*
$ ls a?3
# ? means any character
$ cp <path/To/My File> /media/Dir/.
$ cp myfile myfile-old
# ==
$ cp myfile{,-old}
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
$ ps -u <user>
# lists your processes on terminal
$ ps -uax
# list processes of all users beneath root
$ <cmd>&
# send cmd to background
$ kill -9 <pid>
# kill process for more see man kill
$ top
# displays your currently active processes
$pstree
# tree of active processes
$ export PATH=</my/path/>:$PATH
# add this line to .bashrc to add a path to $PATH variable inorder
# to execute scipts globally
$ unzip <file.zip> -d <destination_folder>

## Network
----------
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
### To configure a interface permanently you will need to edit the interfaces file, /etc/network/interfaces.
cat /sys/class/net/enp9s0/operstate
# show network adapter status
$ iw dev
# show wlan interfaces
$ sudo vi /etc/network/interfaces
{
### To configure a dynamic IP address
auto eth0
iface eth0 inet dhcp

### To configure a static IP
auto eth0
iface eth0 inet static
  address <192.168.1.14>
  gateway <192.168.0.1>
  netmask <255.255.255.0>
  dns-nameservers <192.168.0.1>

For these settings to take effect you need to restart your networking services.

sudo /etc/init.d/networking restart
}
-- Setting up DNS
$ sudo vi /etc/resolv.conf
{
search example.com					// what does search mainly do ?
domain example.com
nameserver <dns server ip>
}

$ nmcli dev status
# check if Network Manager is managing any network interfaces
$ nmcli connection modify <connection name> ipv4.addresses <192.168.1.10/24> ipv4.method <manual> ipv4.gateway <192.168.1.10>
# modify a Network interface
$ sudo systemctl stop NetworkManager.service
$ sudo systemctl disable NetworkManager.service
# disable Network Manager (Linux Desktop)

$ systemctl enable systemd-networkd
# enable networkd
$ nmblookup -S WORKGROUP
# lists available smb shares on a network
$ smbclient -L <server> -A <credentials-file>
# list all smb available on a server

$ whois <domain>
# gets whois information for domain
$ dig <domain>
# gets DNS information for domain
$ dig -x <host>
# reverses lookup host
$ nslookup <domain>
# gets DNS information for domain + used dns server to for lookup
$ wget <file>
# downloads file
$ route -n
# find gateway ip
$ ss
#
$ netstat
#
$ tcpdump -n -nn -i <netadapt> dst port 22
# check traffic on  port 22
$ tshark -i  <netadapt> -Y 'tcp.dstport==22'
# check traffic on port 22
$ hostname
#
$ traceroute <ip or dns name>
#
$ arp
#
$ lsof
# ps + netstat
$ netstat -tulpn 
# list opens ports

! sometime in a fresh installed system the default eth0 can be renames in another name
 - ifconfig -a # list all the adapter
 - look which on is the ethernet one and config the interface file with correspondingly

$ sudo nmap -sL 192.168.0.*
# search network for devices
## Remote
$ screen -S <sessionName>
# create a screen session
$ 'ctrl+A d' 
# to deattach from a session
$ screen -r <sessionName>
# to reattach
$ echo $STY
# check if in screen session


## System Info
--------------
$ who -H
# To see who is currently logged in to the Linux server,
$ last
# The last command tells us the login history of users
$ last reboot
# when was the system last rebooted
$ lastlog
# To see when did someone last log in to the system
$ lspci
# lists info about PCI  devices
$ lsusb
# lists info about USB devices
$ inxi -Fxz
# System info
$ systemd-analyze blame
# show processes on startup
$ systemd-analyze critical-chain <service>
# show subs of a service
$ service --status-all
# show status of all services

## logging
----------
$ less +F /var/log/messages
$ tail --lines=50 -F /var/log/messages
#mit dem Schalter -F (follow) wird die Ausgabe so lange kontinuierlich
#aktualisiert.Diese Funktion macht tail als Live-Monitor für sich laufend
#ändernde Dateien (z. B. Logs) geeignet.
--Default Log File Location--
$ ls -l /var/log

--The rsyslog Daemon--
$vim /etc/rsyslog.conf
# At the heart of the logging mechanism is the rsyslog daemon.
# This service is responsible for listening to log messages from
# different parts of a Linux system and routing the message to an
# appropriate log file in the /var/log directory. It can also forward
# log messages to another Linux server.
$ tail -500 -F /var/log/auth.log | grep 'sshd'
# logs of sshd on server
$ less /var/log/apt/term.log
# apt logs

## Disk
-------
$ lsblk
# list block devices
$ fdisk -l
# list disks
$ df
# shows disk usage
$ tree  /dev/disk/by-label/
# show label and name of mounted partitions
$ du -sh /*
# get size of each folder in .

## Flash to USB
---------------
$ lsblk
$ umount /dev/sd<?>
$ sudo dd bs=4M if=input.iso of=/dev/sd<?> status=progress conv=fdatasync

## Manipulate
-------------
$ touch "new file"
# creates empty file
$ service --status-all
# list of all Services if active or inactive
$ df -h
# free disk space
$ > <filename>
# clear file contents
$ rm "new file"
# remove "new file"
$ mkdir "new folder"
# create "new folder"
$ mkdir -p myProject/{src,doc,tools,db}
# create Parent directory with multiple subdirectories
$ rmdir "new folder"
# remove "new folder"
$ rm -rf "unempty directory"
# remove unempty directory
$ mv /home/user/<oldname> /home/user/<newname>
# rename directory
$ :> foo.txt
# Empty the contents of a file
{
$ ls
this_has_text_to_find_1.txt
this_has_text_to_find_2.txt

$ rename 's/text_to_find/been_renamed/' *.txt
$ ls
this_has_been_renamed_1.txt
this_has_been_renamed_2.txt
}

// mounting an USB Drive
1. Find what the drive is called

sudo fdisk -l

2. Create a mount point

Create a new directory in /media so you can mount the drive onto the filesystem:

sudo  mkdir /media/usb

3. Mount!

sudo mount /dev/sdb1 /media/usb

// mounting an smb drive
sudo mount -v -t cifs //<smb_drive_path> /media/<any_mount_name>/ -o credentials=<credentials_file_path>

// unmount busy smb drive
umount -l /PATH/OF/BUSY-DEVICE
umount -f /PATH/OF/BUSY-NFS(NETWORK-FILE-SYSTEM)

$ vim ~/.local/share/applications/<app>.desktop
# create a desktop starter for an app

$ ls -d *-Dateien *_files >> .hidden
# lists HTML Folder in .hidden file

// Certificate
### to import a certificate
    # Go to /usr/local/share/ca-certificates/
    cd /usr/local/share/ca-certificates/
    mkdir <dir-name>
    # Copy the .crt file into this directory
    #Make sure the permissions are OK (755 for the folder, 644 for the file)
    sudo update-ca-certificates
    
// search & display
-------------------
$ ctrl + shift + f
# search function in Terminal Ubuntu
$ grep
# serach for text in multiple Files can be pipelined with other commands
$ find
# search for Files (subtree)
$ find . -iname "*filename*"
# find recursive case insensitive
$ sudo find / -name ".DS_Store"  -exec rm {} \;
# find and delete
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
$ dpkg -L <package>
# show where package files installed
$ ls -i
# shows info. expl: inode hardlink
$ readlink -f <file>
# shows the path of a file
$ find | grep -i <String>
# search for a file within a folder

$ sudo update-alternatives --config java
# change java version in use
## Packages
-----------
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
$ sudo unattended-upgrades -d
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
$ dpkg --configure -a
# repair broken apt
$ wc -l *.{c}
# count the number of lines of all files that end with .c

## Link
-------
$ ln "file" "shortcut "
# create a hardlink (shortcut like Windows)
# same inode
$ ln -s "file" "softlink shortcut"
# create a softlink quasi a Pointer to the file
# different inode
$ ln -s "folder" "shortcut folder"
# create Folder- bzw Dir shortcut bzw softlink.
# Folder shortcut doesn't work with hardlink


## Permissions
--------------
$ chmod
# edit file permissions. to show Permissions ls -l
$ chmod +x "file name"
# sudo for file then can one ./"filename" without Problems
/ Interactive chmod
- http://www.user-archiv.de/chmod.html
$chown
# edit file owner
## Others
---------
---------
$ shutdown now
# shutdown instantly
$ shutdown -h +10
# shutdown in 10 min
$ service --status-all
# check status for multiple services
$ service "ssh" restart
# restarts service "ssh"


## GUI
---------
$ ~/.local/share/applications
$ /usr/share/applications
# remove links of apps from the list of open with

## Desktop
- X11: is a network protocol. It encodes things such as graphic primitives, images, pointer motion, and key presses.
- X-Windows: is a Unix/Linux Client-Server system. Although usually on the same computer, the Client and Server can be on different computers, unlike Microsoft Windows.
- Xorg: is an X server. It implements X11 and provides an interface to keyboards, mice, and video cards.

## Storage
### LVM
LVM stands for Logical Volume Management. It is a system of managing logical volumes, or filesystems, 
that is much more advanced and flexible than the traditional method of partitioning a disk into one or 
more segments and formatting that partition with a filesystem. 
### Why use LVM?
For a long time I wondered why anyone would want to use LVM when you can use gparted to resize and move partitions just fine. 
The answer is that lvm can do these things better, and some nifty new things that you just can not do otherwise. I will explain 
several tasks that lvm can do and why it does so better than other tools, then how to do them. First you should understand the basics of lvm. 
# see lvm.png
# Display information about volume groups
$ vgs
$ vgdisplay
# Display information about physical volumes
$ pvs
$ pvdisplay
# Display information about logical volumes
$ lvs
$ lvdisplay
### extend logical volume
# run lvdisplay to display the logical volume path
$ lvextend -L+<size|50G> <logical volume path>
$ resize2fs <logical volume path>
### lvm snapshot
#### create a snapshot 
$ lvcreate -L <size|5GB> -s -n  <snap_name> <logical volume path>
#### restore a snapshot
$ lvconvert --merge <logical volume path>
------- Fedora -------------
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

##logs
------
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
# to get GATEWAY : ip route show | grep via
}

$ hostnamectl set-hostname --static <hostname>		# set hostname

# nmcli
nmcli con show
nmcli connection edit "connection name"
nmcli> set ipv4.addresses <ip>/24
nmcli> set ipv4.gateway <gatewa>
nmcli> set ipv4.dns <dns1>,<dns2>
nmcli> set ipv4.dns-search <dom1>,<dom2>
nmcli> save
nmcli> quit

$ ifup >interface> 

----------- Bash -------------
$ cmd1 && cmd2
# run next cmd2 iff cmd1 execution ends up successfully
$ mkdir folder;cd folder
# ; run next command regardless of whether or not the first one succeeds.
$ cmd 1 || cmd2
# causes the next command to run if the previous command failed
$ set -e
# Any subsequent(*) commands which fail will cause the shell script to exit immediately
export DIRPATH = /home/dir
echo -e  "hello\nthis is a test"
# mit -e argument "\n" werden erkannt
echo "$DIRPATH"
set
# shows all enviroment variables
$ $(cat file)
$ `cat file`
# ähnlich wie $(< file) : $ zum ausführen

$ echo "128.83.155.1 pluto.cns.utexas.edu" >> /etc/hosts
# fast way to write into file
$ cat >> <file.txt> <<EOF
FooText
EOF
## () vs {}
If you want the side-effects of the command list to affect your current shell, use {list;}
If you want to discard any side-effects, use (list)

## bash patterns
## http://wiki.bash-hackers.org/syntax/pattern

*	    Matches any string, including the null string (empty string)
?	    Matches any single character
X	    Matches the character X which can be any character that has no special meaning
\X	    Matches the character X, where the characters special meaning is stripped by the backslash
\\	    Matches a backslash
[…]	    Defines a pattern bracket expression (see below). Matches any of the enclosed characters at this position.
---
[XYZ]	        The "normal" bracket expression, matching either X, Y or Z
[X-Z]	        A range expression: Matching all the characters from X to Y (your current locale, defines how the characters are sorted!)
'[[:class:]]'	Matches all the characters defined by a POSIX® character class: alnum, alpha, ascii, blank, cntrl, digit, graph, lower, print, punct, space, upper, word and xdigit
[^…]	A negating expression: It matches all the characters that are not in the bracket expression

: Pattern [Hh]"ello world" matches
    ⇒ Hello world
    ⇒ hello world
### Extended pattern language
*(<PATTERN-LIST>)	Matches zero or more occurrences of the given patterns
!(<PATTERN-LIST>)	Matches anything except one of the given patterns
$ rm -f !(survivior.txt)
# Delete all but one specific file 

## subshell
## https://unix.stackexchange.com/questions/442692/is-a-subshell
There are several other constructs that create a subshell. I think this is the full list for bash:
* Subshell for grouping: 
        ( … ) does nothing but create a subshell and wait for it to terminate). 
        Contrast with { … } which groups commands purely for syntactic purposes and does not create a subshell.
* Background: 
        … & creates a subshell and does not wait for it to terminate.
* Pipeline: 
        … | … creates two subshells, one for the left-hand side and one for the right-hand side, and waits for both to terminate. 
        The shell creates a pipe and connects the left-hand sides standard output to the write end of the pipe and the right-hand sides standard 
        input to the read end. In some shells (ksh88, ksh93, zsh, bash with the lastpipe option set and effective), the right-hand side runs 
        in the original shell, so the pipeline construct only creates one subshell.
* Command substitution: 
        $(…) (also spelled `…`) creates a subshell with its standard output set to a pipe, collects the output in the parent and expands to that 
        output, minus its trailing newlines. (And the output may be further subject to splitting and globbing, but that's another story.)'
* Process substitution: 
        <(…) creates a subshell with its standard output set to a pipe and expands to the name of the pipe. 
        The parent (or some other process) may open the pipe to communicate with the subshell. >(…) does the same but with the pipe on standard input.
* Coprocess: 
        coproc … creates a subshell and does not wait for it to terminate. The subshells standard input and output are each set to a 
        pipe with the parent being connected to the other end of each pipe.


## bash test
[[ expression ]]
valuate conditional expression with the "[[" keyword; 
word splitting is not performed. The righthand side of a string
comparison (==, !=) is treated as a pattern(see above) when not quoted,
and as a string when quoted.

[[ -n string ]]
string is non-empty
[[ -z string ]]
string is empty
[[ string1 == string2 ]]
string1 and string2 are the same
[[ string1 != string2 ]]
string1 and string2 are not the same
[[ string =~ regex ]]
string matches regular expression
[[ -e file ]]
file exists
[[ -f file ]]
file is a regular file
[[ -d file ]]
file is a directory
[[ -t fd ]]
fd is open and refers to a terminal
## bash special variables
$ $0
# name of the shell or shell script
$ $1,$2,$3
# Positional parameters, passed from command line to scripts
$ $#
# number of positional parameters $1,$2,$3
$ $@
# what positional parameters are passed (array like)
$ $?
# was last command successful. if 0 then yes (exit status)
$ $$
# process id of the script
$ $* 
# is the IFS(internal field separator) expansion of all positional parameters, $1 $2 $3 ....
$ $- 
# current options set for the shell.
$ $_ or "!$"
# most recent parameter (or the abs path of the command to start the current shell immediately after startup).
$ $IFS 
# is the (input) field separator. (echo "$IFS" | cat -A)
$ $! 
# is the PID of the most recent background command.
$ !$
# the "end" of the previous command

## Shell-Parameter-Expansion
## https://tiswww.case.edu/php/chet/bash/bashref.html#Shell-Parameter-Expansion

# ':-' is a  parameter expansion, it means if argument is null or unset, replace it with whats after 
$ echo ${x:-default}
default
$ echo $x

#Theres also another similar PE that assign the value if the variable is null:
$ echo ${x:=default}
default
$ echo $x
default

### for loop
#looping over parameter
input="$1"
for (( i = 1; i < ${#input}; i++ )); do
    char+=${!i}
done
# another way
for arg;do
    char1+=$arg
done

#loop over array
array=(5,6,7,8)
for i in ${array[@]}
do
    echo $i
done
#loop
for i in ${!prefix*}
do
    echo ${!i} # values of variables
done
# array length
echo ${#array[@]}

## String Ops
#### Substring Extraction
STRING="this is a string"
POS=0
LEN=3
echo ${STRING:$POS:$LEN} 

### Substring Replacement
#### Replace first occurrence of substring with replacement
STRING="to be or not to be"
echo ${STRING[@]//be/eat}        # to eat or not to eat
#### Replace all occurrences of substring
STRING="to be or not to be"
echo ${STRING[@]//be/eat}        # to eat or not to eat
#### more https://www.learnshell.org/en/Basic_String_Operations

--- File Descriptors
-- stdin 0 stdout 1 stderr 2
$ cmd > file
# Redirect the standard output (stdout) of cmd to a File.
$ cmd >> file
# Append (no overwrite) stdout of cmd to a File.
$ cmd 2> file
# Redirect the standard error (stderr) of cmd to a File. 2 is the default fd for stderr.
$ 3>&1
# Create a new file descriptor 3 and point it to the file descriptor 1 (stdout)

# foo=1, boo=2
$ echo "$fooboo"
# outputs fooboo
$ echo "${foo}boo"
# outputs 1boo
$ echo "${foo}${boo}"
# outputs 12



# interactive
read -rp "Domain to use: ($DOMAIN): " choice;
if [ "$choice" != "" ] ; then
	export DOMAIN="$choice";
fi
--------------sed-----------------------------------
sed 's/horse/dog/g' /dir/file
# replace horse with dof
# muss not be /
--------------RegEx---------------------------------
$ grep "foo" file.txt
# searches for foo in file.txt
$ grep "fo." file.txt
# . means any character
$ grep ^"foo" file.txt
# searches for lines that start with foo
$ grep $"foo" file.txt
# searches for lines that end with foo
$ grep ^"[ab]" file.txt
# searches for lines that start with a or b
$ grep ^"[ab][cd]" file.txt
# searches for lines that start with ac,ad,bc or bd
$ grep "[0-9]" file.txt
# searches for lines that contain any number from range 0 to 9
$ grep "[0-9][a-zA-Z]" file.txt
# searches for lines that contain any number from range 0 to 9 with a letter from a-z and A-Z
$ grep "[\]]" file.txt
# searches for lines that contain ']' character
$ grep -i "foo" file.txt
# ignor case foo or Foo
$ grep -- -<String>
# searches for a String that starts with '-'
$ grep -rni <String>
# search for a string within a Folder
