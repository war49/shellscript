#!/bin/bash
# Suwardi
# suwardi.suwardi@btpnsyariah.com
# war49.a0001.net
# 
# Hardening Assessment 

# Cek program argumen, program butuh 1 argumen hostname/ip address dari target hardening 
if [ -z "$1" ]; then
  echo "Usage: $0 <hostname atau ip target hardening>"
  exit 1
fi

# Cek apakah user memiliki priviledge menggunakan sudo
if [ sudo -l > /dev/null 2>&1 ]; then
    echo "User: $(whoami) memiliki sudo privilege."
else
    echo "User: $(whoami) Tidak memiliki sudo privilege."
    #exit 1
fi

# Hostname/ip address target hardening
HOST="$1"

# SSH ke target server
#ssh_output=$(ssh "$HOST" << 'EOF'

echo "===== Collect Informasi System ====="
echo
echo "Server hostname : `hostname`"
echo "BTPN Syariah OS Asset Assessment"

# Gali informasi release OS
IS_RHEL=0
IS_UBUNTU=0
IS_OTHER_SYSTEM=0

printf "\n\n ---> OS RELEASE :"
if [ -f /etc/redhat-release ]; then
    echo "Redhat family detected!"
    cat /etc/redhat-release
    IS_RHEL=1
elif [ -f /etc/lsb-release ]; then
    echo "Debian family detected"
    lsb_release -a
    IS_UBUNTU=1
else
    echo "Other linux system detected"
    uname -a
    IS_OTHER_LINUX=1
fi

# Kernel arsitektur 
printf "\n\n ---> Info kernel & arsitektur\n"
uname -r && uname -m

# Cek file system
printf "\n\n ---> FILE SYSTEMS CHECK"
echo "-------> cramfs freevfs jffs2 hfs hfsplus squashfs udf vfat"

for fs in cramfs freevfs jffs2 hfs hfsplus squashfs udf vfat; 
do
  if lsmod | grep $fs; then 
      echo "Loaded module file system $fs"
  else
      echo "Tidak ada module file system $fs yang diload"
  fi
done

# Mount file system parameters check
printf "\n ---> Mounting check"
printf "\n -------> Mounting file system berisi nosuid, nodev, noexec\n"
mount | grep -E '(nosuid|nodev|noexec)'

printf "\n -------> Mounting file system TIDAK berisi nosuid, nodev, noexec\n"
mount | grep -v '(nosuid|nodev|noexec)'

# PAM config check
printf "\n\n ---> Linux PAM config check"
echo "------> Cek minimum password lenght"
grep "minlen" /etc/security/pwquality.conf

printf "\n -----> Cek password age"
cat /etc/shadow | cut -d':' -f5

printf "\n ------> Cek enforce password history"
grep "remember" /etc/pam.d/common-password

printf "\n -----> Cek password complexity"
grep "obscure" /etc/pam.d/common-password

printf "\n -----> Cek MD5 crypt"
grep "md5" /etc/pam.d/common-password

printf "\n ----> Cek unlock time"
grep "unlock_time" /etc/security/faillock.conf

printf "\n -----> Cek config deny di faillock"
grep "deny" /etc/security/faillock.conf

printf "\n ----> Cek no_reset di faillock"
grep "no_reset" /etc/security/faillock.conf

# Check user priviledge
printf "\n\n---> Check user access control\n"
for USER in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd); 
do
    echo "User: $USER"
    sudo -lU $USER
    echo "User info: `grep $USER /etc/passwd`"
    echo "Group info: `grep $USER /etc/group`"
    echo "----"
done

# Cek konfigurasi config
#echo "---> Check Audit configuration"
#auditctl -l
#grep "root" /var/log/audit/audit.log

# Cek Bootloader security
echo "---> Check Bootloader GRUB security"
GRUB_CFG=/boot/grub2/grub.cfg

if [ -z $GRUB_CFG ]; then
    grep "^password" $GRUB_CFG
    stat $GRUB_CFG
else
    echo "Tidak ada file config $GRUB_CFG"
fi

# Cek Kernel network parameter
echo "---> Cek kernel network parameter"
sysctl net.ipv4.icmp_echo_ignore_broadcasts
sysctl net.ipv4.icmp_ignore_bogus_error_responses
sysctl net.ipv4.tcp_syncookies
sysctl net.ipv4.conf.all.log_martians
sysctl net.ipv4.conf.default.log_martians
sysctl net.ipv4.conf.all.accept_source_route
sysctl net.ipv4.conf.default.accept_source_route
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
sysctl net.ipv4.conf.all.accept_redirects
sysctl net.ipv4.conf.default.accept_redirects
sysctl net.ipv4.conf.all.secure_redirects
sysctl net.ipv4.conf.default.secure_redirects
sysctl net.ipv4.ip_forward
sysctl net.ipv4.conf.all.send_redirects

# Module USB & Wireless
echo "---> Module USB & Wireless check"
lsmod | grep usb
lsmod | grep wireless

# Cek Status Service
echo "---> Cek status service Xinet"
SERVICES=("anacron" "apmd" "avahi-daemon" "bluetooth" "cups" "dhcpd" "named" "vsftpd" "httpd" "ntpd" "sshd" "amanda" "amandaidx" "amidxtape" "auth" "chargen-dgram" "chargen-stream" "cvs" "daytime-dgram" "daytime-stream" "discard-dgram" "discard-stream" "echo-dgram" "echo-stream" "eklogin" "ekrb5-telnet" "gssftp" "klogin" "kshell" "ktalk" "ntalk" "rexec" "rlogin" "rsh" "rsync" "talk" "tcpmux-server" "telnet" "tftp" "time-dgram" "time-stream" "uucp")

for service in "${services[@]}"; 
do
    SV_STATUS_RHEL=$(sudo systemctl is-active --quiet "$SERVICES" 2>/dev/null)
    SV_STATUS_UBUNTU=$(sudo initctl status "$SERVICES" 2>/dev/null)
    
    if [[ $IS_RHEL == 1 ]]; then
        if [[ "$SV_STATUS_RHEL" == *"active"* ]]; then 
           echo "--> Service: $SV_STATUS_RHEL active/running"
        elif [[ "$SV_STATUS_RHEL" == *"inactive"* ]]; then 
            echo "--> Service: $SV_STATUS_RHEL stop/die"
        else
            echo "---> Service: $SV_STATUS_RHEL tidak direcognize!"
        fi 
    elif [[ $IS_UBUNTU == 1 ]]; then 
        if [[ "$SV_STATUS_UBUNTU" == *"start/running"* ]]; then 
            echo "--> Service: $SV_STATUS_UBUNTU start/running"
        elif [[ "$SV_STATUS_UBUNTU" == *"stop/waiting"* ]]; then 
            echo "--> Service: $SV_STATUS_UBUNTU stop/waiting"
        else 
            echo "---> Service: $SV_STATUS_UBUNTU tidak direcognize!"
        fi
    elif [[ $IS_OTHER_LINUX == 1 ]]
        echo "===> Other linux system"
        echo "----> Skip check"
    fi
done

# TCP wrapper
printf "\n\n ---> Cek TCP Wrapper"
HOST_ALLOW=/etc/hosts.allow
HOST_DENY=/etc/hosts.deny

echo "---> Cek tcpd & tcp_wrapper apakah terinstall?"
dpkg -l | grep tcpd || rpm -qa | grep tcp_wrappers

echo "---> Capture baris file config TCP_Wrapper yang diaktifkan"
grep -v '^\s*#' "$HOST_ALLOW" | grep -v '^\s*$'
grep -v '^\s*#' "$HOST_DENY" | grep -v '^\s*$'


# SSH config
printf "\n\n ---> Cek config SSH"
grep "PermitRootLogin" /etc/ssh/sshd_config
grep "Protocol" /etc/ssh/sshd_config
grep "AllowGroups" /etc/ssh/sshd_config
grep "AllowUsers" /etc/ssh/sshd_config
grep "PermitTunnel" /etc/ssh/sshd_config
grep "X11Forwarding" /etc/ssh/sshd_config
grep "ClientAliveInterval" /etc/ssh/sshd_config
grep "LogLevel" /etc/ssh/sshd_config
grep "Ciphers" /etc/ssh/sshd_config

# Redhat subscription
printf "\n\n ---> Cek status RHEL Subscription"
if command -v subscription-manager &> /dev/null; then
    subscription-manager identity
fi

# Cek integrity
printf "\n\n ---> Cek integrity & AIDE terinstall"
SERVICES="aide"
AIDE_STATUS_RHEL=$(sudo systemctl is-active --quiet "$SERVICES" 2>/dev/null)
AIDE_STATUS_UBUNTU=$(sudo initctl status "$SERVICES" 2>/dev/null)

# Cek aide di Ubuntu
if dpkg -l | grep -q $SERVICES; then
    echo "AIDE terinstall"
    echo "--> Cek $SERVICES di penjadwalan Cron"
    crontab -l | grep $SERVICES
    
    if [[ "$AIDE_STATUS_UBUNTU" == *"start/running"* ]]; then
        echo "==> Service $SERVICES start/running"
    else 
        echo "==> Service $SERVICES stop/die"
    fi  
else
    echo "$SERVICES is NOT installed"
fi

# Cek aide di RHEL
if rpm -q $SERVICES &> /dev/null; then
    echo "AIDE terinstall"
    echo "--> Cek $SERVICES di penjadwalan Cron"
    crontab -l | grep $SERVICES

    if [[ "$AIDE_STATUS_RHEL" == *"active"* ]]; then 
        echo "--> Service: $SERVICES active/running"
    else 
         echo "--> Service: $SERVICES inactive/die"
    fi

else
    echo "--> Service: $SERVICES iS NOT installed"
fi
    
# Coredump
printf "\n\n ---> Cek batasan coredump"
cat /proc/sys/kernel/core_pattern

# SELinux
printf "\n\n ---> Cek status Selinux"
echo "---> Selinux status"
sestatus
echo "Enforce status: `getenforce`"

# Firewall/iptables 
printf "\n\n ---> Check firewall"
iptables -L

# Permission ke file sensitif
printf "\n\n ---> Sensi file permission info"
stat /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-

#EOF
#)

# Outputnya
#echo "$ssh_output"

#EOF



