#!/bin/bash
#
# Hardening tools
# Suwardi
# URL: war49.a0001.net
#

# Petunjuk penggunaan program
usage() {
    echo "Usage: $0 [options]"
    echo "Option:"
    echo "  -u, --user  <ssh-user>      Username untuk koneksi SSH"
    echo "  -t, --target	<target-host>   Target server yang diharden"
    echo "  -o, --output        <file output>   Output file"
    echo "  -h, --help		Petunjuk penggunaan program"
    echo
    exit 0
}

print_banner() {
    echo
    echo "|------------------------------------------|"
    echo
    echo "  $1. $2"
    echo
    echo "|------------------------------------------|"
    echo
}

print_sub() {
    echo
    echo "  [ $1 ] $2"
    echo
}

TEMP=$(getopt -o u:t:o:h --long user:,target:,output:,help -n 'getopt' -- "$@")

if [ $? != 0 ]; then
    echo "Gagal parsing argumen program." >&2
    usage
    exit 1
fi

SSH_USER=""
TARGET_HOST=""
FILE_OUTPUT=""

eval set -- "$TEMP"

while true; do
    case "$1" in
        -u|--user)
           SSH_USER="$2"
           shift 2
           ;;
        -t|--target)
           TARGET_HOST="$2"
           shift 2
           ;;
        -o|--output)
           FILE_OUTPUT="$2"
           shift 2
           ;;
        -h|--help)
           usage
           ;;
        --) #echo "Option $1 membutuhkan argumen" >&2;
            shift
            break
            ;;
        *)
           echo "Argumen tidak dikenal: $1"
           usage
           exit 1
           ;;
    esac
done


if [[ -z "$SSH_USER" ]]; then
    echo "->Argument -u atau --user required!"
    usage
    exit 1
elif [[ -z "$TARGET_HOST" ]]; then
    echo "->Argument -t atau --target required!"
    usage
    exit 1
elif [[ -z "$FILE_OUTPUT" ]]; then
    echo "->Argument -o atau --output required!"
    usage
    exit 1
fi


#OUTPUT_FILE="system_info_${HOST}.txt"
OUTPUT_FILE=$FILE_OUTPUT

# Function to run commands on remote server using SSH
collect_info() {
  ssh -t "${SSH_USER}@${TARGET_HOST}" <<'EOF'
   IS_RHEL=0
   IS_UBUNTU=0
   IS_OTHER_SYSTEM=0

   print_banner() {
      echo
      echo "|------------------------------------------|"
      echo
      echo "  $1. $2"
      echo
      echo "|------------------------------------------|"
      echo
   }

   print_sub() {
      echo
      echo "  [ $1 ] $2"
      echo
   }

    print_banner "A" "Hardening Assessment Tool v1.0"
    printf "\tPelaksanaan: %s\n" "$(date)" 
    printf "\tTarget server: %s\n" "$(hostname)" 

    print_sub "0x0" "OS - Cek current OS"
    if [ -f /etc/redhat-release ]; then
        printf "\t-> Redhat family detected!\n"
        printf "\t%s\n" $(cat /etc/redhat-release)
        IS_RHEL=1
    elif [ -f /etc/lsb-release ]; then
        printf "\t-> Debian family detected\n"
        printf "\t%s\n" $(cat /etc/lsb-release)
        #lsb_release -a
        IS_UBUNTU=1
    else
        printf "\t-> Terdeteksi menggunakan system linux lainnya\n"
        printf "\t%s\n" $(uname -a)
        IS_OTHER_LINUX=1
    fi

    # Kernel arsitektur
    printf "\tInfo kernel : %s Architecture: %s\n" "$(uname -r)" "$(uname -m)" 

    #Cek file system
    print_sub "0x1" "Cek status fs: cramfs freevfs jffs2 hfs hfsplus squashfs udf vfat"

    for fs in cramfs freevfs jffs2 hfs hfsplus squashfs udf vfat;
    do
        if lsmod | grep $fs; then
            printf "\tModule fs \"%s\" terloaded\n" $fs
        else
            printf "\tTidak ada module file system \"%s\" yang diload\n" $fs
        fi
    done


    # Mount file system parameters check
    print_sub "0x2" "Cek mounting - Scan mount fs  berisi nosuid, nodev, noexec"

    mount | grep -E '(nosuid|nodev|noexec)' | while read -r line; do
        printf "\t-> Filesystem: %s on %s\n" "$(echo "$line" | cut -d' ' -f1)" "$(echo "$line" | cut -d' ' -f3)"
    done

    print_sub "0x2.1" "Mounting file system TIDAK berisi nosuid, nodev, noexec"
    mount | grep -v '(nosuid|nodev|noexec)' | while read -r line; do
        printf "\t-> Filesystem: %s on %s\n" "$(echo "$line" | cut -d' ' -f1)" "$(echo "$line" | cut -d' ' -f3)"
    done


    # PAM config - Cek enforce password
    print_sub "0x3" "Linux PAM - Cek existing minimum password lenght yang diset"
    PASS_MIN_COMPASS=$(grep min /etc/pam.d/common-password)
    PASS_MIN_PWQUAL=$(grep minlen /etc/security/pwquality.conf)
    PASS_MIN_DEFS=$(sudo grep PASS_MIN_LEN /etc/login.defs 2>/dev/null)

    if [ -z "$PASS_MIN_COMPASS" ]; then
       printf "\t--> /etc/pam.d/common-password lenght config: TIDAK diset\n"
    else
       printf "\t-> /etc/pam.d/common-password length config: %s\n" "$PASS_MIN_COMPASS"
    fi

    if [ -z "$PASS_MIN_PWQUAL" ]; then
    	printf "\t--> /etc/security/pwquality.conf lenght config: TIDAK diset\n"
    else
    	printf "\t-> /etc/security/pwquality.conf length config: %s\n" "$PASS_MIN_PWQUAL"
   fi

   if [ -z "$PASS_MIN_DEFS" ]; then
   	printf "\t--> /etc/login.defs lenght config: TIDAK diset\n"
   else
   	printf "\t-> /etc/login.defs length config: %s\n" "$PASS_MIN_DEFS"
   fi


   print_sub "0x3.1" "Cek enforce password history"
   if [[ $IS_UBUNTU -eq 1 ]]; then
      PASS_REMEMBER_UBUNTU=$(sudo grep remember /etc/pam.d/common-password 2>/dev/null)
      if [ -z $PASS_REMEMBER_UBUNTU ]; then
          printf "\t--> /etc/pam.d/common-password remember: TIDAK diset\n"
          #printf "\t--> Password history config from /etc/security/pwhistory:\n%s\n\n" "$(cat /etc/security/pwhistory.conf)"
          echo ""
       else
          printf "\t-> /etc/pam.d/common-password remember: %s\n\n" "$PASS_REMEMBER_UBUNTU"
      fi
  elif [[ $IS_RHEL -eq 1 ]]; then
      PASS_REMEMBER_RHEL=$(sudo grep remember /etc/pam.d/system.auth 2>/dev/null)
      if [ -z $PASS_REMEMBER_RHEL ]; then
          printf "\t--> /etc/pam.d/common-password remember: TIDAK diset\n\n"
      else
          printf "\t-> /etc/pam.d/common-password remember: %s\n" "$PASS_REMEMBER_RHEL"
      fi
  else
    printf "\t-> Other undefined linux system!\n"
  fi



print_sub "0x3.2" "Cek password complexity"
 if [[ "$IS_UBUNTU" -eq 1 ]]; then
     PASS_REMEMBER_UBUNTU=$(grep remember /etc/pam.d/common-password)
     if [ -z $PASS_REMEMBER_UBUNTU ]; then
         printf "\t--> /etc/pam.d/common-password remember: TIDAK diset\n"
     else
        #printf "\t-> /etc/pam.d/common-password remember: %s\n"
        echo "$PASS_REMEMBER_UBUNTU"
     fi
 elif [[ "$IS_RHEL" -eq 1 ]]; then
     PASS_REMEMBER_RHEL=$(grep remember /etc/pam.d/system.auth)
     if [ -z $PASS_REMEMBER_RHEL ]; then
         printf "\t--> /etc/pam.d/common-password remember: TIDAK diset\n"
     else
        #printf "\t-> /etc/pam.d/common-password remember: %s\n"
        echo "$PASS_REMEMBER_RHEL"
     fi
 else
     printf "\t-> Other undefined linux system!\n"
 fi


# Check user priviledge
print_sub "0x4" "Check user access control"
for USERX in $(awk -F: '$3 >= 1000 && $1 != "nobody" {print $1}' /etc/passwd);
do
    echo "User: $USERX"
    echo "User info: `grep $USERX /etc/passwd`"
    echo "Group info: `grep $USERX /etc/group`"
    echo "----"
done



# Cek Bootloader security
print_sub "0x5" "Check Bootloader GRUB security"
if [[ $IS_RHEL -eq 1 ]]; then
    GRUB_CFG=/boot/grub2/grub.cfg
    if [ -z $(sudo -S grep "password" $GRUB_CFG) ]; then
	printf "\tPassword GRUB diset dalam config\n"
	printf "\t%s\n" $_
    else
	printf "\tPassword GRUB tidak set dalam config\n"
    fi

elif [[ $IS_UBUNTU -eq 1 ]]; then
    GRUB_CFG=/boot/grub/grub.cfg
    if [ -z $(sudo grep "password" $GRUB_CFG) ]; then
    	printf "\t->Password GRUB diset dalam config\n"
	printf "\t%s\n" $_
    else 
	printf "\tPassword GRUB tidak diset dalam config\n"
    fi
else
    printf "\tGrub config: %s tidak ditemukan\n" $GRUB_CFG
fi

# Cek Kernel network parameter
print_sub "0x6" "Cek kernel network parameter"
printf "\t-> %s\n" "$(sysctl net.ipv4.icmp_echo_ignore_broadcasts)"
printf "\t-> %s\n" "$(sysctl net.ipv4.icmp_ignore_bogus_error_responses)"
printf "\t-> %s\n" "$(sysctl net.ipv4.tcp_syncookies)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.log_martians)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.default.log_martians)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.accept_source_route)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.default.accept_source_route)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.rp_filter)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.default.rp_filter)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.accept_redirects)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.default.accept_redirects)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.secure_redirects)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.default.secure_redirects)"
printf "\t-> %s\n" "$(sysctl net.ipv4.ip_forward)"
printf "\t-> %s\n" "$(sysctl net.ipv4.conf.all.send_redirects)"


# Module USB & Wireless
print_sub "0x7" "Module USB & Wireless check"
if [ -z $(lsmod | grep usb)]; then
    printf "\tModule USB tidak diload\n" 
else 
    printf "\tModule USB diload\n"
fi

if [ -z $(lsmod | grep wireless) ]; then
    printf "\tModule wirelesss tidak diload\n"
else
    printf "\tModule wireless diload\n"
fi


print_sub "0x8" "Cek status service Xinet - Based on Juknis"
JUKNIS_SERVICES=("anacron" "apmd" "avahi-daemon" "bluetooth" "cups" "dhcpd" "named" "vsftpd" "httpd" "ntpd" "ssh" "amanda" "amandaidx" "amidxtape" "auth" "chargen-dgram" "chargen-stream" "cvs" "daytime-dgram" "daytime-stream" "discard-dgram" "discard-stream" "echo-dgram" "echo-stream" "eklogin" "ekrb5-telnet" "gssftp" "klogin" "kshell" "ktalk" "ntalk" "rexec" "rlogin" "rsh" "rsync" "talk" "tcpmux-server" "telnet" "tftp" "time-dgram" "time-stream" "uucp")

for cservice in "${JUKNIS_SERVICES[@]}";
do
    SV_STATUS=$(systemctl is-active --quiet "$cservice.service" 2>/dev/null)

    if [[ "$IS_STATUS" -eq 1 ]]; then
        printf "\t-> Service: %s --> active/running\n" $cservice
    else
        printf "\t-> Service: %s --> inactive/not-running\n" $cservice
    fi
done

print_sub "0x9" "Cek service sedang running"
RUNNING_SERVICES=$(systemctl list-units --type=service --state=running | awk {'print $1'})
printf "\tList service yang sedang running :\n"
for dservice in "${RUNNING_SERVICES[@]}";
do
    printf "\t-> %s\n" $dservice
done

# TCP wrapper
print_sub "0xa" "Cek TCP Wrapper"
HOST_ALLOW=/etc/hosts.allow
HOST_DENY=/etc/hosts.deny

printf "\t-> Cek tcpd & tcp_wrapper apakah terinstall ?\n"

if [[ $(dpkg -l | grep -E '(tcpd|libwrap0)') ]] || [[ $(rpm -qa | grep 'tcp_wrappers') ]]; then
    printf "\t-> Tcpwrapper terinstal\n"
    if [[ $(ldd /usr/sbin/sshd | grep libwrap) ]]; then
        printf "\t-> Cek service tcpwrapper: tcpwrapper running\n"
        printf "\t-> Capture isi config TCPWrapper\n"
        printf "\t-> Config $HOST_ALLOW:\n%s\n" "$(grep -v '^\s*#' "$HOST_ALLOW" | grep -v '^\s*$')"
        printf "\t-> Config $HOST_DENY:\n%s\n" "$(grep -v '^\s*#' "$HOST_DENY" | grep -v '^\s*$')"
    else
        printf "\t-> Cek service tcpwrapper: tcpwrapper TIDAK running\n"
    fi
else
    printf "\t---> Tcpwrapper tidak terinstall\n"
fi


# SSH config
print_sub "0xb" "Cek config SSH"
SSHD_CONFIG="/etc/ssh/sshd_config"
permit_root_login=$(grep -i "PermitRootLogin" "$SSHD_CONFIG" | awk '{print $2}')
#enable_protocol=$(grep -i "Protocol" "$SSHD_CONFIG" | awk '{print $2'})

if [[ -z $(grep "PermitRootLogin" "$SSHD_CONFIG" | awk '{print $2}') ]]; then
    printf "\t--> PermitRootLogin enabled: %s\n" "$permit_root_login"
else
    printf "\t-> PermitRootLogin disabled\n"
fi


# Cek integrity
print_sub "0xc" "Cek integrity"
ASERVICE="aide"
AIDE_STATUS=$(sudo systemctl is-active "$SERVICES" 2>/dev/null)

printf "\t-> Cek aplikas aide & service\n"

if [[ "$IS_UBUNTU" -eq 1 ]]; then
    if [ -z $(dpkg -l | grep -q $ASERVICE) ]; then
        printf "\tAide apps install status: Terinstall\n"
        if [[ "$AIDE_STATUS" == "active" ]]; then
            printf "\t==> Service $SERVICES start/running\n"
        else
            printf "\t==> Service $SERVICES stop/die\n"
        fi
    else
        printf "\tAide apps tidak terinstall\n"
        printf "\tCek status repository...\n"
        if sudo apt update > /dev/null 2>apt_update_err.log; then
            printf "\tApt update complete sukses\n"
        else
            printf "\tApt failed:\n\n"
            cat apt_update_err.log
        fi
        rm -rf apt_update_err.log
    fi
elif [[ "$IS_RHEL" -eq 1 ]]; then
    if [ -z $(rpm -q $ASERVICE &> /dev/null) ]; then
        echo "AIDE terinstall"
        if [[ "$AIDE_STATUS" == "active" ]]; then
            printf "\t==> Service $SERVICES start/running\n"
        else
            printf "\t==> Service $SERVICES stop/die\n"
        fi

        printf "\t-> Cek $SERVICES di penjadwalan Cron:\n"
        printf "\t%s\n" "$(crontab -l | grep $ASERVICE)"
    else
        printf "\tAide apps tidak terinstall\n"
        printf "\tCek status repository...\n"
        if sudo yum update > /dev/null 2>yum_update_err.log; then
            printf "\tYUM update complete sukses\n"
        else
            printf "\tYUM update failed:\n\n"
            cat yum_update_err.log
        fi
        rm -rf yum_update_err.log
    fi
else
    echo "--> Service: $SERVICES TIDAK terinstall\n"
fi

# SELinux Check
print_sub "0xd" "Cek Selinux Rhel"
if [[ "$IS_RHEL" -eq 1 ]]; then
    printf "\t-> Cek status Selinux\n"
    printf "\t---> Selinux status:\n"
    sestatus

    printf "\tEnforce status: %s\n" "$(getenforce)"
else
    printf "\tSelinux tidak aktif\n"
fi


# Cek Firewall di Ubuntu & RHEL

print_sub "0xe" "Cek Firewall"
if [[ "$IS_UBUNTU" -eq 1 ]]; then
    if [ -z $(command -v ufw) ]; then
        printf "\tStatus UFW: %s\n" "$(ufw status)"
    else
        printf "\tFirewall UFW TIDAK terinstall\n"
        printf "\tCek iptables:\n"
        sudo iptables -L
    fi
elif [[ "$IS_RHEL" -eq 1 ]]; then
    if [ -z $(systemctl is-active firewalld) ]; then
        printf "\tStatue firewall:\n\t %s\n" "$_"
        printf "\tList rules:\n\t%s\n" "$(sudo firewall-cmd --list-all)"
    else
        printf "\t-> Firewall-cmd TIDAK terinstall\n"
        printf "\t-> Cek iptables rules:\n\t%s\n" "$(sudo iptables -L)"
    fi
fi


# Permission ke file sensitif
print_sub "0xf" "Cek sensi file permission"
printf "\t-> Sensi file permission info\n"
printf "\t%s\n" "$(stat /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/passwd- /etc/shadow- /etc/group- /etc/gshadow-)"


EOF
}

#scp $0 "$SSH_USER@$TARGET_HOST:/home/$SSH_USER/"

# Run the function and capture the output in a variable
output=$(collect_info)
#ssh -t "$SSH_USER@$TARGET_HOST" "sudo /home/$SSH_USER/$0"

# Print the output to the console
echo "$output"

# Save the output to a file
echo "$output" > "$OUTPUT_FILE"

# Notify user where the output is stored
#echo "System information collected and saved to $OUTPUT_FILE"

