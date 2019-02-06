#!/bin/bash

#secure installation for ubuntu 16.04
#support me visiting globalssh.net readyssh.net iptunnels.com
#chatme m.me/ibnumalik.al

#inisialiasi firewall
apt-get -y update --fix-missing
# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;
MYIP=$(curl -4 icanhazip.com)
if [ $MYIP = "" ]; then
   MYIP=`ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1`;
fi
MYIP2="s/xxxxxxxxx/$MYIP/g";
#firewall by iptables-persistent
iptables -I INPUT -p tcp --dport 8080 -j ACCEPT
iptables -I INPUT -p tcp --dport 3128 -j ACCEPT
iptables -t nat -I POSTROUTING -s 10.8.0.0/24 -o venet0 -j MASQUERADE
iptables -t nat -I POSTROUTING -s 10.9.0.0/24 -o venet0 -j MASQUERADE
iptables-save
clear
apt-get -y install iptables-persistent
netfilter-persistent save

apt-get -y install wget curl git nano stunnel4 openvpn easy-rsa zlib1g-dev zlib1g vnstat bmon iftop htop nmap axel nano traceroute sysv-rc-conf dnsutils bc nethogs openvpn less screen psmisc apt-file whois ptunnel ngrep mtr git unzip unrar rsyslog debsums rkhunter fail2ban cmake make gcc libc6-dev dropbear apache2-utils squid3
apt-get -y install build-essential
apt-file update
clear


# remove unused
apt-get -y --purge remove sendmail*;
apt-get -y --purge remove bind9*;
apt-get -y purge sendmail*
apt-get -y remove sendmail*
clear

#change port apache2 
sed -i 's|Listen 80|Listen 81|' /etc/apache2/ports.conf
sed -i 's|80|81|' /etc/apache2/sites-enabled/000-default.conf
systemctl restart apache2


# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#Add resolver dns cloudflare
echo "nameserver 1.1.1.1" > /etc/resolv.conf
echo "nameserver 1.0.0.1" >> /etc/resolv.conf
sed -i '$ i\echo "nameserver 1.1.1.1" > /etc/resolv.conf' /etc/rc.local
sed -i '$ i\echo "nameserver 1.0.0.1" >> /etc/resolv.conf' /etc/rc.local

#time jakarta
# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
service ssh restart

# install screenfetch
cd
wget -O /usr/bin/screenfetch "https://github.com/malikshi/elora/raw/master/screenfetch"
chmod +x /usr/bin/screenfetch
echo "clear" >> .profile
echo "screenfetch" >> .profile

# set ipv4 forward
echo 1 > /proc/sys/net/ipv4/ip_forward
sed -i 's|#net.ipv4.ip_forward=1|net.ipv4.ip_forward=1|' /etc/sysctl.conf
sed -i 's|net.ipv4.ip_forward=0|net.ipv4.ip_forward=1|' /etc/sysctl.conf

#tcpfastopen
echo "3" > /proc/sys/net/ipv4/tcp_fastopen
echo "net.ipv4.tcp_fastopen=3" > /etc/sysctl.d/30-tcp_fastopen.conf
echo '* soft nofile 51200' >> /etc/security/limits.conf
echo '* hard nofile 51200' >> /etc/security/limits.conf
wget -O /etc/sysctl.d/local.conf "https://github.com/malikshi/elora/raw/master/local.conf"
wget -O /etc/issue.net "https://github.com/malikshi/elora/raw/master/issue.net"
ulimit -n 51200
sysctl --system
sysctl -p /etc/sysctl.d/local.conf

#swap ram
echo 'vm.swappiness= 40' >>/etc/sysctl.conf
echo 'vm.vfs_cache_pressure = 50' >>/etc/sysctl.conf
fallocate -l 2G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo '/swapfile none swap sw 0 0' >>/etc/fstab
sysctl vm.swappiness=40
sysctl vm.vfs_cache_pressure=50
swapon -s
clear

# install badvpn
cd
wget https://github.com/ambrop72/badvpn/archive/1.999.130.tar.gz
tar xf 1.999.130.tar.gz
mkdir badvpn-build
cd badvpn-build
cmake ~/badvpn-1.999.130 -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1 -DBUILD_TUN2SOCKS=1
make install
sed -i '$ i\/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300' /etc/rc.local
clear

#install ssh
cd
echo 'Port 143' >>/etc/ssh/sshd_config
echo 'MaxAuthTries 2' >>/etc/ssh/sshd_config
echo 'Banner /etc/issue.net' >>/etc/ssh/sshd_config
clear

# install dropbear
cd
wget -O /etc/default/dropbear "https://github.com/malikshi/elora/raw/master/dropbear"
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
sed -i 's/obscure/minlen=5/g' /etc/pam.d/common-password
service ssh restart
service dropbear restart
clear

#Upgrade to Dropbear 2018
cd
wget https://matt.ucc.asn.au/dropbear/dropbear-2018.76.tar.bz2
bzip2 -cd dropbear-2018.76.tar.bz2 | tar xvf -
cd dropbear-2018.76
./configure
make && make install
mv /usr/sbin/dropbear /usr/sbin/dropbear.old
ln /usr/local/sbin/dropbear /usr/sbin/dropbear
cd && rm -rf dropbear-2018.76 && rm -rf dropbear-2018.76.tar.bz2
service dropbear restart
clear

#install stunnel4
cd
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
wget -O /etc/stunnel/stunnel.conf "https://github.com/malikshi/elora/raw/master/stunnel.conf"
sed -i $MYIP2 /etc/stunnel/stunnel.conf
#setting cert
country=SG
state=MAPLETREE
locality=Bussiness
organization=IPTUNNELS
organizationalunit=ISPSSH
commonname=server
email=admin@iptunnels.com
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem
/etc/init.d/stunnel4 restart
clear

# install fail2ban
cd
service fail2ban restart
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
service fail2ban restart
cd
clear

# install squid3
touch /etc/squid/passwd
/bin/rm -f /etc/squid/squid.conf
/usr/bin/touch /etc/squid/blacklist.acl
/usr/bin/wget --no-check-certificate -O /etc/squid/squid.conf https://github.com/malikshi/squid-proxy-installer/raw/master/squid.conf
service squid restart
update-rc.d squid defaults
#create user default 
/usr/bin/htpasswd -b -c /etc/squid/passwd iptunnels FAST
service squid restart
clear

# install webmin
cd
echo 'deb http://download.webmin.com/download/repository sarge contrib' >>/etc/apt/sources.list
echo 'deb http://webmin.mirror.somersettechsolutions.co.uk/repository sarge contrib' >>/etc/apt/sources.list
wget http://www.webmin.com/jcameron-key.asc
apt-key add jcameron-key.asc
apt-get -y update && apt-get -y install webmin
clear

#install vpn must be already installed by using script from angristan
cd
cd /etc/openvpn/
wget -O /etc/openvpn/openvpn-auth-pam.so https://github.com/malikshi/elora/raw/master/openvpn-auth-pam.so
echo "plugin /etc/openvpn/openvpn-auth-pam.so /etc/pam.d/login" >> /etc/openvpn/server.conf
echo "verify-client-cert none" >> /etc/openvpn/server.conf
echo "username-as-common-name" >> /etc/openvpn/server.conf
echo "duplicate-cn" >> /etc/openvpn/server.conf
echo "max-clients 10000" >> /etc/openvpn/server.conf
echo "max-routes-per-client 1000" >> /etc/openvpn/server.conf
echo "mssfix 1200" >> /etc/openvpn/server.conf
echo "sndbuf 2000000" >> /etc/openvpn/server.conf
echo "rcvbuf 2000000" >> /etc/openvpn/server.conf
echo "txqueuelen 4000" >> /etc/openvpn/server.conf
echo "replay-window 2000" >> /etc/openvpn/server.conf
sed -i 's|user|#user|' /etc/openvpn/server.conf
sed -i 's|group|#group|' /etc/openvpn/server.conf
sed -i 's|user|#user|' /etc/openvpn/server.conf
cp server.conf server-udp.conf
sed -i 's|1194|587|' /etc/openvpn/server-udp.conf
sed -i 's|tcp|udp|' /etc/openvpn/server-udp.conf
sed -i 's|10.8.0.0|10.9.0.0|' /etc/openvpn/server-udp.conf
sed -i 's|#AUTOSTART="all"|AUTOSTART="all"|' /etc/default/openvpn
service openvpn restart
clear
#client vpn edit 
echo "auth-user-pass" /root/client.ovpn
echo "mssfix 1200" /root/client.ovpn
echo "sndbuf 2000000" /root/client.ovpn
echo "rcvbuf 2000000" /root/client.ovpn
clear

#auto startup
cd


sed -i '$ i\iptables -I FORWARD -s 10.9.0.0/24 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -I INPUT -p udp --dport 587 -j ACCEPT' /etc/rc.local
sed -i '$ i\iptables -t nat -A POSTROUTING -s 10.9.0.0/24 ! -d 10.9.0.0/24 -j SNAT --to xxxxxxxxx' /etc/rc.local
sed -i $MYIP /etc/rc.local
sed -i '$ i\screen -AmdS limit /root/limit.sh' /etc/rc.local
sed -i '$ i\screen -AmdS ban /root/ban.sh' /etc/rc.local
sed -i '$ i\service fail2ban restart' /etc/rc.local
sed -i '$ i\service dropbear restart' /etc/rc.local
sed -i '$ i\service squid restart' /etc/rc.local
sed -i '$ i\service webmin restart' /etc/rc.local
sed -i '$ i\/etc/init.d/stunnel4 restart' /etc/rc.local
sed -i '$ i\/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 > /dev/nul &' /etc/rc.local
echo "0 0 * * * root /usr/local/bin/user-expire" > /etc/cron.d/user-expire
echo "0 0 * * * root /usr/local/bin/deltrash" > /etc/cron.d/deltrash
echo "0 0 * * * root /usr/local/bin/killtrash" > /etc/cron.d/killtrash
echo "0 0 * * * root /usr/local/bin/expiredtrash" > /etc/cron.d/expiredtrash
clear

#automatic deleting
cat > /usr/local/bin/deltrash <<END1
#!/bin/bash
nowsecs=$( date +%s )

while read account
do
    username=$( echo $account | cut -d: -f1  )
    expiredays=$( echo $account | cut -d: -f2 )
    expiresecs=$(( $expiredays * 86400 ))
    if [ $expiresecs -le $nowsecs ]
    then
        echo "$username has expired deleting"
        userdel -r "$username"
    fi
done < <( cut -d: -f1,8 /etc/shadow | sed /:$/d )
END1

#automatic killing
cat > /usr/local/bin/killtrash <<END2
while :
  do
  ./userexpired.sh
  sleep 36000
  done
END2

#automatic check trash
cat > /usr/local/bin/expiredtrash <<END3
#!/bin/bash
echo "" > /root/infouser.txt
echo "" > /root/expireduser.txt
echo "" > /root/alluser.txt

cat /etc/shadow | cut -d: -f1,8 | sed /:$/d > /tmp/expirelist.txt
totalaccounts=`cat /tmp/expirelist.txt | wc -l`
for((i=1; i<=$totalaccounts; i++ ))
       do
       tuserval=`head -n $i /tmp/expirelist.txt | tail -n 1`
       username=`echo $tuserval | cut -f1 -d:`
       userexp=`echo $tuserval | cut -f2 -d:`
       userexpireinseconds=$(( $userexp * 86400 ))
       tglexp=`date -d @$userexpireinseconds`             
       tgl=`echo $tglexp |awk -F" " '{print $3}'`
       while [ ${#tgl} -lt 2 ]
       do
           tgl="0"$tgl
       done
       while [ ${#username} -lt 15 ]
       do
           username=$username" " 
       done
       bulantahun=`echo $tglexp |awk -F" " '{print $2,$6}'`
       echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/alluser.txt
       todaystime=`date +%s`
       if [ $userexpireinseconds -ge $todaystime ] ;
           then
           timeto7days=$(( $todaystime + 604800 ))
                if [ $userexpireinseconds -le $timeto7days ];
                then                     
                     echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/infouser.txt
                fi
       else
       echo " User : $username Expire tanggal : $tgl $bulantahun" >> /root/expireduser.txt
       passwd -l $username
       fi
done
END3

chmod +x /usr/local/bin/deltrash
chmod +x /usr/local/bin/killtrash
chmod +x /usr/local/bin/expiredtrash
clear

#premium Script
cd /usr/local/bin
wget -O premium-script.tar.gz "https://github.com/malikshi/elora/raw/master/premium-script.tar.gz"
tar -xvf premium-script.tar.gz
rm -f premium-script.tar.gz
cp /usr/local/bin/premium-script /usr/local/bin/menu

cat > /root/ban.sh <<END4
#!/bin/bash
#/usr/local/bin/user-ban
END4

cat > /root/limit.sh <<END5
#!/bin/bash
#/usr/local/bin/user-limit
END5

chmod +x /usr/local/bin/trial
chmod +x /usr/local/bin/user-add
chmod +x /usr/local/bin/user-aktif
chmod +x /usr/local/bin/user-ban
chmod +x /usr/local/bin/user-delete
chmod +x /usr/local/bin/user-detail
chmod +x /usr/local/bin/user-expire
chmod +x /usr/local/bin/user-limit
chmod +x /usr/local/bin/user-lock
chmod +x /usr/local/bin/user-login
chmod +x /usr/local/bin/user-unban
chmod +x /usr/local/bin/user-unlock
chmod +x /usr/local/bin/user-password
chmod +x /usr/local/bin/user-log
chmod +x /usr/local/bin/user-add-pptp
chmod +x /usr/local/bin/user-delete-pptp
chmod +x /usr/local/bin/alluser-pptp
chmod +x /usr/local/bin/user-login-pptp
chmod +x /usr/local/bin/user-expire-pptp
chmod +x /usr/local/bin/user-detail-pptp
chmod +x /usr/local/bin/bench-network
chmod +x /usr/local/bin/speedtest
chmod +x /usr/local/bin/ram
chmod +x /usr/local/bin/log-limit
chmod +x /usr/local/bin/log-ban
chmod +x /usr/local/bin/listpassword
chmod +x /usr/local/bin/pengumuman
chmod +x /usr/local/bin/user-generate
chmod +x /usr/local/bin/user-list
chmod +x /usr/local/bin/diagnosa
chmod +x /usr/local/bin/premium-script
chmod +x /usr/local/bin/user-delete-expired
chmod +x /usr/local/bin/auto-reboot
chmod +x /usr/local/bin/log-install
chmod +x /usr/local/bin/menu
chmod +x /usr/local/bin/user-auto-limit
chmod +x /usr/local/bin/user-auto-limit-script
chmod +x /usr/local/bin/edit-port
chmod +x /usr/local/bin/edit-port-squid
chmod +x /usr/local/bin/edit-port-openvpn
chmod +x /usr/local/bin/edit-port-openssh
chmod +x /usr/local/bin/edit-port-dropbear
chmod +x /usr/local/bin/autokill
chmod +x /root/limit.sh
chmod +x /root/ban.sh
screen -AmdS limit /root/limit.sh
screen -AmdS ban /root/ban.sh
clear



#finalisasi
cd
service ssh restart
service dropbear restart
service fail2ban restart
service squid restart
service webmin restart
/etc/init.d/stunnel4 restart
service openvpn restart
rm 1.999.130.tar.gz
rm iptunnels.sh 
clear 

# info
clear
echo " "
echo "Instalasi telah selesai! Mohon baca dan simpan penjelasan setup server!"
echo " "
echo "--------------------------- Penjelasan Setup Server ----------------------------"
echo "            Modified by https://www.facebook.com/ibnumalik.al                   "
echo "--------------------------------------------------------------------------------"
echo ""  | tee -a log-install.txt
echo "Informasi Server"  | tee -a log-install.txt
echo "   - Timezone    : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban    : [on]"  | tee -a log-install.txt
echo "   - IPtables    : [off]"  | tee -a log-install.txt
echo "   - Auto-Reboot : [on]"  | tee -a log-install.txt
echo "   - IPv6        : [off]"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Informasi Aplikasi & Port"  | tee -a log-install.txt
echo "   - OpenVPN     : TCP 1194 UDP 587 SSL 1443"  | tee -a log-install.txt
echo "   - OpenSSH     : 22, 143"  | tee -a log-install.txt
echo "   - OpenSSH-SSL : 444"  | tee -a log-install.txt
echo "   - Dropbear    : 80, 54793"  | tee -a log-install.txt
echo "   - Dropbear-SSL: 443"  | tee -a log-install.txt
echo "   - Squid Proxy : 8080, 3128 (public u/p= iptunnels/FAST)"  | tee -a log-install.txt
echo "   - Squid-SSL   : 8000 (public u/p= iptunnels/FAST)"  | tee -a log-install.txt
echo "   - Badvpn      : 7300"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Informasi Tools Dalam Server"  | tee -a log-install.txt
echo "   - htop"  | tee -a log-install.txt
echo "   - iftop"  | tee -a log-install.txt
echo "   - mtr"  | tee -a log-install.txt
echo "   - nethogs"  | tee -a log-install.txt
echo "   - screenfetch"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Informasi Premium Script"  | tee -a log-install.txt
echo "   Perintah untuk menampilkan daftar perintah: menu"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   Penjelasan script dan setup VPS"| tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "Informasi Penting"  | tee -a log-install.txt
echo "   - Webmin                  : http://$MYIP:10000/"  | tee -a log-install.txt
echo "   - Log Instalasi           : cat /root/log-install.txt"  | tee -a log-install.txt
echo "     NB: User & Password Webmin adalah sama dengan user & password root"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "            Modified by https://www.facebook.com/ibnumalik.al                   "
