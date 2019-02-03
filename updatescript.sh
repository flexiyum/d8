#!/bin/bash


if [[ $USER != "root" ]]; then
	echo "Maaf, Anda harus menjalankan ini sebagai root"
	exit
fi

# initialisasi var
export DEBIAN_FRONTEND=noninteractive
OS=`uname -m`;

# get the VPS IP
#ip=`ifconfig venet0:0 | grep 'inet addr' | awk {'print $2'} | sed s/.*://`
#MYIP=$(ifconfig | grep 'inet addr:' | grep -v inet6 | grep -vE '127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | cut -d: -f2 | awk '{ print $1}' | head -1)
MYIP=`ifconfig | grep -Eo 'inet (addr:)?([0-9]*\.){3}[0-9]*' | grep -Eo '([0-9]*\.){3}[0-9]*' | grep -v '127.0.0' | head -n1`;if [ "$MYIP" = "" ]; then
	MYIP=$(wget -qO- ipv4.icanhazip.com)
fi
#MYIP=$(wget -qO- ipv4.icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
ether=`ifconfig | cut -c 1-8 | sort | uniq -u | grep venet0 | grep -v venet0:`
if [[ $ether = "" ]]; then
        ether=eth0
fi

#vps="zvur";
vps="aneka";

#if [[ $vps = "zvur" ]]; then
	#source="http://"
#else
	source="https://raw.githubusercontent.com/yarzardhiyit/d8-x64"
#fi

# go to root
cd

# check registered ip
wget -q -O IP $source/master/IP.txt
if ! grep -w -q $MYIP IP; then
	echo "Maaf, hanya IP yang terdaftar yang bisa menggunakan script ini!"
	if [[ $vps = "zvur" ]]; then
		echo "Hubungi: editor SYAHZ86"
	else
		echo "Hubungi: editor SYAHZ86"
	fi
	rm -f /root/IP
	rm -f /root/IPcarding
	exit
fi
rm /root/IP
#echo "Maaf.. Saat ini belum tersedia update script bos......!!!" | boxes -d boy
#echo "Update webmin tersedia bos, tp versi webmin 1.820_all.deb..gk apa2 ya boss.." | lolcat
echo "Perbaikan MENU update script" | boxes -d boy | lolcat
sleep 4
cd

#wget "http://prdownloads.sourceforge.net/webadmin/webmin_1.820_all.deb"
#dpkg --install webmin_1.820_all.deb
#apt-get -y -f install
#rm /root/webmin_1.820_all.deb
#sed -i 's/ssl=1/ssl=0/g' /etc/webmin/miniserv.conf
#service webmin restart
#source="https://raw.githubusercontent.com/elangoverdosis/deeniedoank"
#cd
#wget -O /usr/bin/benchmark $source/master/benchmark.sh
#wget -O /usr/bin/speedtest $source/master/speedtest_cli.py
#wget -O /usr/bin/ps-mem $source/master/ps_mem.py
#wget -O /etc/issue.net $source/master/bannerA
#wget -O /usr/bin/dropmon $source/master/dropmon.sh
#wget -O /usr/bin/menu $source/master/menu.sh
#wget -O /usr/bin/user-active-list $source/master/user-active-list.sh
#wget -O /usr/bin/user-add $source//user-add.sh
#wget -O /usr/bin/user-add-pptp $source/master/user-add-pptp.sh
#wget -O /usr/bin/user-del $source/master/user-del.sh
#wget -O /usr/bin/disable-user-expire $source/master/disable-user-expire.sh
#wget -O /usr/bin/delete-user-expire $source/master/delete-user-expire.sh
#wget -O /usr/bin/banned-user $source/master/banned-user.sh
#wget -O /usr/bin/unbanned-user https://raw.githubusercontent.com/elangoverdosis/deeniedoank/debian7/unbanned-user.sh
#wget -O /usr/bin/user-expire-list $source/master/user-expire-list.sh
#wget -O /usr/bin/user-gen $source/master/user-gen.sh
#wget -O /usr/bin/user-limit $source/master/user-limit.sh
#wget -O /usr/bin/user-list $source/master/user-list.sh
#wget -O /usr/bin/user-login $source/master/user-login.sh
#wget -O /usr/bin/user-pass $source/master/user-pass.sh
#wget -O /usr/bin/user-renew $source/master/user-renew.sh
#wget -O /usr/bin/clearcache.sh $source//clearcache.sh
#wget -O /usr/bin/bannermenu $source/master/bannermenu
wget -O /usr/bin/menu-update-script-vps.sh $source/master/menu-update-script-vps.sh


#chmod +x /usr/bin/benchmark
#chmod +x /usr/bin/speedtest
#chmod +x /usr/bin/ps-mem
#chmod +x /usr/bin/dropmon
#chmod +x /usr/bin/menu
#chmod +x /usr/bin/user-active-list
#chmod +x /usr/bin/user-add
#chmod +x /usr/bin/user-add-pptp
#chmod +x /usr/bin/user-del
#chmod +x /usr/bin/disable-user-expire
#chmod +x /usr/bin/delete-user-expire
#chmod +x /usr/bin/banned-user
#chmod +x /usr/bin/unbanned-user
clear
#chmod +x /usr/bin/user-expire-list
#chmod +x /usr/bin/user-gen
#chmod +x /usr/bin/user-limit
#chmod +x /usr/bin/user-list
#chmod +x /usr/bin/user-login
#chmod +x /usr/bin/user-pass
#chmod +x /usr/bin/user-renew
#chmod +x /usr/bin/clearcache.sh
#chmod +x /usr/bin/bannermenu
chmod +x /usr/bin/menu-update-script-vps.sh
rm /usr/bin/updatescript.sh
clear
echo ""
echo ""
echo ""
echo "selesai bosss...." | lolcat

sleep 3
rm /root/IP
rm /root/IPcarding
clear
menu
