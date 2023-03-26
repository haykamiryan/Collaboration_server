#!/bin/bash
        mkdir $HOME/build
        export SRC_PATH=$HOME/build

	#Zenity
	if [ -d /usr/share/zenity/ ]; then
        echo "Zenity - YES"
else

cd $SRC_PATH
wget  https://download.gnome.org/sources/zenity/3.32/zenity-3.32.0.tar.xz
./configure --prefix=/usr &&
make -j3
sudo make install
	fi
	Zenity(){
option=$(zenity --list --title="Installation" --text="" --column="0"  "Install Postfix & Dovecot(Mail)" "Setup mail server"  "Install Radicale(Calendar)"  "Install honeypot" "Install Metax"  --width=600 --height=200 --hide-header)

if 
         [ "$option" == "Install Postfix & Dovecot(Mail)" ];
 then
#Libtirpc
  if [ -d /usr/include/tirpc ]; then
	echo "libtirpc - YES" 
else	
 
	
    cd $SRC_PATH
        wget  https://downloads.sourceforge.net/libtirpc/libtirpc-1.3.3.tar.bz2
        tar xf libtirpc-1.3.3.tar.bz2
        cd libtirpc-1.3.3
        ./configure --prefix=/usr                                   \
            --sysconfdir=/etc                               \
            --disable-static                                \
            --disable-gssapi                                &&
        make -j3
        sudo make install
  fi
#Berkeley
if [ -d /usr/share/doc/db-5.3.28/ ]; then
	echo "BerkeleyDB - YES"
else
cd $SRC_PATH
        wget https://anduin.linuxfromscratch.org/BLFS/bdb/db-5.3.28.tar.gz
        tar xf db-5.3.28.tar.gz
        cd db-5.3.28
        sed -i 's/\(__atomic_compare_exchange\)/\1_db/' src/dbinc/atomic.h
        cd build_unix                        &&
../dist/configure --prefix=/usr      \
                  --enable-compat185 \
                  --enable-dbm       \
                  --disable-static   \
                  --enable-cxx       &&
        make -j3

        sudo make docdir=/usr/share/doc/db-5.3.28 install &&
        sudo chown -v -R root:root                        \
        /usr/bin/db_*                          \
        /usr/include/db{,_185,_cxx}.h          \
        /usr/lib/libdb*.{so,la}                \
        /usr/share/doc/db-5.3.28
fi

#ICU
if [ -d /usr/share/icu/ ]; then
        echo "ICU - YES"
else

cd $SRC_PATH
wget  https://github.com/unicode-org/icu/releases/download/release-72-1/icu4c-72_1-src.tgz
tar xf icu4c-72_1-src.tgz
cd icu
cd source                                    &&

./configure --prefix=/usr                    &&
make -j3
sudo make install




fi

#Postfix
cd $SRC_PATH
	wget https://ghostarchive.org/postfix/postfix-release/official/postfix-3.7.4.tar.gz
	tar xf postfix-3.7.4.tar.gz
        cd postfix-3.7.4	
	sudo groupadd -g 32 postfix &&
	sudo groupadd -g 33 postdrop &&
	sudo useradd -c "Postfix Daemon User" -d /var/spool/postfix -g postfix \
        -s /bin/false -u 32 postfix &&
	sudo chown -v postfix:postfix /var/mail
	sed -i 's/.\x08//g' README_FILES/*
	sed -i 's/Linux..345/&6/' makedefs &&
	sed -i 's/LINUX2/LINUX6/' src/util/sys_defs.h

	make CCARGS="-DNO_NIS -DUSE_TLS -I/usr/include/openssl/            \
             -DUSE_SASL_AUTH -DUSE_CYRUS_SASL -I/usr/include/sasl" \
	   AUXLIBS="-lssl -lcrypto -lsasl2"                              \
	makefiles &&
	make -j3
	sudo sh postfix-install -non-interactive \
  	daemon_directory=/usr/lib/postfix \
 	manpage_directory=/usr/share/man \
  	html_directory=/usr/share/doc/postfix-3.7.4/html \
 	readme_directory=/usr/share/doc/postfix-3.7.4/readme
	echo 'cat >> /etc/aliases
	# Begin /etc/aliases
	AILER-DAEMON:    postmaster
	postmaster:       root
	root:             <LOGIN>
 	End /etc/aliases ' | sudo -s 
	/usr/sbin/postfix upgrade-configuration
	sudo /usr/sbin/postfix check &&
	sudo /usr/sbin/postfix start
	cd $SRC_PATH
	wget  https://www.linuxfromscratch.org/blfs/downloads/systemd/blfs-systemd-units-20220720.tar.xz
	tar xf blfs-systemd-units-20220720.tar.xz
	cd blfs-systemd-units-20220720
	sudo make install-postfix
	
	
#Dovecot
cd $SRC_PATH
wget https://www.dovecot.org/releases/2.3/dovecot-2.3.20.tar.gz
	tar xf dovecot-2.3.20.tar.gz
	wget https://www.linuxfromscratch.org/patches/blfs/svn/dovecot-2.3.20-openssl3_fixes-1.patch
	wget  https://www.linuxfromscratch.org/patches/blfs/svn/dovecot-2.3.20-security_fix-1.patch
	cd dovecot-2.3.20
	sudo groupadd -g 42 dovecot &&
	sudo useradd -c "Dovecot unprivileged user" -d /dev/null -u 42 \
        -g dovecot -s /bin/false dovecot &&
	sudo groupadd -g 43 dovenull &&
	sudo useradd -c "Dovecot login user" -d /dev/null -u 43 \
        -g dovenull -s /bin/false dovenull
	patch -Np1 -i ../dovecot-2.3.20-openssl3_fixes-1.patch
	patch -Np1 -i ../dovecot-2.3.20-security_fix-1.patch
	CPPFLAGS="-I/usr/include/tirpc" \
	LDFLAGS+=" -ltirpc" \
	./configure --prefix=/usr                          \
            --sysconfdir=/etc                      \
            --localstatedir=/var                   \
            --docdir=/usr/share/doc/dovecot-2.3.20 \
            --disable-static                       &&
	make -j3
	sudo make install
	sudo cp -rv /usr/share/doc/dovecot-2.3.20/example-config/* /etc/dovecot
	sudo sed -i '/^\!include / s/^/#/' /etc/dovecot/dovecot.conf &&
	sudo chmod -v 1777 /var/mail &&
	echo 'cat > /etc/dovecot/local.conf  
	protocols = imap
	ssl = no
	listen = *
	mail_location = mbox:~/Mail:INBOX=/var/mail/%u
	userdb {
  	driver = passwd
	}
	passdb {
  	driver = shadow
	}' | sudo -s
Zenity
fi
if 
         [ "$option" == "Setup mail server" ];
 then

	 sudo mkdir /etc/cert

	 private=$(zenity --file-selection --title="Select Certificate(private.pem)")
	 sudo cp -ax $private /etc/cert/
 	 domainfile=$(zenity --file-selection --title="Select Certificate(domain.com.pem)")
	 sudo cp -ax $domainfile /etc/cert/
       	 master=$(zenity --file-selection --title="Select Certificate(master.cf)")
	 sudo cp -ax $master -  /etc/cert/

	sudo touch /etc/postfix/vmail_mailbox
	sudo touch /etc/postfix/vmail_aliases
	sudo touch /etc/postfix/vmail_domains	

	priv=${private##*/}
	dom=${domainfile##*/}
 
       echo  'cat > /etc/dovecot/dovecot.conf
listen = *
ssl = required
protocols = imap 
' | sudo -s
echo "cat >> /etc/dovecot/dovecot.conf
ssl_key = </etc/cert/$priv
ssl_cert = </etc/cert/$dom" | sudo -s


echo "cat >> /etc/dovecot/dovecot.conf
disable_plaintext_auth = yes
auth_mechanisms = plain login 
mail_access_groups = vmail
default_login_user = vmail
first_valid_uid = 2222
first_valid_gid = 2222
mail_location = Maildir:/var/vmail/%d/%n

passdb {
    driver = passwd-file
   args = scheme=SHA1 /etc/dovecot/passwd
}
userdb {
   driver = static
   args = uid=2222 gid=2222 home=/var/vmail/%d/%n allow_all_users=yes 

}

service auth {
    unix_listener auth-client {
       group = postfix
        mode = 0660
        user = postfix
}
    user = root
}
service imap-login {
  service_count = 1
  client_limit = 300
  process_limit = 300
  process_min_avail = 4
  vsz_limit = 512M
}
#service imap-login {
#  inet_listener imap {
#    port = 0
#  }
#  inet_listener imaps {
#    address = *
 #   port = 993
 # }
#}

#namespace inbox {
 # inbox = yes
  
#mailbox Drafts {
    #special_use = \Drafts
  #}
  #mailbox Junk {
   # special_use = \Junk
  #}
  #mailbox Sent {
   # special_use = \Sent
  #}
   # special_use = \Sent
  #}
  #mailbox Trash {
#    special_use = \Trash
 # }
#  prefix =
 # separator = /
#}


dict {
  #quota = mysql:/etc/dovecot/dovecot-dict-sql.conf.ext
}
# Most of the actual configuration gets included below. The filenames are
# first sorted by their ASCII value and parsed in that order. The 00-prefixes
# in filenames are intended to make it easier to understand the ordering.
!include conf.d/*.conf

# A config file can also tried to be included without giving an error if
# its not found:
#!include_try local.conf "  | sudo -s



hos=$(zenity --entry --title="" --text="Enter domain")

sudo touch /etc/postfix/main.cf
echo  'cat > /etc/postfix/main.cf 
compatibility_level = 2
queue_directory = /var/spool/postfix
command_directory = /usr/sbin
daemon_directory = /usr/lib/postfix
data_directory = /var/lib/postfix
mail_owner = postfix' | sudo -s
echo "cat >> /etc/postfix/main.cf
myhostname = $hos
mydomain = $hos " | sudo -s
echo 'cat >> /etc/postfix/main.cf
myorigin = $mydomain
inet_interfaces = all
mydestination = localhost.$mydomain, localhost
local_recipient_maps =
local_recipient_maps =
unknown_local_recipient_reject_code = 550
alias_maps = hash:/etc/postfix/aliases
alias_database = hash:/etc/postfix/aliases
home_mailbox = Maildir/
mailbox_command =
smtpd_banner = $myhostname ESMTP $mail_name
debug_peer_level = 2
debugger_command =
         PATH=/bin:/usr/bin:/usr/local/bin:/usr/X11R6/bin
         ddd $daemon_directory/$process_name $process_id & sleep 5

sendmail_path = /usr/sbin/sendmail
newaliases_path = /bin/newaliases
mailq_path = /bin/mailq
setgid_group = postdrop
html_directory = /usr/share/doc/postfix-3.7.4/html
manpage_directory = /usr/share/man
sample_directory = /etc/postfix
readme_directory = /usr/share/doc/postfix-3.7.4/readme
inet_protocols = ipv4
meta_directory = /etc/postfix
shlib_directory = no
smtputf8_enable = yes
header_checks =  regexp:/etc/postfix/header_checks
body_checks =  regexp:/etc/postfix/body_checks
virtual_alias_maps=hash:/etc/postfix/vmail_aliases
virtual_mailbox_domains=hash:/etc/postfix/vmail_domains
virtual_mailbox_maps=hash:/etc/postfix/vmail_mailbox

virtual_mailbox_base = /var/vmail
virtual_transport = virtual
virtual_uid_maps = static:2222
virtual_gid_maps = static:2222
' | sudo -s

echo "cat >>  /etc/postfix/main.cf
smtpd_tls_key_file = /etc/cert/$priv
smtpd_tls_cert_file = /etc/cert/$dom
" | sudo -s
echo 'cat >> /etc/postfix/main.cf
smtpd_tls_security_level = may
smtpd_tls_loglevel = 3
smtpd_tls_received_header = yes
smtpd_tls_session_cache_timeout = 3600s
tls_random_source = dev:/dev/urandom

smtpd_sasl_auth_enable = yes
smtp_sasl_security_options = noanonymous
smtpd_sasl_type = dovecot
smtpd_sasl_path = /var/run/dovecot/auth-client
smtpd_sasl_local_domain = $mydomain
broken_sasl_auth_clients = yes

smtpd_recipient_restrictions = check_sender_access hash:/etc/postfix/access
smtpd_relay_restrictions = permit_mynetworks, permit_sasl_authenticated, reject_unauth_destination, reject_unknown_reverse_client_hostname
smtpd_restriction_classes = insiders_only
insiders_only = check_sender_access hash:/etc/postfix/insiders, reject

smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3
smtp_tls_mandatory_protocols=!SSLv2,!SSLv3
smtpd_tls_protocols=!SSLv2,!SSLv3
smtp_tls_protocols=!SSLv2,!SSLv3

tls_preempt_cipherlist = yes
smtpd_tls_mandatory_ciphers = high
tls_high_cipherlist = ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:DHE-DSS-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA256:ADH-AES256-GCM-SHA384:ADH-AES256-SHA256:ECDH-RSA-AES256-GCM-SHA384:ECDH-ECDSA-AES256-GCM-SHA384:ECDH-RSA-AES256-SHA384:ECDH-ECDSA-AES256-SHA384:AES256-GCM-SHA384:AES256-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:DHE-DSS-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-SHA256:DHE-DSS-AES128-SHA256:ADH-AES128-GCM-SHA256:ADH-AES128-SHA256:ECDH-RSA-AES128-GCM-SHA256:ECDH-ECDSA-AES128-GCM-SHA256:ECDH-RSA-AES128-SHA256:ECDH-ECDSA-AES128-SHA256:AES128-GCM-SHA256:AES128-SHA256:NULL-SHA256


smtpd_sender_restrictions = reject_unknown_sender_domain
smtpd_client_message_rate_limit = 10
anvil_rate_time_unit = 300s
smtpd_recipient_limit = 20


transport_maps = hash:/etc/postfix/transport
' | sudo -s
sudo systemctl start dovecot.service
sudo systemctl start postfix.service

Zenity
fi 


if 
         [ "$option" == "Install Radicale(Calendar)" ];
 then
#Radicale
cd $SRC_PATH
sudo python3 -m pip install --upgrade https://github.com/Kozea/Radicale/archive/master.tar.gz
mkdir ~/.config/radicale
mkdir ~/.config/radicale/collections
echo "[server]
max_connections = 100
max_content_length = 100000000
timeout = 40
hosts = 127.0.0.1:5232, [::]:5232


[auth]
type = htpasswd
htpasswd_filename = ~/.config/radicale/users
htpasswd_encryption = plain

[storage]
filesystem_folder = ~/.config/radicale/collections

[rights]
type = owner_write" >~/.config/radicale/config
wget https://greenhosting.am:444/db/get/radicale.service?id=bb393c04-86ef-4e3b-88f3-ce47373fee63
mv 'radicale.service?id=bb393c04-86ef-4e3b-88f3-ce47373fee63'  radicale.service
sudo mv  radicale.service /etc/systemd/system/radicale.service
sudo systemctl daemon-reload
sudo systemctl enable radicale
sudo systemctl start radicale

Zenity
fi

if 
         [ "$option" == "Install honeypot" ];
 then
#Libedit
cd $SRC_PATH
git clone https://github.com/cdesjardins/libedit.git
cd libedit
./configure --prefix=/usr/
make -j3
sudo make install
#Libnftnl
cd $SRC_PATH
wget https://www.netfilter.org/pub/libnftnl/libnftnl-1.2.4.tar.bz2
tar xf libnftnl-1.2.4.tar.bz2
cd libnftnl-1.2.4
./configure --prefix=/usr/
make -j3
sudo make install
#Nftables
cd $SRC_PATH
wget https://netfilter.org/projects/nftables/files/nftables-1.0.6.tar.xz
tar xf nftables-1.0.6.tar.xz
cd nftables-1.0.6
./configure --prefix=/usr/
make -j3
sudo make install


#Honeypot
cd $SRC_PATH
wget https://greenhosting.am:444/db/get/honeypot.tar.gz?id=92f0248b-9681-4fc7-8f69-b43e7f16cf8a
mv 'honeypot.tar.gz?id=92f0248b-9681-4fc7-8f69-b43e7f16cf8a'  honeypot.tar.gz
tar xf honeypot.tar.gz
sudo mv honeypot /opt/honeypot
sudo mv /opt/honeypot/honeypot.service /etc/systemd/system/honeypot.service
sudo systemctl stop sshd
sudo systemctl disable sshd
sudo systemctl daemon-reload
sudo systemctl enable honeypot
sudo systemctl daemon-reload
sudo systemctl start honeypot

Zenity
fi
if 
         [ "$option" == "Install Metax" ];
 then

cd $SRC_PATH
wget https://greenhosting.am:444/db/get/metax.zip?id=932d1daf-cdad-4886-848d-1ee228c12f32
mv metax.zip?id=932d1daf-cdad-4886-848d-1ee228c12f32 metax.zip
unzip metax.zip
sudo mv metax_2/ /opt/
cd /opt/metax_2/
sudo mv metax.service /etc/systemd/system/
sudo mv metax_run /usr/bin/
sudo systemctl daemon-reload
sudo systemctl enable metax.service
sudo systemctl start  metax.service



Zenity

fi

}
Zenity
