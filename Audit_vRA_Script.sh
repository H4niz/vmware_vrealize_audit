#!/bin/bash

#Đã lâu rồi không viết gì. Nhân dịp đang tìm hiểu các best practice, checklist for hardening cho VMWare vRealize. Mình có tìm được một bài Secure Guide (https://docs.vmware.com/en/vRealize-Automation/7.2/vrealize-automation-72-hardening.pdf). Từ bài này mình viết lại các script để tiết kiệm thời gian cho quá trình thực hiện theo các checklist mà guide đưa ra. Share lại cho những ai cần!
#	A small script to check 

# Functions were defined here

LOG_PATH="`pwd`/`hostname`_`date +%d_%m_%y_%s`_log.txt"
CSV_PATH="`pwd`/`hostname`_`date +%d_%m_%y_%s`_log.csv"
touch $LOG_PATH
touch $CSV_PATH
# Output result
#Orange
_warning()	{
	echo -e "[\e[1m\e[33m$2\e[0m\t]\t$1\t\t\t\t\t\t"
}

#Red
_failure()	{
	echo -e "[\e[1m\e[31m$2\e[0m]\t$1\t\t\t\t\t\t"
}

#Green
_success()	{
	echo -e "[\e[1m\e[92m$2\e[0m\t]\t$1\t\t\t\t\t\t"
}

#Bolder
_note()	{
	echo -e "[\e[1mm$2\e[0m\t]\t$1\t\t\t\t\t\t"
}

#Tile
_title()	{
	echo -e "\t --*[ \e[1m$1\e[0m ]*--"
}
#Tile
_export_with_recommend()	{
	echo -e "$1,$2,$3,$4" >> $CSV_PATH
}




# Function check passwords, it'll verify that SHA512 was used.
check_password() {
	_title "1.2	Verify Root Password Hash and Complexity" >> $LOG_PATH
	_title "1.2	Verify Root Password Hash and Complexity"
	cat /etc/shadow | while read user; do
		_password=`echo "$user" | cut -d: -f2`
		_user=`echo "$user" | cut -d: -f1`
		type_hash=`echo "$_password" | cut -d$ -f2`
		if [[ ${#_password} -gt 8 ]]; then
			if [[ 6 -ne $type_hash ]]; then
				_failure `echo $_user` "FAILURE"
				_failure `echo $_user` "FAILURE" >> $LOG_PATH
				_export_with_recommend "1.2" "Verify Root Password Hash and Complexity" "FAILURE" "1 To verify the hash of the root password log in as root and run the # more /etc/shadow command. The hash information is displayed. Figure 8‑1.  Password Hash Results 2 If the root password does not contain a sha512 hash run the passwd command to change it. All hardened appliances enable enforce_for_root for the pw_history module found in the /etc/pam.d/common-password file. The system remembers the last five passwords by default. Old passwords are stored for each user in the /etc/securetty/passwd file."
			else
				_success `echo $_user` "SHA512"		
				_success `echo $_user` "SHA512" >> $LOG_PATH
				_export_with_recommend "1.2" "Verify Root Password Hash and Complexity" "SUCCESS" ""		
			fi
		fi

	done
}


check_password

check_password_expired()	{
	_title "1.3	Verify Password Expried" >> $LOG_PATH
	_title "1.3	Verify Password Expried"
	cat /etc/shadow | while read user; do
		_password=`echo "$user" | cut -d: -f2`
		_user=`echo "$user" | cut -d: -f1`
		_isexpired=`chage -l $_user | sed -n '2p' | cut -d: -f2`
		if [[ ${#_password} -gt 8 ]]; then
			if [[  $_isexpired == " never" ]]; then
				_failure `echo $_user` "FAILURE"
				_failure `echo $_user` "FAILURE" >> $LOG_PATH
				_export_with_recommend "1.3" "Verify Password Expried" "FAILURE" "1 Log in to your virtual appliance machines as root and run the following command to verify the password expiration on all accounts. # cat /etc/shadow The password expiration is the fifth field (fields are separated by colons) of the shadow file. The root expiration is set in days. Figure 8‑2.  Password Expiry Field 2 To modify the expiry of the root account run a command of the following form. # passwd -x 365 root In this command 365 specifies the number of days until password expiry. Use the same command to modify any user substituting the specific account for 'root' and replacing the number of days to meet the expiry standards of the organization."
			else
				_success `echo $_user` "OK"		
				_success `echo $_user` "OK" >> $LOG_PATH
				_export_with_recommend "1.3" "Verify Password Expried" "SUCCESS" ""	
			fi
		fi
	done
}
check_password_expired

check_secure_shell_root()	{
	_title "2.1	Secure Shell root User Account" >> $LOG_PATH
	_title "2.1	Secure Shell root User Account"
	isok=1
	cat /etc/ssh/ssh_config | while read line; do
		if [[ ${line:0:1} != "#" ]]; then
			if [[  ${line:0:10} == "AllowGroup" ]]; then
				if [[  ${line:(-5):5} != "wheel" ]]; then
					$isok=0
					_failure "2.1	Secure Shell root User Account" "AllowGroup"
					_failure "2.1	Secure Shell root User Account" "AllowGroup" >> $LOG_PATH
					_export_with_recommend "2.1" "Secure Shell root User Account" "FAILURE" "The wheel group is enabled with the pam_wheel module for superuser access so members of the wheel group can su-root where the root password is required. Group separation enables users to SSH to the appliance but not to su to root. Do not remove or modify other entries in the AllowGroups field which ensures proper appliance functionality. After making a change you must restart the SSH daemon by running the command: # service sshd restart."
				else
					_success "2.1	Secure Shell root User Account" "OK"		
					_success "2.1	Secure Shell root User Account" "OK" >> $LOG_PATH
					_export_with_recommend "2.1" "Secure Shell root User Account" "SUCCESS" ""
				fi
			elif [[  ${line:0:15} == "PermitRootLogin" ]]; then
				if [[  ${line:(-2):2} != "no" ]]; then
					$isok=0
					_success "2.1	Secure Shell root User Account" "PermitRootLogin"		
					_success "2.1	Secure Shell root User Account" "PermitRootLogin" >> $LOG_PATH
					_export_with_recommend "2.1" "Secure Shell root User Account" "FAILURE" "The wheel group is enabled with the pam_wheel module for superuser access so members of the wheel group can su-root where the root password is required. Group separation enables users to SSH to the appliance but not to su to root. Do not remove or modify other entries in the AllowGroups field which ensures proper appliance functionality. After making a change you must restart the SSH daemon by running the command: # service sshd restart."
				else
					_success "2.1	Secure Shell root User Account" "OK"		
					_success "2.1	Secure Shell root User Account" "OK" >> $LOG_PATH
					_export_with_recommend "2.1" "Secure Shell root User Account" "SUCCESS" ""
				fi
			fi
		fi
	done
	if [[ $isok -eq 1 ]]; then
		_success "2.1	Secure Shell root User Account" "OK"		
		_success "2.1	Secure Shell root User Account" "OK" >> $LOG_PATH
		_export_with_recommend "2.1" "Secure Shell root User Account" "SUCCESS" ""
	fi
}
check_secure_shell_root

check_local_admin_for_ssh()	{
	_title "2.3	Create Local Administrator Account for Secure Shell" >> $LOG_PATH
	_title "2.3	Create Local Administrator Account for Secure Shell"
	_rs=0
	cat /etc/shadow | while read user; do
		_user=`echo "$user" | cut -d: -f1`
		_group=`groups "$_user" | cut -d: -f2 | grep -e "root\|wheel\|sudo"`
	done
	_rs=$_rs+${#_group}
	if [[ _rs -lt 1 ]]; then
		_failure "2.3	Create Local Administrator Account for Secure Shell" "FAILURE"
		_failure "2.3	Create Local Administrator Account for Secure Shell" "FAILURE" >> $LOG_PATH
		_export_with_recommend "2.3" "Create Local Administrator Account for Secure Shell" \
			"FAILURE" \
			"1 Log in to the virtual appliance as root and run the following commands with the appropriate username. # useradd -g users <username> -G wheel -m -d /home/username              # passwd username Wheel is the group specified in AllowGroups for ssh access. To add multiple secondary groups use -G wheelsshd. 2 Switch to the user and provide a new password to enforce password complexity checking. # su –username     # username@hostname:~>passwd                  If the password complexity is met the password updates. If the password complexity is not met the password reverts to the original password and you must rerun the password command. 3 To remove direct login to SSH modify the/etc/ssh/sshd_config file by replacing (#)PermitRootLogin yes with PermitRootLogin no"
	else 
		_success "2.3	Create Local Administrator Account for Secure Shell" "OK"		
		_success "2.3	Create Local Administrator Account for Secure Shell" "OK"	 >> $LOG_PATH
		_export_with_recommend "2.3" "Create Local Administrator Account for Secure Shell" "SUCCESS" ""
	fi
}
check_local_admin_for_ssh

check_harden_secure_shell_server()	{
	_title "2.4	Harden the Secure Shell Server Configuration" >> $LOG_PATH
	_title "2.4	Harden the Secure Shell Server Configuration"
	result=0
	cat /etc/ssh/ssh_config | while read line; do
		if [[ ${line:0:1} != "#" ]]; then
			_protocol=`echo "$line" | grep "Protocol 2"`
			_cipher=`echo "$line" | grep "aes256-ctr"`
			_cipherr=`echo "$line" | grep "aes128-ctr"`
			_allow_forward=`echo "$line" | grep "AllowTCPForwarding no"`
			_allow_xforward=`echo "$line" | grep "X11Forwarding no"`
			_permittunnel=`echo "$line" | grep "PermitTunnel no"`
			_maxsession=`echo "$line" | grep "MaxSessions 1"`
			_useprevilege=`echo "$line" | grep "UsePrivilegeSeparation yes"`
			_esaauth=`echo "$line" | grep "RhostsESAAuthentication no"`
			_hmac=`echo "$line" | grep "hmac-sha1"`
			_permituserenv=`echo "$line" | grep "PermitUserEnvironment no1"`

		fi	
		result=${#_protocol}*${#_cipher}*${#_cipherr}*${#_allow_forward}*${#_allow_xforward}*${#_permittunnel}*${#_maxsession}*${#_useprevilege}*${#_esaauth}*${#_hmac}*${#_permituserenv}
	done
	if [[  $result -lt 1 ]]; then
		_failure "2.4	Harden the Secure Shell Server Configuration" "FAILURE"
		_failure "2.4	Harden the Secure Shell Server Configuration" "FAILURE" >> $LOG_PATH
		_export_with_recommend "2.4" "Harden the Secure Shell Server Configuration" \
			"FAILURE" \
			"Procedure 1 Open the /etc/ssh/sshd_config server configuration file on the VMware appliance and verify that the settings are correct. Setting Status Server Daemon Protocol Protocol 2 CBC Ciphers aes256-ctr and aes128-ctr TCP Forwarding AllowTCPForwarding no Server Gateway Ports Gateway Ports no X11 Forwarding X11Forwarding no SSH Service Use the AllowGroups field and specify a group permitted access. Add appropriate members to this group. GSSAPI Authentication GSSAPIAuthentication no if unused Keberos Authentication KeberosAuthentication no if unused Local Variables (AcceptEnv global option) Set to disabled by commenting out or enabled for LC_* or LANG variables Tunnel Configuration PermitTunnel no Network Sessions MaxSessions 1 User Concurrent Connections Set to 1 for root and any other user. The /etc/security/limits.conf file also needs to be configured with the same setting. Strict Mode Checking Strict Modes yes Privilege Separation UsePrivilegeSeparation yes rhosts RSA Authentication RhostsESAAuthentication no Compression Compression delayed or Compression no Secure Configuration Guide VMware Inc. 18 Setting Status Message Authentication code MACs hmac-sha1 User Access Restriction PermitUserEnvironment no 2 Save your changes and close the file."
	else
		_success "2.4	Harden the Secure Shell Server Configuration" "OK"
		_success "2.4	Harden the Secure Shell Server Configuration" "OK" >> $LOG_PATH
		_export_with_recommend "2.4" "Harden the Secure Shell Server Configuration" "SUCCESS" ""
	fi
}
check_harden_secure_shell_server

check_keyfile_permission()	{
	setperm=0
	ownroot=0
	_title "2.5	Maintain Secure Shell Key File Permissions" >> $LOG_PATH
	_title "2.5	Maintain Secure Shell Key File Permissions"
	ls -la  /etc/ssh/*key.pub | while read line; do
		issetperm=`echo "$line" | grep -e "\-rw\-r\-\-r\-\-"`
		if [[ ${#issetperm} -lt 1 ]]; then
			_failure "2.5	Maintain Secure Shell Key File Permissions" "0644"
			_failure "2.5	Maintain Secure Shell Key File Permissions" "0644" >> $LOG_PATH
			_export_with_recommend "2.5" "Maintain Secure Shell Key File Permissions" "FAILURE" "Procedure 1 View the public host key filesǰ located in /etc/ssh/*key.pub. Chapter 8 Secure Configuration VMware Inc. 23 2 Verify that these files are owned by root that the group is owned by root and that the files have permissions set to 0644. The permissions are (-rw-r--r--). 3 Close all filesǯ 4 View the public host key filesǰ located in /etc/ssh/*key. 5 Verify that these file are owned by root that the group is owned by root and that the files have permissions set to 0600. The permissions are (-rw-------). 6 Close all files"
		fi
	done

	ls -la  /etc/ssh/*key | while read line; do
		ownroot=`echo "$line" | grep -e "\-rw\-\-\-\-\-\-"`
		if [[ ${#ownroot} -lt 1 ]]; then
			_failure "2.5	Maintain Secure Shell Key File Permissions" "0600"
			_failure "2.5	Maintain Secure Shell Key File Permissions" "0600" >> $LOG_PATH
			_export_with_recommend "2.5" "Maintain Secure Shell Key File Permissions" "FAILURE" "Procedure 1 View the public host key filesǰ located in /etc/ssh/*key.pub. Chapter 8 Secure Configuration VMware Inc. 23 2 Verify that these files are owned by root that the group is owned by root and that the files have permissions set to 0644. The permissions are (-rw-r--r--). 3 Close all filesǯ 4 View the public host key filesǰ located in /etc/ssh/*key. 5 Verify that these file are owned by root that the group is owned by root and that the files have permissions set to 0600. The permissions are (-rw-------). 6 Close all files"
		fi
	done
	if [[ ${#issetperm} -gt 2 && ${#ownroot} -gt 2 ]]; then
		_success "2.5	Maintain Secure Shell Key File Permissions" "OK"
		_success "2.5	Maintain Secure Shell Key File Permissions" "OK" >> $LOG_PATH
		_export_with_recommend "2.5" "Maintain Secure Shell Key File Permissions" "SUCCESS" ""
	fi
}
check_keyfile_permission

check_xss_protection()	{
	_title "6.3.	Configure X-XSS-Protection Response Header"
	_title "6.3.	Configure X-XSS-Protection Response Header" >> $LOG_PATH
	rs=`grep -e " X-XSS-Protection:\|rspadd X-XSS-Protection:\|mode=block"  "/etc/haproxy/conf.d/20-vcac.cfg"` > /dev/null 2>&1
	if [[ ${#rs} -lt 80 ]]; then
		_failure "6.3.	Configure X-XSS-Protection Response Header" "FAILURE"
		_failure "6.3.	Configure X-XSS-Protection Response Header" "FAILURE" >> $LOG_PATH
		_export_with_recommend "6.3" "Configure X-XSS-Protection Response Header" "FAILURE" "Procedure 1 Open /etc/haproxy/conf.d/20-vcac.cfg for editing. 2 Add the following lines in a front end section: rspdel X-XSS-Protection:\ 1;\ mode=block rspadd X-XSS-Protection:\ 1;\ mode=block 3 Reload the HAProxy configuration using the following command. /etc/init.d/haproxy reload"
	else 
		_success "6.3.	Configure X-XSS-Protection Response Header" "OK"
		_success "6.3.	Configure X-XSS-Protection Response Header" "OK" >> $LOG_PATH
	fi
}
check_xss_protection

check_http_strict_header()	{
	_title "6.4.	Configure HTTP Strict Transport Security Response Header"
	_title "6.4.	Configure HTTP Strict Transport Security Response Header" >> $LOG_PATH
	rs=`grep -e " Strict-Transport-Security:\|rspadd X-XSS-Protection:\|max-age=31536000"  "/etc/haproxy/conf.d/20-vcac.cfg"` > /dev/null 2>&1
	if [[ ${#rs} -lt 100 ]]; then
		_failure "6.4.	Configure HTTP Strict Transport Security Response Header" "FAILURE"
		_failure "6.4.	Configure HTTP Strict Transport Security Response Header" "FAILURE" >> $LOG_PATH
		_export_with_recommend "6.4" "Configure HTTP Strict Transport Security Response Header" "FAILURE" "Procedure 1 Open /etc/haproxy/conf.d/20-vcac.cfg for editing. 2 Add the following lines in a front end section: rspdel Strict-Transport-Security:\ max-age=31536000 rspadd Strict-Transport-Security:\ max-age=31536000 3 Reload the HAProxy configuration using the following command. /etc/init.d/haproxy reload"
	else 
		_success "6.4.	Configure HTTP Strict Transport Security Response Header" "OK"
		_success "6.4.	Configure HTTP Strict Transport Security Response Header" "OK" >> $LOG_PATH
	fi
}
check_http_strict_header

check_xframe_header()	{
	_title "6.5.	Configure X-Frame-Options Response Header"
	_title "6.5.	Configure X-Frame-Options Response Header" >> $LOG_PATH
	rs=`grep -e " X-Frame-Options:\|SAMEORIGIN"  "/etc/haproxy/conf.d/20-vcac.cfg"` > /dev/null 2>&1
	if [[ ${#rs} -lt 36 ]]; then
		_failure "6.5.	Configure X-Frame-Options Response Header" "FAILURE"
		_failure "6.5.	Configure X-Frame-Options Response Header" "FAILURE" >> $LOG_PATH
		_export_with_recommend "6.5" "Configure X-Frame-Options Response Header" "FAILURE" "Procedure 1 Open /etc/haproxy/conf.d/20-vcac.cfg for editing. 2 Locate the following line in the front end section: rspadd X-Frame-Options:\ SAMEORIGIN 3 Add the following lines before the line you located in the preceding step: rspdel X-Frame-Options:\ SAMEORIGIN 4 Reload the HAProxy configuration using the following command. /etc/init.d/haproxy reload"
	else 
		_success "6.5.	Configure X-Frame-Options Response Header" "OK"
		_success "6.5.	Configure X-Frame-Options Response Header" "OK" >> $LOG_PATH
	fi
}
check_xframe_header

check_xframe_header()	{
	_title "7.1.	Configure the Lighttpd Server Response Header"
	_title "7.1.	Configure the Lighttpd Server Response Header" >> $LOG_PATH
	rs=`grep -e "server.tag = \" \""  "/opt/vmware/etc/lighttpd/lighttpd.conf"` > /dev/null 2>&1
	if [[ ${#rs} -lt 16 ]]; then
		_failure "7.1.	Configure the Lighttpd Server Response Header" "FAILURE"
		_failure "7.1.	Configure the Lighttpd Server Response Header" "FAILURE" >> $LOG_PATH
		_export_with_recommend "7.1" "Configure the Lighttpd Server Response Header" "FAILURE" "Procedure 1 Open the /opt/vmware/etc/lighttpd/lighttpd.conf file in a text editor. 2 Add the server.tag = " " to the fileǯ 3 Save your changes and close the fileǯ 4 Restart the lighĴpd server by running the # /opt/vmware/etc/init.d/vami-lighttp restart command.
"
	else 
		_success "7.1.	Configure the Lighttpd Server Response Header" "OK"
		_success "7.1.	Configure the Lighttpd Server Response Header" "OK" >> $LOG_PATH
	fi
}
check_xframe_header

check_TCPResponse_header()	{
	_title "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance"
	_title "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance" >> $LOG_PATH
	rs=`grep -e " server = \" \""  "/etc/vco/app-server/server.xml"` > /dev/null 2>&1
	if [[ ${#rs} -lt 11 ]]; then
		_failure "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance" "FAILURE"
		_failure "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance" "FAILURE" >> $LOG_PATH
		_export_with_recommend "7.2" "Configure the TCServer Response Header for the vRealize Automation Appliance" "FAILURE" "Procedure 1 Open the /etc/vco/app-server/server.xml file in a text editor. 2 In each element add server=" ". For example: 3 Save your changes and close the fileǯ 4 Restart the server using the following command. service vco-server restart"
	else 
		_success "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance" "OK"
		_success "7.2.	Configure the TCServer Response Header for the vRealize Automation Appliance" "OK" >> $LOG_PATH
	fi
}
check_TCPResponse_header


check_session_timeout()	{
	_title "7.4.	Set vRealize Automation appliance Session Timeout"
	_title "7.4.	Set vRealize Automation appliance Session Timeout" >> $LOG_PATH
	rs=`grep -e "<session-timeout>"  "/usr/lib/vcac/server/webapps/vcac/WEB-INF/web.xml"`
	if [[ ${#rs} -lt 36 ]]; then
		_failure "7.4.	Set vRealize Automation appliance Session Timeout" "FAILURE"
		_failure "7.4.	Set vRealize Automation appliance Session Timeout" "FAILURE" >> $LOG_PATH
		_export_with_recommend "7.4" "Set vRealize Automation appliance Session Timeout" "FAILURE" "Procedure 1 Open the /etc/vco/app-server/server.xml file in a text editor. 2 In each element add server=" ". For example: 3 Save your changes and close the fileǯ 4 Restart the server using the following command. service vco-server restart"
	else 
		_success "7.4.	Set vRealize Automation appliance Session Timeout" "OK"
		_success "7.4.	Set vRealize Automation appliance Session Timeout" "OK" >> $LOG_PATH
	fi
}
check_session_timeout

check_usb_mass_storage()	{
	_title "8.1.	Secure the USB Mass Storage Handler"
	_title "8.1.	Secure the USB Mass Storage Handler" >> $LOG_PATH
	rs=`grep -e "install usb-storage /bin/true"  "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 36 ]]; then
		_failure "8.1.	Secure the USB Mass Storage Handler" "FAILURE"
		_failure "8.1.	Secure the USB Mass Storage Handler" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.1" "Secure the USB Mass Storage Handler" "FAILURE" "Procedure 1 Open the/etc/modprobe.conf.local file in a text editor. 2 Ensure that the install usb-storage /bin/true line appears in the fileǯ 3 Save the file and close it."
	else 
		_success "8.1.	Secure the USB Mass Storage Handler" "OK"
		_success "8.1.	Secure the USB Mass Storage Handler" "OK" >> $LOG_PATH
	fi
}
check_usb_mass_storage

check_bluetooth_protocol()	{
	_title "8.2.	Secure the Bluetooth Protocol Handler"
	_title "8.2.	Secure the Bluetooth Protocol Handler" >> $LOG_PATH
	rs=`grep -e "install bluetooth /bin/true"  "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 36 ]]; then
		_failure "8.2.	Secure the Bluetooth Protocol Handler" "FAILURE"
		_failure "8.2.	Secure the Bluetooth Protocol Handler" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.2" "Secure the Bluetooth Protocol Handler" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. Chapter 8 Secure Configuration VMware Inc. 41 2 Ensure that the following line appears in this fileǯ install bluetooth /bin/true 3 Save the file and close it"
	else 
		_success "8.2.	Secure the Bluetooth Protocol Handler" "OK"
		_success "8.2.	Secure the Bluetooth Protocol Handler" "OK" >> $LOG_PATH
	fi
}
check_bluetooth_protocol

check_stream_control_transmission()	{
	_title "8.3.	Secure the Stream Control Transmission Protocol"
	_title "8.3.	Secure the Stream Control Transmission Protocol" >> $LOG_PATH
	rs=`grep -e "install sctp /bin/true"  "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 36 ]]; then
		_failure "8.3.	Secure the Stream Control Transmission Protocol" "FAILURE"
		_failure "8.3.	Secure the Stream Control Transmission Protocol" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.3" "Secure the Stream Control Transmission Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the following line appears in this fileǯ install sctp /bin/true 3 Save the file and close it."
	else 
		_success "8.3.	Secure the Stream Control Transmission Protocol" "OK"
		_success "8.3.	Secure the Stream Control Transmission Protocol" "OK" >> $LOG_PATH
	fi
}
check_stream_control_transmission

check_datagram_congrestion_protocol()	{
	_title "8.4.	Secure the Datagram Congestion Protocol"
	_title "8.4.	Secure the Datagram Congestion Protocol" >> $LOG_PATH
	rs=`grep -e "install dccp/bin/true\|install dccp_ipv4/bin/true\|install dccp_ipv6/bin/true"  "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 70 ]]; then
		_failure "8.4.	Secure the Datagram Congestion Protocol" "FAILURE"
		_failure "8.4.	Secure the Datagram Congestion Protocol" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.4" "Secure the Datagram Congestion Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the DCCP lines appear in the fileǯ install dccp/bin/true install dccp_ipv4/bin/true install dccp_ipv6/bin/true 3 Save the file and close it."
	else 
		_success "8.4.	Secure the Datagram Congestion Protocol" "OK"
		_success "8.4.	Secure the Datagram Congestion Protocol" "OK" >> $LOG_PATH
	fi
}
check_datagram_congrestion_protocol

check_secure_bridging()	{
	_title "8.5.	Secure Network Bridging"
	_title "8.5.	Secure Network Bridging" >> $LOG_PATH
	rs=`grep -e "install bridge /bin/false"  "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 70 ]]; then
		_failure "8.5.	Secure Network Bridging" "FAILURE"
		_failure "8.5.	Secure Network Bridging" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.5" "Secure Network Bridging" "FAILURE" "Procedure 1 Run the following command on all VMware virtual appliance host machines. # rmmod bridge 2 Open the /etc/modprobe.conf.local file in a text editor. Secure Configuration Guide 42 VMware Inc. 3 Ensure that the following line appears in this fileǯ install bridge /bin/false 4 Save the file and close it."
	else 
		_success "8.5.	Secure Network Bridging" "OK"
		_success "8.5.	Secure Network Bridging" "OK" >> $LOG_PATH
	fi
}
check_secure_bridging

check_reliable_datagram_socket()	{
	_title "8.6.	Secure Reliable Datagram Sockets Protocol"
	_title "8.6.	Secure Reliable Datagram Sockets Protocol" >> $LOG_PATH
	rs=`grep -e "install rds /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
	if [[ ${#rs} -lt 20 ]]; then
		_failure "8.6.	Secure Reliable Datagram Sockets Protocol" "FAILURE"
		_failure "8.6.	Secure Reliable Datagram Sockets Protocol" "FAILURE" >> $LOG_PATH
		_export_with_recommend "8.6" "Secure Reliable Datagram Sockets Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the install rds /bin/true line appears in this fileǯ 3 Save the file and close it."
	else 
		_success "8.6.	Secure Reliable Datagram Sockets Protocol" "OK"
		_success "8.6.	Secure Reliable Datagram Sockets Protocol" "OK" >> $LOG_PATH
	fi
}
check_reliable_datagram_socket

# ------------------------
secure_transparent_inter-process_communication_protocol() {
 _title "8.7.	Secure Transparent Inter-Process Communication Protocol"
 _title "8.7.	Secure Transparent Inter-Process Communication Protocol" >> $LOG_PATH
 rs=`grep -e "install tipc /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
 if [[ ${#rs} -lt 21 ]]; then
     _failure "8.7.	Secure Transparent Inter-Process Communication Protocol" "FAILURE"
     _failure "8.7.	Secure Transparent Inter-Process Communication Protocol" "FAILURE" >> $LOG_PATH
     _export_with_recommend "8.7" "Secure Transparent Inter-Process Communication Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the install tipc /bin/true line appears in this fileǯ 3 Save the file and close it."
 else 
     _success "8.7.	Secure Transparent Inter-Process Communication Protocol" "OK"
     _success "8.7.	Secure Transparent Inter-Process Communication Protocol" "OK" >> $LOG_PATH
 fi
}
secure_transparent_inter-process_communication_protocol


secure_internetwork_packet_exchange_protocol() {
 _title "8.8.	Secure Internetwork Packet Exchange Protocol"
 _title "8.8.	Secure Internetwork Packet Exchange Protocol" >> $LOG_PATH
 rs=`grep -e "install ipx /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
 if [[ ${#rs} -lt 20 ]]; then
     _failure "8.8.	Secure Internetwork Packet Exchange Protocol" "FAILURE"
     _failure "8.8.	Secure Internetwork Packet Exchange Protocol" "FAILURE" >> $LOG_PATH
     _export_with_recommend "8.8" "Secure Internetwork Packet Exchange Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the following line appears in this fileǯ install ipx /bin/true 3 Save the file and close it"
 else 
     _success "8.8.	Secure Internetwork Packet Exchange Protocol" "OK"
     _success "8.8.	Secure Internetwork Packet Exchange Protocol" "OK" >> $LOG_PATH
 fi
}
secure_internetwork_packet_exchange_protocol


secure_appletalk_protocol() {
 _title "8.9.	Secure Appletalk Protocol"
 _title "8.9.	Secure Appletalk Protocol" >> $LOG_PATH
 rs=`grep -e "install appletalk /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
 if [[ ${#rs} -lt 26 ]]; then
     _failure "8.9.	Secure Appletalk Protocol" "FAILURE"
     _failure "8.9.	Secure Appletalk Protocol" "FAILURE" >> $LOG_PATH
     _export_with_recommend "8.9" "Secure Appletalk Protocol" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the following line appears in this fileǯ install appletalk /bin/true 3 Save the file and close it."
 else 
     _success "8.9.	Secure Appletalk Protocol" "OK"
     _success "8.9.	Secure Appletalk Protocol" "OK" >> $LOG_PATH
 fi
}
secure_appletalk_protocol


secure_decnet_protocol() {
 _title "8.10.	Secure DECnet Protocol"
 _title "8.10.	Secure DECnet Protocol" >> $LOG_PATH
 rs=`grep -e "install decnet /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
 if [[ ${#rs} -lt 23 ]]; then
     _failure "8.10.	Secure DECnet Protocol" "FAILURE"
     _failure "8.10.	Secure DECnet Protocol" "FAILURE" >> $LOG_PATH
     _export_with_recommend "8.10" "Secure DECnet Protocol" "FAILURE" "Procedure 1 Open the DECnet Protocol /etc/modprobe.conf.local file in a text editor. 2 Ensure that the following line appears in this fileǯ install decnet /bin/true 3 Save the file and close it."
 else 
     _success "8.10.	Secure DECnet Protocol" "OK"
     _success "8.10.	Secure DECnet Protocol" "OK" >> $LOG_PATH
 fi
}
secure_decnet_protocol


secure_firewire_module() {
 _title "8.11.	Secure Firewire Module"
 _title "8.11.	Secure Firewire Module" >> $LOG_PATH
 rs=`grep -e "install ieee1394 /bin/true" "/etc/modprobe.conf.local"` > /dev/null 2>&1
 if [[ ${#rs} -lt 25 ]]; then
     _failure "8.11.	Secure Firewire Module" "FAILURE"
     _failure "8.11.	Secure Firewire Module" "FAILURE" >> $LOG_PATH
     _export_with_recommend "8.11" "Secure Firewire Module" "FAILURE" "Procedure 1 Open the /etc/modprobe.conf.local file in a text editor. 2 Ensure that the following line appears in this fileǯ install ieee1394 /bin/true 3 Save the file and close it."
 else 
     _success "8.11.	Secure Firewire Module" "OK"
     _success "8.11.	Secure Firewire Module" "OK" >> $LOG_PATH
 fi
}
secure_firewire_module


tcp_backlog_queue_size() {
	_title "10.2	Set TCP Backlog Queue Size"
	_title "10.2	Set TCP Backlog Queue Size" >> $LOG_PATH

	rs=`cat /proc/sys/net/ipv4/tcp_max_syn_backlog`

	if [ $rs -gt 1023 ]; then
		_success "10.2	Set TCP Backlog Queue Size" "OK"
		_success "10.2	Set TCP Backlog Queue Size" "OK" >> $LOG_PATH

	else
		_failure "10.2	Set TCP Backlog Queue Size" "FAILURE"
		_failure "10.2	Set TCP Backlog Queue Size" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.2" "Set TCP Backlog Queue Size" "FAILURE" "Procedure 1 Run the following command on each VMware appliance host machine. # cat /proc/sys/net/ipv4/tcp_max_syn_backlog 2 Open the /etc/sysctl.conf file in a text editor. 3 Set the default TCP backlog queue size by adding the following entry to the fileǯ net.ipv4.tcp_max_syn_backlog=1280 4 Save your changes and close the fileǯ"
	fi
}
tcp_backlog_queue_size

disabled_ipv4_arp() {
	_title "10.4	Disable IPv4 Proxy ARP"
	_title "10.4	Disable IPv4 Proxy ARP" >> $LOG_PATH

	rs=`grep [0] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.4	Disable IPv4 Proxy ARP" "OK"
		_success "10.4	Disable IPv4 Proxy ARP" "OK" >> $LOG_PATH

	else
		_failure "10.4	Disable IPv4 Proxy ARP" "FAILURE"
		_failure "10.4	Disable IPv4 Proxy ARP" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.4" "Disable IPv4 Proxy ARP" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv4/conf/*/proxy_arp|egrep \"default|all\" command on the VMware virtual appliance host machines to verify that IPv4 Proxy ARP is disabled. If IPv6 Proxy ARP is disabled on the host machines this command will return values of 0. /proc/sys/net/ipv4/conf/all/proxy_arp:0 /proc/sys/net/ipv4/conf/default/proxy_arp:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure IPv6 Proxy ARP on host machines open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv4.conf.default.proxy_arp=0 net.ipv4.conf.all.proxy_arp=0 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the fileǯ"
	fi
}
disabled_ipv4_arp

deny_ipv4_icmp_redirect() {
	_title "10.5	Deny IPv4 ICMP Redirect Messages"
	_title "10.5	Deny IPv4 ICMP Redirect Messages" >> $LOG_PATH

	rs=`grep [0] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.5	Deny IPv4 ICMP Redirect Messages" "OK"
		_success "10.5	Deny IPv4 ICMP Redirect Messages" "OK" >> $LOG_PATH

	else
		_failure "10.5	Deny IPv4 ICMP Redirect Messages" "FAILURE"
		_failure "10.5	Deny IPv4 ICMP Redirect Messages" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.5" "Deny IPv4 ICMP Redirect Messages" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_redirects|egrep \"default|all\" command on the VMwarevirtual appliance host machines to confirm that they deny IPv6 redirect messages. If the host machines are configured to deny IPv6 redirects this command returns the following: /proc/sys/net/ipv6/conf/all/accept_redirects:0 /proc/sys/net/ipv6/conf/default/accept_redirects:0 2 To configure a virtual appliance host machine to deny IPv4 redirect messages open the /etc/sysctl.conf file in a text editor. 3 Check the values of the lines that begin with net.ipv6.conf. If the values for the following entries in the are not set to zero or if the entries do not exist add them to the file or update the existing entries accordingly. net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 4 Save the changes and close the file."
	fi
}
deny_ipv4_icmp_redirect


deny_ipv6_icmp_redirect() {
	_title "10.6	Deny IPv6 ICMP Redirect Messages"
	_title "10.6	Deny IPv6 ICMP Redirect Messages" >> $LOG_PATH

	rs=`grep [0] /proc/sys/net/ipv4/conf/*/accept_redirects|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.6	Deny IPv6 ICMP Redirect Messages" "OK"
		_success "10.6	Deny IPv6 ICMP Redirect Messages" "OK" >> $LOG_PATH

	else
		_failure "10.6	Deny IPv6 ICMP Redirect Messages" "FAILURE"
		_failure "10.6	Deny IPv6 ICMP Redirect Messages" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.6" "Deny IPv6 ICMP Redirect Messages" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_redirects|egrep \"default|all\" command on the VMwarevirtual appliance host machines to confirm that they deny IPv6 redirect messages. If the host machines are configured to deny IPv6 redirects this command returns the following: /proc/sys/net/ipv6/conf/all/accept_redirects:0 /proc/sys/net/ipv6/conf/default/accept_redirects:0 2 To configure a virtual appliance host machine to deny IPv4 redirect messages open the /etc/sysctl.conf file in a text editor. 3 Check the values of the lines that begin with net.ipv6.conf. If the values for the following entries in the are not set to zero or if the entries do not exist add them to the file or update the existing entries accordingly. net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 4 Save the changes and close the file."
	fi
}
deny_ipv6_icmp_redirect


log_ipv4_martian_pkt() {
	_title "10.7	Log IPv4 Martian Packets"
	_title "10.7	Log IPv4 Martian Packets" >> $LOG_PATH

	rs=`grep [1] /proc/sys/net/ipv4/conf/*/log_martians|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.7	Log IPv4 Martian Packets" "OK"
		_success "10.7	Log IPv4 Martian Packets" "OK" >> $LOG_PATH

	else
		_failure "10.7	Log IPv4 Martian Packets" "FAILURE"
		_failure "10.7	Log IPv4 Martian Packets" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.7" "Log IPv4 Martian Packets" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv4/conf/*/rp_filter|egrep \"default|all\" command on the VMware virtual appliance host machines to verify that they use IPv4 reverse path filtering. If the virtual machines use IPv4 reverse path filtering this command returns the following: /proc/sys/net/ipv4/conf/all/rp_filter:1 /proc/sys/net/ipv4/conf/default/re_filter:1 If your virtual machines are configured correctly no further action is required. 2 If you need to configure IPv4 reverse path filtering on host machines open the /etc/sysctl.conf file in a text editor. Secure Configuration Guide VMware Inc. 53 3 Check the values of the lines that begin with net.ipv4.conf. If the values for the following entries are not set to 1 or if they do not exist add them to the file or update the existing entries accordingly. net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 4 Save the changes and close the file."
	fi
}
log_ipv4_martian_pkt

use_ipv4_reversepath_filtering() {
	_title "10.8	Use IPv4 Reverse Path Filtering"
	_title "10.8	Use IPv4 Reverse Path Filtering" >> $LOG_PATH

	rs=` grep [1] /proc/sys/net/ipv4/conf/*/rp_filter|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.8	Use IPv4 Reverse Path Filtering" "OK"
		_success "10.8	Use IPv4 Reverse Path Filtering" "OK" >> $LOG_PATH

	else
		_failure "10.8	Use IPv4 Reverse Path Filtering" "FAILURE"
		_failure "10.8	Use IPv4 Reverse Path Filtering" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.8" "Use IPv4 Reverse Path Filtering" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv4/conf/*/rp_filter|egrep \"default|all\" command on the VMware virtual appliance host machines to verify that they use IPv4 reverse path filtering. If the virtual machines use IPv4 reverse path filtering this command returns the following: /proc/sys/net/ipv4/conf/all/rp_filter:1 /proc/sys/net/ipv4/conf/default/re_filter:1 If your virtual machines are configured correctly no further action is required. 2 If you need to configure IPv4 reverse path filtering on host machines open the /etc/sysctl.conf file in a text editor. Secure Configuration Guide VMware Inc. 53 3 Check the values of the lines that begin with net.ipv4.conf. If the values for the following entries are not set to 1 or if they do not exist add them to the file or update the existing entries accordingly. net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.default.rp_filter=1 4 Save the changes and close the file."
	fi
}
use_ipv4_reversepath_filtering


check_ipv4_fwd() {
	_title "10.9	Deny IPv4 Forwarding"
	_title "10.9	Deny IPv4 Forwarding" >> $LOG_PATH

	rs=`cat /proc/sys/net/ipv4/ip_forward`

	if [ ${#rs} -eq 0 ]; then
		_success "10.9	Deny IPv4 Forwarding" "OK"
		_success "10.9	Deny IPv4 Forwarding" "OK" >> $LOG_PATH

	else
		_failure "10.9	Deny IPv4 Forwarding" "FAILURE"
		_failure "10.9	Deny IPv4 Forwarding" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.9" "Deny IPv4 Forwarding" "FAILURE" "Procedure 1 Run the # cat /proc/sys/net/ipv4/ip_forward command on the VMware appliance host machines to confirm that they deny IPv4 forwarding. If the host machines are configured to deny IPv4 forwarding this command will return a value of 0 for /proc/sys/net/ipv4/ip_forward. If the virtual machines are configured correctly no further action is necessary. 2 To configure a virtual appliance host machine to deny IPv4 forwarding open the /etc/sysctl.conf file in a text editor. 3 Locate the entry that reads net.ipv4.ip_forward=0. If the value for this entry is not currently set to zero or if the entry does not exist add it or update the existing entry accordingly. 4 Save any changes and close the file."

	fi
}
check_ipv4_fwd

check_ipv6_fwd() {
	_title "10.10.	Deny IPv6 Forwarding"
	_title "10.10.	Deny IPv6 Forwarding" >> $LOG_PATH

	rs=`grep [0] /proc/sys/net/ipv6/conf/*/forwarding|egrep "default|all"`

	if [ ${#rs} -gt 1 ]; then
		_success "10.10.	Deny IPv6 Forwarding" "OK"
		_success "10.10.	Deny IPv6 Forwarding" "OK" >> $LOG_PATH

	else
		_failure "10.10.	Deny IPv6 Forwarding" "FAILURE"
		_failure "10.10.	Deny IPv6 Forwarding" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.10" "Deny IPv6 Forwarding" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/forwarding|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 forwarding. If the host machines are configured to deny IPv6 forwarding this command will return the following: /proc/sys/net/ipv6/conf/all/forwarding:0 /proc/sys/net/ipv6/conf/default/forwarding:0 Secure Configuration Guide VMware Inc. 54 If the host machines are configured correctly no further action is necessary. 2 If you need to configure a host machine to deny IPv6 forwarding open the /etc/sysctl.conf file in a text editor. 3 Check the values of the lines that begin with net.ipv6.conf. If the values for the following entries are not set to zero or if the entries do not exist add the entries or update the existing entries accordingly. net.ipv6.conf.all.accept_redirects=0 net.ipv6.conf.default.accept_redirects=0 4 Save any changes you made and close the file."

	fi
}
check_ipv6_fwd


use_ipv4_tcp_syncookie() {
	_title "10.11.	Use IPv4 TCP Syncookies"
	_title "10.11.	Use IPv4 TCP Syncookies" >> $LOG_PATH

	cat /proc/sys/net/ipv4/tcp_syncookies | grep -v 1 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.11.	Use IPv4 TCP Syncookies" "OK"
		_success "10.11.	Use IPv4 TCP Syncookies" "OK" >> $LOG_PATH

	else
		_failure "10.11.	Use IPv4 TCP Syncookies" "FAILURE"
		_failure "10.11.	Use IPv4 TCP Syncookies" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.11" "Use IPv4 TCP Syncookies" "FAILURE" "Procedure 1 Run the # cat /proc/sys/net/ipv4/tcp_syncookies command on the VMware appliance host machines to verify that they use IPv4 TCP Syncookies. If the host machines are configured to deny IPv4 forwarding this command will return a value of 1 for /proc/sys/net/ipv4/tcp_syncookies. If the virtual machines are configured correctly no further action is necessary. 2 If you need to configure a virtual appliance to use IPv4 TCP Syncookies open the /etc/sysctl.conf in a text editor. 3 Locate the entry that reads net.ipv4.tcp_syncookies=1. If the value for this entry is not currently set to one or if it does not exist add the entry or update the existing entry accordingly. 4 Save any changes you made and close the file."

	fi
}
use_ipv4_tcp_syncookie


deny_ipv6_advertisement()	{
	_title "10.12.	Deny IPv6 Router Advertisements"
	_title "10.12.	Deny IPv6 Router Advertisements" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/accept_ra|egrep "default|all" | grep -v 0  > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.12.	Deny IPv6 Router Advertisements" "OK"
		_success "10.12.	Deny IPv6 Router Advertisements" "OK" >> $LOG_PATH
	else
		_failure "10.12.	Deny IPv6 Router Advertisements" "FAILURE"
		_failure "10.12.	Deny IPv6 Router Advertisements" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.12" "Deny IPv6 Router Advertisements" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_ra|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny router advertisements. If the host machines are configured to deny IPv6 router advertisements this command will return values of 0: /proc/sys/net/ipv6/conf/all/accept_ra:0 /proc/sys/net/ipv6/conf/default/accept_ra:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure a host machine to deny IPv6 router advertisements open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.accept_ra=0 net.ipv6.conf.default.accept_ra=0 If these entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."
	fi
}
deny_ipv6_advertisement


deny_ipv6_router_solicitations() {
	_title "10.13.	Deny IPv6 Router Solicitations"
	_title "10.13.	Deny IPv6 Router Solicitations" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/router_solicitations|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.13.	Deny IPv6 Router Solicitations" "OK"
		_success "10.13.	Deny IPv6 Router Solicitations" "OK" >> $LOG_PATH

	else
		_failure "10.13.	Deny IPv6 Router Solicitations" "FAILURE"
		_failure "10.13.	Deny IPv6 Router Solicitations" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.13" "Deny IPv6 Router Solicitations" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/router_solicitations|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 router solicitations. If the host machines are configured to deny IPv6 router advertisements this command will return the following: /proc/sys/net/ipv6/conf/all/router_solicitations:0 /proc/sys/net/ipv6/conf/default/router_solicitations:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure host machines to deny IPv6 router solicitations open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.router_solicitations=0 net.ipv6.conf.default.router_solicitations=0 Chapter 9 Configuring Host Network Security VMware Inc. 57 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes and close the file."

	fi
}
deny_ipv6_router_solicitations

deny_ipv6_router_preference_in_router_solicitations() {
	_title "10.14.	Deny IPv6 Router Preference in Router Solicitations"
	_title "10.14.	Deny IPv6 Router Preference in Router Solicitations" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_rtr_pref|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.14.	Deny IPv6 Router Preference in Router Solicitations" "OK"
		_success "10.14.	Deny IPv6 Router Preference in Router Solicitations" "OK" >> $LOG_PATH

	else
		_failure "10.14.	Deny IPv6 Router Preference in Router Solicitations" "FAILURE"
		_failure "10.14.	Deny IPv6 Router Preference in Router Solicitations" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.14" "Deny IPv6 Router Preference in Router Solicitations" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_rtr_pref|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 router solicitations. If the host machines are configured to deny IPv6 router advertisements this command will return the following: /proc/sys/net/ipv6/conf/all/accept_ra_rtr_pref:0 /proc/sys/net/ipv6/conf/default/accept_ra_rtr_pref:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure host machines to deny IPv6 route solicitations open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.accept_ra_rtr_pref=0 net.ipv6.conf.default.accept_ra_rtr_pref=0 If the entries do not exist or if their values not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."

	fi
}
deny_ipv6_router_preference_in_router_solicitations

deny_ipv6_router_prefix() {
	_title "10.15.	Deny IPv6 Router Prefix"
	_title "10.15.	Deny IPv6 Router Prefix" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_pinfo|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.15.	Deny IPv6 Router Prefix" "OK"
		_success "10.15.	Deny IPv6 Router Prefix" "OK" >> $LOG_PATH

	else
		_failure "10.15.	Deny IPv6 Router Prefix" "FAILURE"
		_failure "10.15.	Deny IPv6 Router Prefix" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.15" "Deny IPv6 Router Prefix" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_pinfo|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 router prefix information. If the host machines are configured to deny IPv6 router advertisements this command will return the following. /proc/sys/net/ipv6/conf/all/accept_ra_pinfo:0 /proc/sys/net/ipv6/conf/default/accept_ra_pinfo:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure host machines to deny IPv6 router prefix information open the /etc/sysctl.conf file in a text editor. Secure Configuration Guide 58 VMware Inc. 3 Check for the following entries. net.ipv6.conf.all.accept_ra_pinfo=0 net.ipv6.conf.default.accept_ra_pinfo=0 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes and close the file."

	fi

}
deny_ipv6_router_prefix

deny_ipv6_router_advertisement_hop_limit_settings() {
	_title "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings"
	_title "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_defrtr|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings" "OK"
		_success "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings" "OK" >> $LOG_PATH

	else
		_failure "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings" "FAILURE"
		_failure "10.16.	Deny IPv6 Router Advertisement Hop Limit Settings" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.16" "Deny IPv6 Router Advertisement Hop Limit Settings" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/accept_ra_defrtr|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 router hop limit seĴingsǯ If the host machines are configured to deny IPv6 router hop limit seĴingsǰ this command will return values of 0. /proc/sys/net/ipv6/conf/all/accept_ra_defrtr:0 /proc/sys/net/ipv6/conf/default/accept_ra_defrtr:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure a host machine to deny IPv6 router hop limit seĴingsǰ open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.autoconf=0 net.ipv6.conf.default.autoconf=0 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."

	fi

}
deny_ipv6_router_advertisement_hop_limit_settings

deny_ipv6_router_advertisement_autoconf_settings() {
	_title "10.17.	Deny IPv6 Router Advertisement Autoconf Settings"
	_title "10.17.	Deny IPv6 Router Advertisement Autoconf Settings" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/autoconf|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.17.	Deny IPv6 Router Advertisement Autoconf Settings" "OK"
		_success "10.17.	Deny IPv6 Router Advertisement Autoconf Settings" "OK" >> $LOG_PATH

	else
		_failure "10.17.	Deny IPv6 Router Advertisement Autoconf Settings" "FAILURE"
		_failure "10.17.	Deny IPv6 Router Advertisement Autoconf Settings" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.17" "Deny IPv6 Router Advertisement Autoconf Settings" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/autoconf|egrep \"default|all\" command on the VMware appliance host machines to verify that they deny IPv6 router autoconf seĴingsǯ If the host machines are configured to deny IPv6 router autoconf seĴingsǰ this command will return values of 0. /proc/sys/net/ipv6/conf/all/autoconf:0 /proc/sys/net/ipv6/conf/default/autoconf:0 If the host machines are configured correctly no further action is necessary. Chapter 9 Configuring Host Network Security VMware Inc. 59 2 If you need to configure a host machine to deny IPv6 router autoconf seĴingsǰ open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.autoconf=0 net.ipv6.conf.default.autoconf=0 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."

	fi

}
deny_ipv6_router_advertisement_autoconf_settings

deny_ipv6_neighbor_solicitations() {
	_title "10.18.	Deny IPv6 Neighbor Solicitations"
	_title "10.18.	Deny IPv6 Neighbor Solicitations" >> $LOG_PATH

	grep [01] /proc/sys/net/ipv6/conf/*/dad_transmits|egrep "default|all" | grep -v 0 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.18.	Deny IPv6 Neighbor Solicitations" "OK"
		_success "10.18.	Deny IPv6 Neighbor Solicitations" "OK" >> $LOG_PATH

	else
		_failure "10.18.	Deny IPv6 Neighbor Solicitations" "FAILURE"
		_failure "10.18.	Deny IPv6 Neighbor Solicitations" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.18" "Deny IPv6 Neighbor Solicitations" "FAILURE" "Procedure 1 Run the # grep [01] /proc/sys/net/ipv6/conf/*/dad_transmits|egrep \"default|all\" command on the VMware appliance host machines to confirm that they deny IPv6 neighbor solicitations. If the host machines are configured to deny IPv6 neighbor solicitations this command will return values of 0. /proc/sys/net/ipv6/conf/all/dad_transmits:0 /proc/sys/net/ipv6/conf/default/dad_transmits:0 If the host machines are configured correctly no further action is necessary. 2 If you need to configure a host machine to deny IPv6 neighbor solicitations open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.dad_transmits=0 net.ipv6.conf.default.dad_transmits=0 If the entries do not exist or if their values are not set to zero add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."

	fi

}
deny_ipv6_neighbor_solicitations

restrict_ipv6_max_addresses() {
	_title "10.19.	Restrict IPv6 Max Addresses"
	_title "10.19.	Restrict IPv6 Max Addresses" >> $LOG_PATH

	grep [1] /proc/sys/net/ipv6/conf/*/max_addresses|egrep "default|all" | grep -v 1 > /dev/null 2>&1

	if [ $? -eq 1 ]; then
		_success "10.19.	Restrict IPv6 Max Addresses" "OK"
		_success "10.19.	Restrict IPv6 Max Addresses" "OK" >> $LOG_PATH

	else
		_failure "10.19.	Restrict IPv6 Max Addresses" "FAILURE"
		_failure "10.19.	Restrict IPv6 Max Addresses" "FAILURE" >> $LOG_PATH
		_export_with_recommend "10.19" "Restrict IPv6 Max Addresses" "FAILURE" "Procedure 1 Run the # grep [1] /proc/sys/net/ipv6/conf/*/max_addresses|egrep \"default|all\" command on the VMware appliance host machines to verify that they restrict IPv6 max addresses appropriately. If the host machines are configured to restrict IPv6 max addresses this command will return values of 1. /proc/sys/net/ipv6/conf/all/max_addresses:1 /proc/sys/net/ipv6/conf/default/max_addresses:1 Secure Configuration Guide 60 VMware Inc. If the host machines are configured correctly no further action is necessary. 2 If you need to configure IPv6 max addresses on host machines open the /etc/sysctl.conf file in a text editor. 3 Check for the following entries. net.ipv6.conf.all.max_addresses=1 net.ipv6.conf.default.max_addresses=1 If the entries do not exist or if their values are not set to 1 add the entries or update the existing entries accordingly. 4 Save any changes you made and close the file."

	fi

}
restrict_ipv6_max_addresses

