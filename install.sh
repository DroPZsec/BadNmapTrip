#!/bin/sh
#[+] INSTALL SCRIPT
#[+] Coded by vDroPZz
#    Github @DroPZsec 
#

## COLORS

blue='\033[94m'
red='\033[91m'
green='\033[92m'
orange='\033[93m'
reset='\e[0m'
magenta='\u001b[35m'
yellow='\u001b[33m'

# SYSTEM UPDTAE 

echo $green "FIRST UPDATE & UPGRADE YOUR SYSTEM" $reset
echo 
echo 
echo 
echo $yellow "PRESS ''ENTER'' TO CONTINUE..." $reset
read 
clear 
echo $blue "COLLECTING UPDATE..." $reset
sudo apt-get update && sudo apt-get upgrade --yes
sudo apt-get install php mysql geoip mssql ipOps datafile dns sslcert proxy openssl mysql shortport stdnse string table lpeg-utility comm vulns http json table smb rand unpwdb httpspider smbauth base64 os datetime strbuf tab io creds url coroutine brute math anyconnect stringaux tableaux slaxml _G rand --yes 
echo $green "FINISH!" $reset

# SYSTEM UPGRADE

echo $green "NEXT STEP WILL COLLECT A FULL UPGRADE FOR YOUR LINUX" $reset
echo  
echo  
echo 
echo $yellow "PRESS ''ENTER'' TO CONTINUE..." $reset
read 
clear 
sudo apt-get install figlet --yes 
sudo apt-get full-upgrade --yes
chmod +x BadNmapTrip.sh
echo $green "FINISH!" $reset

# INSTALLING NMAP

echo $green "NEXT STEP WILL INSTALL OFFFICIAL NMAP" $reset
echo 
echo  
echo  
echo $yellow "PRESS ''ENTER'' TO CONTINUE..." $reset
read 
clear 
sudo apt-get install nmap --yes 
echo $green "FINISH!" $reset
echo $green "Start the Tool with ./BadNmapTrip.sh" $reset
exit
/bin/bash