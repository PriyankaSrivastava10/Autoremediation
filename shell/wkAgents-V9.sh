#!/bin/bash
###############Check McAfee Status############
function checkMcAfeeStatus() {
service cma status &>/dev/null
if [ $? -eq 0 ]; then
   echo "McAfee-Installed"
else
   echo "McAfee-NotInstalled"
fi
}
###############Check OpsRamp Status############
function checkOpsRampStatus() {
service vistara-agent status &>/dev/null || service opsramp-agent status &>/dev/null
if [ $? -eq 0 ]; then
   echo "OpsRamp-Installed"
else
   echo "OpsRamp-NotInstalled"
fi
}
###############Check SAM Status############
function checkSAMStatus() {
rpm -qa | grep -i snowagent &>/dev/null
if [ $? -eq 0 ]; then
   echo "SAM-Installed"
else
   echo "SAM-NotInstalled"
fi
}

###############Check epel  Status############
function checkepelStatus() {
yum repolist | grep epel &>/dev/null
if [ $? -ne 0 ]; then
   eplrpm=`rpm -qa | grep epel-release-*`
   if [ $? -eq 0 ]; then
     rpm -e $eplrpm >> /var/log/$(hostname)-WKVMAgents.log
     rm -f /etc/yum.repos.d/epel* >> /var/log/$(hostname)-WKVMAgents.log
   fi
   echo "EPEL-NotInstalled"
else
   echo "EPEL-Installed"
fi

}

###############Check SSM Status############
function checkSSMStatus() {
service amazon-ssm-agent status &>/dev/null
if [ $? -eq 0 ]; then
   echo "SSM-Installed"
else 
   echo "SSM-NotInstalled"
fi
}
###############Check Hostname############
function checkHostname() {
rgc=$1
if [ -z "$rgc" ]; then
   echo "Region code can't be null to check hostname"
   exit
fi   
if [[ $(hostname) =~ ^([A,Z]+)([A-Z0-9])+$ ]]; then
   hoststr=1
else
   hoststr=0
fi
len=`hostname | wc -m`
((len--))
pos=`hostname | grep -o -b "$rgc""P" | cut -d : -f 1`
if [ -z "$pos" ]; then
   pos=`hostname | grep -o -b "$rgc""N" | cut -d : -f 1`
   if [ -z "$pos" ]; then
      pos=0
   fi
fi
#echo "$hoststr $len $st $pos"
if [ $hoststr -eq 1 ] && [ $len -le 15 ] && [ $pos -eq 1 ]; then
  echo "Hostname $(hostname) is as per WK naming convention"
else
   echo "Hostname $(hostname) is not as per WK naming convention"
fi

}





#############Install McAfee###############
function installMcAfee() {
rpm -qa | grep -i unzip &> /dev/null
if [ "$?" -ne 0 ]; then
   yum install unzip -y &> /dev/null
   if [ $? -ne 0 ]; then
      echo "McAfee-Agent: McAfee could not be installed on $(hostname) as unzip utility is not installed"
      echo "$(date) McAfee-Agent: McAfee could not be installed as unzip utility is not installed" >> /var/log/$(hostname)-WKVMAgents.log
      continue
   fi   
fi
pu="$1"
cu="$2"
echo "Parent BU is $pu and child BU is $cu" >> /var/log/$(hostname)-WKVMAgents.log
if [ $pu = "N" ] || [ $cu = "N" ]; then
   echo " Please enter a valid value for parent and child BUs. McAfee agent can not be installed" >> /var/log/$(hostname)-WKVMAgents.log
   echo " Please enter a valid value for parent and child BUs. McAfee agent can not be installed"
   continue
fi	
cd /tmp/$(hostname)-wkagents
wget https://patchredhat.blob.core.windows.net/mcafee/MA.linux.506220.zip &> /dev/null          ##URI of McAfee agent 
wget https://patchredhat.blob.core.windows.net/mcafee/ENSTP.Linux.10.2.3.1459.gz &> /dev/null          ##URI of ENS
if [ -e MA.linux.506220.zip ]; then
   unzip MA.linux.506220.zip &> /dev/null
   sh install.sh -i &> /dev/null 
   if [ $? -eq 0 ]; then 
      echo "$(date) McAfee-Agent: McAfee Agent has been installed" >> /var/log/$(hostname)-WKVMAgents.log 
      echo "Status: McAfee Agent has been installed on $(hostname)"
   else
      echo "$(date) McAfee-Agent: McAfee Agent could not be installed" >> /var/log/$(hostname)-WKVMAgents.log
      echo "Status: McAfee-Agent: McAfee Agent could not be installed"
      continue
   fi	
		
   /opt/McAfee/agent/bin/maconfig -custom -prop1 $pu -prop2 $cu &> /dev/null
				
fi
if [ -e ENSTP.Linux.10.2.3.1459.gz ]; then
    tar -xzf ENSTP.Linux.10.2.3.1459.gz &> /dev/null
    sh install-isectp.sh silent &> /dev/null
    if [ $? -eq 0 ]; then 
       echo "$(date) ENS: ENS has been installed" >> /var/log/$(hostname)-WKVMAgents.log
       echo "Status: ENS has been installed on $(hostname)"
    else
      echo "$(date) ENS: ENS Agent could not be installed" >> /var/log/$(hostname)-WKVMAgents.log
      echo "Status: ENS Agent could not be installed on $(hostname)"
    fi		
		
fi         
}

#############Install OpsRamp###############
function installOpsRamp() {
oid="$1"
echo "Status: OpsRamp client id is $oid" >> /var/log/$(hostname)-WKVMAgents.log
if [ "$oid" != "N" ]; then
    cd /tmp/$(hostname)-wkagents
    wget -O deployAgent.py "https://wolterskluwer.vistarait.com/downloadagentNA.do?action=downloadInstallationScript&clientid=$oid&primaryChannelId=1&profile=0"
    script=`ls /tmp/$(hostname)-wkagents | grep -i deployAgent`
    if [ -e "$script" ]; then 
        python $script -i silent &> /dev/null
        if [ $? -eq 0 ]; then
         echo "Status: OpsRamp has been installed on $(hostname)"
         echo "$(date) OpsRamp-Agent: OpsRamp has been installed on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
        else
         echo "Status: OpsRamp could not be installed as python script did not execute successfully,please check"
         echo "$(date) OpsRamp-Agent: OpsRamp could not be installed as  python script did not execute successfully" >> /var/log/$(hostname)-WKVMAgents.log
        fi
	   
    else 
     echo "$(date) OpsRamp-Agent: Python script for OpsRamp agent could not be downloaded" >> /var/log/$(hostname)-WKVMAgents.log
    fi
fi
}

############Install SNOW Agent#################
function installSAM() {

cd /tmp/$(hostname)-wkagents
wget https://wktestrgdisks678.blob.core.windows.net/wkagents/wolterskluwer_Linux_corrected.zip &> /dev/null
unzip wolterskluwer_Linux_corrected.zip &> /dev/null
cd /tmp/$(hostname)-wkagents/wolterskluwer/
if [[ `arch` =~ "x86_64" ]]; then
   rpm -i wolterskluwer_snowagent-5.0.1-1.x86_64.rpm &> /dev/null
    if [ $? -eq 0 ]; then
      echo "$(date) SAM-Agent: SAMAgent has been installed" >> /var/log/$(hostname)-WKVMAgents.log
      echo "Status: SAM Agent has been installed on $(hostname)"
    else 
      echo "Status: Snow agent could not be installed on $(hostname)."
      echo "$(date) SAM-Agent: could not be installed on $(hostname)." >> /var/log/$(hostname)-WKVMAgents.log
      continue
    fi
else
    rpm -i wolterskluwer_snowagent-5.0.1-1.i386.rpm &> /dev/null
    if [ $? -eq 0 ]; then
      echo "$(date) SAM-Agent: SAMAgent has been installed" >> /var/log/$(hostname)-WKVMAgents.log
      echo "Status: SAM Agent has been installed on $(hostname)"
    else 
      echo "Status: Snow agent could not be installed on $(hostname)."
      echo "$(date) SAM-Agent: could not be installed on $(hostname)." >> /var/log/$(hostname)-WKVMAgents.log
    
    fi
fi
       
}

############Install SSM Agent#################
function installSSM(){
if [ -e /etc/cloud/cloud.cfg ]; then
    clp="AWS"
    echo "Detected cloud provider as AWS" >> /var/log/$(hostname)-WKVMAgents.log
    echo "Detected cloud provider as AWS"
    service amazon-ssm-agent status &> /dev/null
    if [ $? -ne 0 ]; then
        if [[ `arch` =~ "x86_64" ]]; then
           yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm &> /dev/null
            if [ $? -eq 0 ]; then
              service amazon-ssm-agent start &> /dev/null
              chkconfig amazon-ssm-agent on
              echo " $(date) SSM-Agent: SSM agent has been installed">>/var/log/$(hostname)-WKVMAgents.log
              echo "Status: SSM-Agent has been installed on $(hostname)"
            else 
              echo " $(date) SSM-Agent: SSM agent could not be installed">>/var/log/$(hostname)-WKVMAgents.log
              echo "Status: SSM-Agent could not be installed on $(hostname)"
            fi
        else
            yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_386/amazon-ssm-agent.rpm &> /dev/null
            if [ $? -eq 0 ]; then
               service amazon-ssm-agent start &> /dev/null
               chkconfig amazon-ssm-agent on
               echo " $(date) SSM-Agent: SSM agent has been installed">>/var/log/$(hostname)-WKVMAgents.log
               echo "Status: SSM-Agent has been installed on $(hostname)"
            else 
               echo " $(date) SSM-Agent: SSM agent could not be installed">>/var/log/$(hostname)-WKVMAgents.log
               echo "Status: SSM-Agent could not be installed on $(hostname)"
            fi
        fi 
    elif [[ `arch` =~ "x86_64" ]]; then
          yum upgrade -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm &> /dev/null
          echo " $(date) SSM-Agent: SSM agent is already  installed">>/var/log/$(hostname)-WKVMAgents.log
          echo "Status: SSM-Agent is already installed on $(hostname)"
    fi
else       
    service waagent status &> /dev/null
    if [ $? -eq 0 ]; then
       echo " $(date) SSM-Agent: It is an Azure instance and SSM can not be  installed">>/var/log/$(hostname)-WKVMAgents.log
       echo "Status: It is an azure instance and SSM can not be installed on $(hostname)"
    fi
    echo "It is not an AWS instance so SSM can not be installed on $(hostname)"
    echo "It is not an AWS instance so SSM can not be installed on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log

fi   
}
####################Install epel##########################
function installEPEL() {
cd /tmp/$(hostname)-wkagents
wget $1 &> /dev/null
pkg=`ls /tmp/$(hostname)-wkagents | grep epel-release`
rpm -i $pkg
echo "$(date) epel-repo: epel has been installed" >> /var/log/$(hostname)-WKVMAgents.log
echo "Status: epel repo has been installed on $(hostname)"
}


###############Check ADJoin###############
function checkADJoin() {
getent passwd | awk '/WKRAINIER\\rainiervmagent/'
if [ $? -eq 0 ]; then
   echo "Joined"
else   
   echo "NotJoined"
fi	
}

###############Check Firewall Status###############
function checkFirewall(){
echo $(cat /etc/system-release)
CHECK=$(cat /etc/system-release | grep "release 7")
if [ "$CHECK" ];
   then
      status=$(systemctl status firewalld)
          if [ -z "$status" ]
                then
                    echo "Firewalld-NotInstalled"

                else
                    echo "Firewalld-Installed"
                    status="$(systemctl status firewalld)"
                    if [[ "$status" =~ "inactive" ]]; then
                            echo "Enabling firewalld"
                            systemctl start firewalld
                            systemctl enable firewalld
                    fi
                    echo "Firewalld enabled"
        fi

        elif [ "$(cat /etc/system-release | grep "release 6" | grep -i centos)" ];
    then
      status="$(service iptables status)"
      if [[ "$status" =~ "Table" ]]; then
        echo "Iptables-Installed"
        echo "Cofiguring and enabling iptables for CentOS6.x"
        iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
                iptables -A INPUT -p icmp -j ACCEPT
                iptables -A INPUT -i lo -j ACCEPT
                iptables -A INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
                iptables -A INPUT -j REJECT --reject-with icmp-host-prohibited
                iptables -A FORWARD -j REJECT --reject-with icmp-host-prohibited
                service iptables save
                service iptables stop
                service iptables start
                chkconfig iptables on

        else
                echo "IpTables-NotInstalled"
        fi


fi
}

###############Install Firewall###############
function InstallFirewall() {
	echo $(cat /etc/system-release)
	CHECK=$(cat /etc/system-release | grep "release 7")
	if [ "$CHECK" ];
	   then
		  echo "installing Firewalld"
	      sudo yum install firewalld -y &> /dev/null
        if [ $? -eq 0 ]; then
         echo "Status: Firewalld has been installed on $(hostname)"
         echo "$(date) Firewalld has been installed on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
       
        fi
		  
	elif [ "$(cat /etc/system-release | grep "release 6" | grep -i centos)" ];
		then
			sudo yum install iptables -y &> /dev/null
			if [ $? -eq 0 ]; then
         echo "Status: IpTables has been installed on $(hostname)"
         echo "$(date) IpTables has been installed on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
		 fi

	fi
}

##############Enable UTC and NTP#############################
function enableUTCandNTP(){
logPath="/tmp/CustomScriptExtension_00_CommonLinuxTools.log"

ntpServers="server time.nist.gov iburst
server 0.pool.ntp.org iburst \n
server 1.pool.ntp.org iburst \n
server time1.google.com iburst \n
server time2.google.com iburst \n
server time3.google.com iburst \n server time4.google.com iburst"

initiation_system=$(ps -p 1 | sed -n '2p'| awk 'NF>1{print $NF}')

if [[ $initation_system == "init" ]]; then
        rm -rf /etc/localtime
        ln -s /usr/share/zoneinfo/UTC /etc/localtime

elif [[ $initation_system == "sysmtemd" ]]; then
        timedatectl set-timezone UTC
fi


#curl is needed for NTP
if ! hash curl 2>/dev/null
then
        echo "'curl' was not found in PATH"
        exit 1
fi

#the below check if VM is running on AWS
if [[ ! -z $(curl -s http://169.254.169.254/1.0/) ]]; then
        sudo yum -y erase ntp* >> /tmp/tmp.log
        sudo yum -y install chrony >> /tmp/tmp.log
        string1="server 169.254.169.123 prefer iburst"
        if [ -f /etc/chrony/chrony.conf ]; then
                FILE="/etc/chrony/chrony.conf"
                if grep -q "$string1" $FILEX;
                then
                #if [ ! -z $(grep "$string1" "$FILE") ]; then
                        echo "FOUND" >> /tmp/tmp.log
                else
                        echo $string1 >> $FILE
                fi
        elif [ -f /etc/chrony.conf ]; then
                FILEX="/etc/chrony.conf"
                if grep -q "$string1" $FILEX;
                then
                        echo "FOUND" >> /tmp/tmp.log;
                else
                        echo $string1 >> $FILEX
                fi

        fi


else

        sudo yum -y erase ntp* >> /tmp/tmp.log
        sudo yum -y install chrony >> /tmp/tmp.log
        if [ -f /etc/chrony/chrony.conf ]; then
                FILE="/etc/chrony/chrony.conf"
                if grep -q "$ntpServers" $FILE;
                then
                        echo "FOUND" >> /tmp/tmp.log
                else
                        echo $ntpServers >> $FILE
                fi
        elif [ -f /etc/chrony.conf ]; then
                FILE="/etc/chrony.conf"
                if grep -q "$ntpServers" $FILE;
                then
                        echo "FOUND" >> /tmp/tmp.log;
                else
                        echo $ntpServers >> $FILE
                fi

        fi


fi

if [[ $initation_system == "init" ]]; then
        /etc/rc.d/init.d/chronyd start
        chkconfig chronyd on

elif [[ $initation_system == "sysmtemd" ]]; then
        systemctl start chronyd
        systemctl enable chronyd
fi

echo "Status: UTC and NTP has been enabled on $(hostname)"
echo "$(date) UTC and NTP has been enabled on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
}


#########################################################
##########################Main Script Body##########################
cid=616093
bu='GBS'
cu='GBSIT'
touch /var/log/$(hostname)-WKVMAgents.log
if [ -e /etc/redhat-release ]; then
  if [[ `cat /etc/redhat-release` =~ ^([^0-9]+)\ ([0-9])\. ]]; then
    distro="${BASH_REMATCH[1]}"
    ver="${BASH_REMATCH[2]}"
  fi
else 
   echo "$(date) OS: It is not a Redhat or CentOS linux distribution" >> /var/log/$(hostname)-WKVMAgents.log
   #echo " $(hostname) is not a Redhat or CentOS distribution"
   exit 1
fi
#echo " Detected  $distro $ver"
echo "$(date)  OS: Detected  $distro $ver" >> /var/log/$(hostname)-WKVMAgents.log
rpm -qa | grep  wget >> /dev/null
if [ $? -ne 0 ]; then
    echo "Installing wget on $(hostname)" 
    echo "Installing wget on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
    yum install wget -y &> /dev/null
    if [ $? -ne 0 ]; then
        echo "$(date) wget command is not installed. Please check YUM for issues" >> /var/log/$(hostname)-WKVMAgents.log
	    echo "wget could not be installed on $(hostname). Please check YUM for issues"
        exit 1
    fi
fi

rpm -qa | grep  unzip >> /dev/null
if [ $? -ne 0 ]; then
    echo "Installing unzip on $(hostname)" 
    echo "Installing unzip on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
    yum install unzip -y &> /dev/null
    if [ $? -ne 0 ]; then
        echo "$(date) unzip command is not installed. Please check YUM for issues" >> /var/log/$(hostname)-WKVMAgents.log
	    echo "unzip could not be installed on $(hostname). Please check YUM for issues"
        exit 1
    fi
fi
 
if [ $# -eq 0 ]; then
    echo "Argument list is empty. Please enter set of arguments"
    exit 1 
fi	
mkdir -p /tmp/$(hostname)-wkagents

j=0
for i in $*
do
#echo "$i"
args[$j]="$i"
((j++))
done
opramp=''
sam=''
epelrepo=''
firewall=''
ntp=''
mcafee=''
ssm=''
#echo ${args[@]}
t=0
#echo -e "$(hostname)"
while [ $t -lt $j ] 
do
case ${args[$t]} in
    --checkOpsRampStatus) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    opramp=$(checkOpsRampStatus)
					
                fi					
		        ((t++))
                ;;
	--checkSAMStatus) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    sam=$(checkSAMStatus)
					
                fi					
		        ((t++))
                ;;
	--checkepelStatus) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    epelrepo=$(checkepelStatus)
					
                fi					
		        ((t++))
                ;;
	--checkFirewall) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    firewall=$(checkFirewall)
					
                fi					
		        ((t++))
                ;;
	--checkMcAfeeStatus) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    mcafee=$(checkMcAfeeStatus)
					
                fi					
		        ((t++))
                ;;
	--checkSSMStatus) 
	            ((t++))
	            if [ "${args[$t]}" = "Y" ]; then
                    ssm=$(checkSSMStatus)
					
                fi					
		        ((t++))
                ;;
	--checkHostname)
                ((t++))
                if [ "${args[$t]}" = "-regioncode" ]; then
	          	   ((t++))
			       rgcode=${args[$t]}
						  checkHostname $rgcode
			    else
                    echo "Not a valid argument. Hostname validity can't be checked"
			        exit	
                fi
                ((t++)) 
			    ;;
    --checkADJoin)
                ad=$(checkADjoin)
                ((t++)) 
			    ;;							  
    --installOpsRamp)
				
                ((t++))
				if [ "${args[$t]}" = "Y" ]; then
                    orampStatus=$(checkOpsRampStatus)
                    echo "$(date) OPSRAMP-Agent: OPSRAMP agent is $orampStatus on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
                    if [ "$orampStatus" = "OpsRamp-NotInstalled" ]; then
						  installOpsRamp $cid
                    fi
                else     
                    echo "$(date) OpsRamp-Agent: Install OpsRamp is not required on $(hostname) " >> /var/log/$(hostname)-WKVMAgents.log
                fi					
		        ((t++))
                ;;
	
    --installSAM)
				((t++))
				if [ "${args[$t]}" = "Y" ]; then
                    samStatus=$(checkSAMStatus)
                    echo "$(date) SAM-Agent: SAM agent is $samStatus on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
                    if [ "$samStatus" = "SAM-NotInstalled" ]; then
                           installSAM
                    fi
                else     
                    echo "$(date) SAM-Agent: Install SAM is not required on $(hostname) " >> /var/log/$(hostname)-WKVMAgents.log
                fi					
		        ((t++))
                ;;
	--InstallFirewall)
				((t++))
				if [ "${args[$t]}" = "Y" ]; then
                    firewall=$(checkFirewall)
                    echo "$(date) Firewall: SAM agent is $firewall on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
                    if [ "$firewall" = "Firewall-NotInstalled" ]; then
                           InstallFirewall
                    fi
                else     
                    echo "$(date) Firewall: Install Firewall is not required on $(hostname) " >> /var/log/$(hostname)-WKVMAgents.log
                fi					
		        ((t++))
                ;;
	--enableNTP)
				((t++))
				if [ "${args[$t]}" = "Y" ]; then
                    enableUTCandNTP
                    echo "$(date) NTP: NTP enabled on $(hostname) " >> /var/log/$(hostname)-WKVMAgents.log
                fi					
		        ((t++))
                ;;
	--InstallMcAfee)
				((t++))
				if [ "${args[$t]}" = "Y" ]; then
                    mcafee=$(checkMcAfeeStatus)
                    echo "$(date) McAfee: McAfee agent is $mcafee on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
                    if [ "$mcafee" = "McAfee-NotInstalled" ]; then
                           installMcAfee $bu $cu
                    fi
                else     
                    echo "$(date) McAfee: Install McAfee is not required on $(hostname) " >> /var/log/$(hostname)-WKVMAgents.log
                fi					
		        ((t++))
                ;;
   --installSSM)
		   ((t++))
		    if [ "${args[$t]}" = "Y" ]; then
                ssmStatus=$(checkSSMStatus)
		        echo "$(date) SSM-Agent: SSM is $ssmStatus on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
		        if [ "$ssmStatus" = "SSM-NotInstalled" ]; then
                   installSSM
                fi
            else     
                echo "$(date) SSM-Agent: SSM is not required to install on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
	        fi	
		   ((t++))
                ;;
   --installEPEL)
				((t++))
				if [[ "$distro" =~ "Red Hat" ]] || [[ "$distro" =~ "CentOS" ]]; then
                    if [ $ver -eq 7 ]; then
                        epelurl=https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
                    elif [ $ver -eq 6 ]; then
                         epelurl=http://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm
                    fi
                fi
		        if [ "${args[$t]}" = "Y" ]; then
                    epelStatus=$(checkepelStatus)
		            echo "$(date) epel-repo: epel repo is $epelStatus on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
		            if [ "$epelStatus" = "EPEL-NotInstalled" ]; then
                          installEPEL $epelurl
                    fi
                else     
                    echo "$(date) epel-repo: epel is not required on $(hostname)" >> /var/log/$(hostname)-WKVMAgents.log
                fi
	            ((t++))
                ;;
 
esac
done
cd /tmp
rm -rf ./$(hostname)-wkagents/
if [ ! -z "$opramp" ] || [ ! -z "$sam" ] || [ ! -z "$epelrepo" ] || [ ! -z "$epelrepo" ] || [ ! -z "$firewall" ] || [ ! -z "$ntp" ] || [ ! -z "$mcafee" ]; then
   echo -e "$(hostname)"" $opramp"" $sam" " $epelrepo"" $ssm"" $firewall"" $ntp"" $mcafee"
fi   
