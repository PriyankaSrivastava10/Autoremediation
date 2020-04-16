 Param(
       $CheckAgents,
       $InstallAgents,
       $OpsRampClientID,
       $OpsRamp,
       $Mcafee,
       $SAM,
       $OUPath,
       $CU = 'GBSIT',
       $BU = 'GBS',
	     $Falcon
     ) 

function CheckOpsRmapStatus
{
 $OpsRamp = Get-Service -Name "VistaraAgent" 2> Out-Null
 if ($OpsRamp.Status -match 'Running' -or $OpsRamp.Status -match 'Stopped')
 {
  Write-Output "OpsRamp-Installed" 
 } 
 else
 {
  Write-Output "OpsRamp-NotInstalled"
 }
}

function CheckSnowStatus
{
 $Snow = Get-Service -Name "Snow*" 2> Out-Null
 if ($Snow.Status -match 'Running' -or $Snow.Status -match 'Stopped')
 {
  Write-Output "Snow-Installed" 
 } 
 else
 {
  Write-Output "Snow-NotInstalled"
 }
}

function CheckMcAfeeStatus
{
 $McAfee = Get-Service -Name "McAfee*" 2> Out-Null
 if ($McAfee.Status -match 'Running' -or $McAfee.Status -match 'Stopped' )
{
 Write-Output "McAfee-Installed" 
 } 
else
 {
  Write-Output "McAfee-NotInstalled"
 }
}

function CheckFalconStatus
{

#### Check if Omni is Installed
if((Get-Service $OldServiceName -ErrorAction Ignore | ft -HideTableHeaders) -or (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$OldAppName" }))
{
Write-Host "OmniAgent Installed";
}
     else { 

Write-Host "OmniAgent not installed"; }

####### Check if CrowdStrike Sensor is installed ###############

            if((((Get-Service $NewServiceName -ErrorAction Ignore | ft -HideTableHeaders).Status) -eq "Running") -or (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$NewAppName" }))
            {
Write-Host "Falcon Agent Installed.";
            }
            else {
Write-Host "$Falcon Agent Not Installed.";}
            
        

#####Check if Falcon collector is installed####################

###Check if uploadstatus is 200
##date/time stamp as a data value
if(((Get-ItemProperty -Path 'HKLM:\SOFTWARE\CrowdStrike\FFC' -Name UploadStatus -ErrorAction SilentlyContinue | ft -HideTableHeaders).UploadStatus -eq 200) -and ((Get-ItemProperty -Path 'HKLM:\SOFTWARE\CrowdStrike\FFC' -Name Uploaded -ErrorAction SilentlyContinue).Uploaded))
{
 Write-Host "Falcon Collector Installed "
}
else {
Write-Host "Falcon Collector Not Installed"
}


}

function InsOpsRamp
{
 Param($OpsRampClientID)
 $Status = CheckOpsRmapStatus
 if ($Status -match 'NotInstalled')
 {
  New-Item -ItemType Directory -Force -Path  "C:\$(Hostname)-WKAgents-OpsR"
  $Dst = "C:\$(Hostname)-WKAgents-OpsR\OpsRamp.exe"
  $Src = "https://wolterskluwer.vistarait.com/downloadagentNA.do?action=downloadAgent&clientid=$OpsRampClientID&primaryChannelId=1&profile=0"
  #Write-Output $Src
  Invoke-WebRequest $Src -OutFile $Dst 
  $Time = 0
  
  while ($true)
  {
    Get-Item $Dst 2> Out-Null
    if ($? -eq 'True' -or $Time -le 180)
    {
      break
    }
    Start-Sleep -Seconds 10
    $Time +=10
  }
  <#Set-Location "C:\$(Hostname)-WKAgents\"
  .\OpsRamp.exe#>
  Invoke-Command -scriptblock {"C:\$(Hostname)-WKAgents\OpsRamp.exe"} | Out-Null
  
  Write-Output "OpsRamp installed"
  
 }
 
}

function InsSnow
{
 $Status = CheckSnowStatus
 if ($Status -match 'NotInstalled')
 {
  
  New-Item -ItemType Directory -Force -Path "C:\$(Hostname)-WKAgents-SAM" 
  $Src = "https://s3.amazonaws.com/wksamagentbucket/wolterskluwer_snowagent-5.3.0.x64.msi"
  $Dst = "C:\$(Hostname)-WKAgents-SAM\snowagent.msi"
  Invoke-WebRequest $Src -OutFile $Dst
  MsiExec /i $Dst /qn
  Write-Output "SAM installed"
  
 }
 
}

#function ConfMcAfee
#{
#  param ($CustomProps)
  #Write-Output $CustomProps
 # $WorkingDir = "C:\$(Hostname)-WKAgents"
  #$Time = 0
  #write-Output "Installing McAfee agent....."
  #cd $WorkingDir
  #Start-Process "$WorkingDir\FramePkg_505658.exe" -ArgumentList $CustomProps
  #while ( $true)
#  $InsSoft = Get-WmiObject -Class Win32_Product | where Name -Match 'McAfee Agent' 2> Out-Null
#   if ($InsSoft.Name -eq 'McAfee Agent')
#    {
#      #$args = [System.Collections.ArrayList] @("/REBOOT=R","/q")
#      Start-Process "$WorkingDir\VSE.win.8801804\SetupVSE.Exe" -ArgumentList "/REBOOT=R /q"
#      break
#    }
#
#   if ($Time -gt 300 )
#
#    {
#     Write-Output "McAfee agent  can't be installed"
#     break 
#    }
#
#              Start-Sleep -Seconds 5
#              $Time = $Time + 5
#              #Write-Output "."
#   }
           
#   if( $Time -le 300)
#   {
#     $Time = 0
#     while ( $true)
#      {
#        $InsSoft = Get-WmiObject -Class Win32_Product | where Name -Match 'McAfee VirusScan Enterprise' 2> Out-Null
#        if ($InsSoft.Name -eq 'McAfee VirusScan Enterprise')
##         {
 #           Write-Output "McAfee agent has been installed"
#            break
#         }
#
#        if ($Time > 300 )
#
#         {
#           Write-Output "McAfee agent  can't be installed"
#           break 
#         }

#         Start-Sleep -Seconds 5
#         $Time = $Time + 5
#      }
#    }
#    $Services= "macmnsvc","McAfeeFramework","masvc"
#    foreach($service in $Services)
#    {
#      Set-Service -name $service -StartupType Manual -Status Stopped 2> Out-Null
#    }
            
#}

function InsMcAfee
{
#  Param($OUPath,$BU,$CU)
  $Status = CheckMcAfeeStatus
  if ($Status -match 'NotInstalled')
  {
 ########Installing McAfee Virus Scan #########################
   $Src = "https://use1gbsstap1vmautomation.blob.core.windows.net/software/McAfee_Latest.zip"
   $Dst = "C:\$(Hostname)-WKAgents\McAfee_Latest.zip"
   New-Item -ItemType Directory -Force -Path "C:\$(Hostname)-WKMcAgent"
   $WorkingDir = "C:\$(Hostname)-WKMcAgent"
   Invoke-WebRequest $Src -OutFile $Dst
   Add-Type -assembly system.io.compression.filesystem
   [io.compression.zipfile]::ExtractToDirectory($Dst, "C:\$(Hostname)-WKAgents\")
   Start-Process "$WorkingDir\VSE\SetupVSE.Exe" -ArgumentList "/REBOOT=R /q" #-WorkingDirectory "$WorkingDir\VSE.win.8801804" -NoNewWindow -Wait
   Start-Sleep -Seconds 20
 #######Installing Updated McAfee Agent ###########
 
  $src1 = 'https://use1gbsstap1vmautomation.blob.core.windows.net/software/MA-win-560702-510.zip'
  $Dst1 = "C:\$(Hostname)-WKAgents\MA-win-560702-510.zip"
  $WorkingDir1 = "C:\$(Hostname)-WKMcAgent"
  Invoke-WebRequest $Src1 -OutFile $Dst1
  Add-Type -assembly system.io.compression.filesystem
  [io.compression.zipfile]::ExtractToDirectory($Dst1, "C:\$(Hostname)-WKMcAgent\")
  Start-Process -FilePath "$WorkingDir1\FramePkg-epo510.exe" "/Install=Agent /ForceInstall /silent" -NoNewWindow -Wait -WorkingDirectory $WorkingDir1
  Start-Sleep -Seconds 20  
 
  $Services= "macmnsvc","McAfeeFramework","masvc"
  foreach($service in $Services)
  {
   Set-Service -name $service -StartupType Manual -Status Stopped
  }
    Write-Output "McAfee has been installed"

  
 }
 } 

function enableNTP
{
param (
	$allNTPServers = "time.nist.gov,0.pool.ntp.org,1.pool.ntp.org,time1.google.com,time2.google.com,time3.google.com,time4.google.com"
)

$expression = "cmd /c w32tm /config /syncfromflags:manual /manualpeerlist:`"$allNTPServers`""

Invoke-Expression $expression
}

function InsFalcon
{
$ServerName = (Hostname)
$OldAppName = "Omni Agent by MWR InfoSecurity"
$OldServiceName = "OmniAgent"
$NewAppName = "CrowdStrike Sensor Platform"
$NewServiceName = "CSFalconService"
$PathToDownloadFile = "C:\WindowsAWS\"
if(!(Test-Path $PathToDownloadFile)) { mkdir $PathToDownloadFile}
$FileToInstall = "WindowsSensor_7E3A9735FA064249A7005E9BE8CDD907-BC.exe"
$DownloadFileLink = "https://s3.amazonaws.com/flamp/WindowsSensor_7E3A9735FA064249A7005E9BE8CDD907-BC.exe"
$FileToInstallPath = ($PathToDownloadFile+$FileToInstall)
#### Check if Omni is Installed
if((Get-Service $OldServiceName -ErrorAction Ignore) -or (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$OldAppName" }))
{
	#### Remove Installed Service
	Write-Host "Un-installing $OldAppName application on machine $ServerName"
	$AppToUnInstall = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$OldAppName" }
	if($AppToUnInstall) {
		$AppToUnInstall.Uninstall(); 
	} else { 
		Throw " Unable to find application $OldAppName";
	}
	if((!(Get-Service $OldServiceName -ErrorAction Ignore)) -and (!(Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$OldAppName" })))
	{ 
		Write-Host "Application $OldAppName is uninstalled and $OldServiceName Service deleted on machine $ServerName";
	} else { 
		Write-Host "Unable to Delete $OldServiceName Service on machine $ServerName"; } 
} else { 
	Write-Host "Application $OldAppName is not installed on machine $ServerName"; }
	
######Installing Falcon Agent ##############

if((!(Get-Service $OldServiceName -ErrorAction Ignore)) -and (!(Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$OldAppName" })))
{
	if(((!((Get-Service $NewServiceName -ErrorAction Ignore).Status) -eq "Running")) -and (!(Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$NewAppName" })))
	{
		cd $PathToDownloadFile;
		##### Download Specific DL version;
		$client = new-object System.Net.WebClient;
		$client.DownloadFile("$DownloadFileLink","$FileToInstallPath");
		##### Install 
		if(Test-Path $FileToInstallPath)
		{
			Write-Host "Installing CrowdStrike Agent..";
			Start-Process "$FileToInstall" -ArgumentList "/install /quiet /norestart CID=7E3A9735FA064249A7005E9BE8CDD907-BC ProvWaitTime=3600000" -Wait;
			if((((Get-Service $NewServiceName).Status) -eq "Running") -or (Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -match "$NewAppName" }))
			{
				Write-Host "$NewAppName application Installation is Completed ....";
			} else {
				Write-Host "Failed To Install $NewAppName application";
			}
		} else {
			Write-Host "$FileToInstallPath file is not available on Server $ServerName";
		}
	} else {
		Write-Host "$NewServiceName service already exists on Server $ServerName"
	}
} else {
	Write-Host "$OldServiceName service still exists on Server $ServerName"
}

#####Check if Falcon collector is installed####################

 
 

$PathToDownloadCollectorFile = "C:\FalconCollector\"
if(!(Test-Path $PathToDownloadCollectorFile)) { mkdir $PathToDownloadCollectorFile}
Add-MpPreference -ExclusionPath "C:\FalconCollector" ######Adding Exclusion for COllector Exe##########
$FileToInstallCollector = "goldwaltz3752_custom230_FFCWin_2019_05_16.exe"
$DownloadFileLinkCollector = "https://use1gbsstap1vmautomation.blob.core.windows.net/software/goldwaltz3752_custom230_FFCWin_2019_05_16.exe?sp=r&st=2019-05-20T12:24:29Z&se=2021-09-23T00:24:29Z&spr=https&sv=2018-03-28&sig=tDl8wraejUScjMTA7aB6dSHRWTKZHJpauPXAFZKyD%2B4%3D&sr=b"
$FileToInstallPathCollector = ($PathToDownloadCollectorFile+$FileToInstallCollector)


if(Test-Path $PathToDownloadCollectorFile)
{
cd $PathToDownloadCollectorFile;
		##### Download Specific DL version;
		$client = new-object System.Net.WebClient;
		$client.DownloadFile("$DownloadFileLinkCollector","$FileToInstallPathCollector");
Start-Process "$FileToInstallCollector" -Wait;
  Start-Sleep -Seconds 60  
  }
  
  else
  {
  Write-Host "$FileToInstallPathCollector file is not available on Server $ServerName";
  }
}



if ($CheckAgents -eq 'Y')
{

	if ($OpsRamp -eq 'Y'){
	  $OpsRamp1 = CheckOpsRmapStatus
	
	}
	if ($SAM -eq 'Y'){
	  $Snow1 = CheckSnowStatus
	   
	}
	if ($Mcafee -eq 'Y'){
	  $McAfee1 = CheckMcAfeeStatus
	  	
	}
	if ($Falcon -eq 'Y'){
	$Falcon1 = CheckFalconStatus
	
	}
Write-Output "$(Hostname) $($OpsRamp1) $($Snow1) $($McAfee1) $($Falcon1)"
}

if ($InstallAgents -eq 'Y')
{
  mkdir "C:\$(Hostname)-WKAgents\" 2> Out-Null
  #Write-Output "Status: $OpsRampClientID on $(Hostname)"
  
  if ($OpsRamp -eq 'Y'){
	  $OpsRamp2 = InsOpsRamp $OpsRampClientID
	 # Write-Output "Status: $OpsRamp on $(Hostname)"
	}
	if ($SAM -eq 'Y'){
	  $Snow2 =  InsSnow
	 # Write-Output "Status: $Snow on $(Hostname)"
	}
	if ($Mcafee -eq 'Y'){
	  $McAfee2 = InsMcAfee $OUPath $BU $CU
	 # Write-Output "Status: $McAfee on $(Hostname)"
	}  
	if ($Ntp -eq 'Y'){
	  $ntp = enableNTP
	 # Write-Output "Status: $ntp on $(Hostname)"
	}
	if ($Falcon -eq 'Y'){
	  $Falcon2 = InsFalcon
	  
	  }
  Write-Output "$(Hostname) $OpsRamp2 $Snow2 $McAfee2 $ntp $Falcon2"
  #Write-Output "$($(Hostname)) $($OpsRamp2) $($Snow2) $($McAfee2) $($ntp))"
  Remove-Item -Recurse "C:\$(Hostname)-WKAgents\" -Force 2> Out-Null
  }
