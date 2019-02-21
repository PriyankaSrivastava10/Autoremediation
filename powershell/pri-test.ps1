 Param(
       $CheckAgents,
       $InstallAgents,
       $OpsRampClientID,
       $OpsRamp,
       $Mcafee,
       $SAM,
       $OUPath,
       $CU = 'GBSIT',
       $BU = 'GBS'
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

function InsOpsRamp
{
 Param($OpRampcid)
 $Status = CheckOpsRmapStatus
 if ($Status -match 'NotInstalled')
 {
  $Dst = "C:\$(Hostname)-WKAgents"
  $Src = "https://wolterskluwer.vistarait.com/downloadagentNA.do?action=downloadAgent&clientid=$OpRampcid&primaryChannelId=1&profile=0"
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
  
  mkdir "C:\$(Hostname)-WKAgents" 
  $Src = "https://s3.amazonaws.com/wksamagentbucket/wolterskluwer_snowagent-5.3.0.x64.msi"
  $Dst = "C:\$(Hostname)-WKAgents\snowagent.msi"
  Invoke-WebRequest $Src -OutFile $Dst
  MsiExec /i $Dst /qn
  Write-Output "SAM installed"
  
 }
 
}

function ConfMcAfee
{
  param ($CustomProps)
  #Write-Output $CustomProps
  $WorkingDir = "C:\$(Hostname)-WKAgents"
  $Time = 0
  #write-Output "Installing McAfee agent....."
  #cd $WorkingDir
  Start-Process "$WorkingDir\FramePkg_505658.exe" -ArgumentList $CustomProps
  while ( $true)
  {
   $InsSoft = Get-WmiObject -Class Win32_Product | where Name -Match 'McAfee Agent' 2> Out-Null
   if ($InsSoft.Name -eq 'McAfee Agent')
    {
      #$args = [System.Collections.ArrayList] @("/REBOOT=R","/q")
      Start-Process "$WorkingDir\VSE.win.8801804\SetupVSE.Exe" -ArgumentList "/REBOOT=R /q"
      break
    }

   if ($Time -gt 300 )

    {
     Write-Output "McAfee agent  can't be installed"
     break 
    }

              Start-Sleep -Seconds 5
              $Time = $Time + 5
              #Write-Output "."
   }
           
   if( $Time -le 300)
   {
     $Time = 0
     while ( $true)
      {
        $InsSoft = Get-WmiObject -Class Win32_Product | where Name -Match 'McAfee VirusScan Enterprise' 2> Out-Null
        if ($InsSoft.Name -eq 'McAfee VirusScan Enterprise')
         {
            Write-Output "McAfee agent has been installed"
            break
         }

        if ($Time > 300 )

         {
           Write-Output "McAfee agent  can't be installed"
           break 
         }

         Start-Sleep -Seconds 5
         $Time = $Time + 5
      }
    }
    $Services= "macmnsvc","McAfeeFramework","masvc"
    foreach($service in $Services)
    {
      Set-Service -name $service -StartupType Manual -Status Stopped 2> Out-Null
    }
            
}

function InsMcAfee
{
  Param($OUPath,
        $BU,
        $CU
        )
  $Status = CheckMcAfeeStatus
  $CustomProps = "/install=agent"+" "+"/ForceInstall"+" "+"/silent"
  if ($Status -match 'NotInstalled')
  {
   $Src = "https://use1gbsstap1vmautomation.blob.core.windows.net/software/McAfee.zip"
   $Dst = "C:\$(Hostname)-WKAgents\McAfee.zip"
   $WorkingDir = "C:\$(Hostname)-WKAgents"
   Invoke-WebRequest $Src -OutFile $Dst
   Add-Type -assembly system.io.compression.filesystem
   [io.compression.zipfile]::ExtractToDirectory($Dst, "C:\$(Hostname)-WKAgents")
   if ($OUPath -ne 'null' )
   {
     for ($i=1;$i -le 8;$i++)
     {
        $CustomProp = $OUPath.Split(',')[$i].Remove(0,3) 
 
        if($CustomProp)
         {
          $CustomProps+= " "+"/CustomProps"+$i+"="+$CustomProp
          #$Args.add($arg) | Out-Null
         }
     }
     ConfMcAfee $CustomProps
       
   }

   else
   {
    if ($BU -ne 'null' -and $CU -ne 'null' )
       { 
           
           $CustomProps+= " "+"/CustomProps1=$BU"+" "+"/CustomProps2=$CU"
           ConfMcAfee $CustomProps
           
       }
         
       else
        {
              Write-Otuput "McAfee can't be installed. Values of BU and CU can't be null"
              
        }
       #}
     
    }
  
 


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
Write-Output "$(Hostname) $($OpsRamp1) $($Snow1) $($McAfee1)"
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
  Write-Output "$(Hostname) $OpsRamp2 $Snow2 $McAfee2 $ntp"
  #Write-Output "$($(Hostname)) $($OpsRamp2) $($Snow2) $($McAfee2) $($ntp))"
  Remove-Item -Recurse "C:\$(Hostname)-WKAgents\" -Force 2> Out-Null
  }
