# UseFull_PowerCLI_Scripts
usefull powercli scripts

###WWPN##

$scope = Get-Cluster -Name 'ClusterName' | Get-VMHost

foreach ($esx in $scope){
Write-Host "Host:", $esx
$hbas = Get-VMHostHba -VMHost $esx -Type FibreChannel
foreach ($hba in $hbas){
$wwpn = "{0:x}" -f $hba.PortWorldWideName
Write-Host `t $hba.Device, "|", $hba.model, "|", "World Wide Port Name:" $wwpn
}}


###################find VM with MAC##

Get-VM | Get-NetworkAdapter | Where {$_.MacAddress -eq “00:50:56:61:cc:59”}

##########################OVF VM Property 


Function Get-VMOvfProperty {
<#
    .NOTES
    ===========================================================================
     Created by:    William Lam
     Organization:  VMware
     Blog:          www.virtuallyghetto.com
     Twitter:       @lamw
    ===========================================================================
    .DESCRIPTION
        This function retrieves the OVF Properties (vAppConfig Property) for a VM
    .PARAMETER VM
        VM object returned from Get-VM
    .EXAMPLE
        #Get-VMOvfProperty -VM (Get-VM -Name "vesxi65-1-1")
#>
    param(
        [Parameter(Mandatory=$true)]$VM
    )
    $vappProperties = $VM.ExtensionData.Config.VAppConfig.Property

    $results = @()
    foreach ($vappProperty in $vappProperties | Sort-Object -Property Id) {
        $tmp = [pscustomobject] @{
            Id = $vappProperty.Id;
            Label = $vappProperty.Label;
            Value = $vappProperty.Value;
            Description = $vappProperty.Description;
        }
        $results+=$tmp
    }
    $results
}


Get-VMOvfProperty -VM ( get-vm "VMNAME")


################## Check vMotion Reqquirement

if (!(Get-VMHost $ehost -ErrorAction SilentlyContinue | Get-VMHostNetworkAdapter -VMKernel | Where {$_.VMotionEnabled -match 'True' } ))
{ 
  
$Hosts_vMotionDisabled += $ehost
  
}

Elseif(Get-VMHost $ehost -ErrorAction SilentlyContinue | Get-VMHostNetworkAdapter -VMKernel | Where {$_.VMotionEnabled -match 'True' } |Get-VDPortgroup | ? {$_.Name -notmatch 'vMotion'})

Get-VMHost | ?{$_.ConnectionState -ne "NotResponding" } | Get-VMHostNetworkAdapter -VMKernel | Where {$_.VMotionEnabled -match 'True' } |?{$_.IP -match "169" } | select VMHost

####################### REBOOT all the hosts in a cluster one at a time #############

$ehosts = Get-Cluster "ClusterName"| Get-VMHost | select name -ExpandProperty name # Use this if you would like to perform all hosts in a cluster

#$ehosts = gc c:\reboothost.txt  # use this if you would like provide a list
foreach($ehost in $ehosts) 
{ 

# Put server in maintenance mode

Write-Host "Entering Maintenance Mode $ehost " -ForegroundColor Yellow
Set-VMhost $ehost -State maintenance -Evacuate | Out-Null

#Disable Alarm
$alarmMgr = Get-View AlarmManager 
$esx = Get-VMHost $ehost  
$alarmMgr.EnableAlarmActions($esx.Extensiondata.MoRef,$false)

If ((get-vmhost $ehost ).ConnectionState -eq "Maintenance" )

{

# Reboot host
Write-Host "Rebooting $ehost " -ForegroundColor Yellow


Restart-VMHost $ehost -confirm:$false | Out-Null

# Wait for Server to show as down
do {
sleep 15
$ServerState = (get-vmhost $ehost ).ConnectionState
}
while ($ServerState -ne "NotResponding")
Write-Host "$ehost is Down" -ForegroundColor Yellow

# Wait for server to reboot
do {
sleep 60
$ServerState = (get-vmhost $ehost).ConnectionState
Write-Host "Waiting for Reboot …" -ForegroundColor Yellow
}
while ($ServerState -ne "Maintenance")
Write-Host "$ehost is back up"  -ForegroundColor Green

#Enable Alarm
$alarmMgr = Get-View AlarmManager 
$esx = Get-VMHost $ehost  
$alarmMgr.EnableAlarmActions($esx.Extensiondata.MoRef,$true)

#check vMotion network

If (Get-VMHost $ehost | Get-VMHostNetworkAdapter -VMKernel | Where {$_.VMotionEnabled -match 'True' } |?{$_.IP -match "169" })

{

Write-Host "vMotion network has a issue on the host please fix the issue manually by re-adding the VMK " -ForegroundColor Red

Exit 
}

# Exit maintenance mode
Write-Host "Exiting Maintenance mode" -ForegroundColor Green
Set-VMhost $ehost -State Connected | Out-Null
Write-Host "** Reboot Complete **" -ForegroundColor Green
Write-Host ""
}
}

######################## VM BUILD ##############

## read teh custom spec ## 

$spec = Get-OSCustomizationSpec "customspec name" 

##create a temp custom spec from above ## 
$tempSpec = $spec | New-OSCustomizationSpec -Name tempctstomspecname

### Subnet mask,GW and DNS settings ##

$SubnetMask = "255.255.252.0"
$Gateway = "updateTheIP" 
$pDNS = "updateTheIP"
$sDNS = "updateTheIP"

## get the template details ## 
$Template = "TemplateName"

## use temp spec as custom spec for teh VM build ## 

$custspec = $tempSpec


$VMHost = Get-Cluster "ClusterName" | Get-VMHost | Get-Random
$Datastore = Get-DatastoreCluster "Name" | Get-Datastore | Sort-Object -Property FreeSpaceGB -Descending | Select -First 1 


##VM name and Ip from CSV file ## 

$vms = Import-Csv U:\vms.csv

Foreach( $vm in $vms) { 
		
New-OSCustomizationNicMapping -Spec $custspec -IpMode UseStaticIp –Position 1 -IpAddress $vm.ip -SubnetMask $SubnetMask -Dns $pDNS,$sDNS -DefaultGateway $Gateway

New-VM -Name $vm.name -Location "VMFolder" -Datastore $Datastore -VMHost $VMHost -Template $Template -OSCustomizationSpec $custspec -RunAsync -EA SilentlyContinue

Get-OSCustomizationSpec $custspec | Get-OSCustomizationNicMapping | Remove-OSCustomizationNicMapping -Confirm:$false

Start-Sleep -Seconds 600 #Clone Procell in progress##

Start-VM $vm.name

Start-Sleep -Seconds 1080 

}
############################# Validate Datastore #######################
param (
    [VMware.VimAutomation.ViCore.Impl.V1.Inventory.VMHostImpl[]]$vmhosts = $(throw "vmhosts must be specified")
)
 
$masterList = @{}


 
# Use the first host as the reference host
foreach ($datastore in Get-Datastore -VMHost $vmhosts[0] | ?{$_.ExtensionData.Summary.MultipleHostAccess -eq 'True'}) {
    $masterList[$datastore.Name] = "Missing"
}
 
# Check all of the hosts against the master list
foreach ($vmhost in $vmhosts) {
    $testList = @{} + $masterList
 
    foreach ($datastore in Get-Datastore -VMHost $vmhost | ?{$_.ExtensionData.Summary.MultipleHostAccess -eq 'True'}) {
        $dsName = $datastore.Name
 
        # If we have a match change the status
        if ($testList.ContainsKey($dsName)) {
            $testList[$dsName] = "OK"
        }
        # Otherwise we have found a datastore that wasn't on our reference host.
        else {
            $testList[$dsName] = "Extra"
        }
    }
 
    # Output our findings
    foreach ($dsName in $testList.Keys) {
        $info = "" | Select-Object VMHost, Datastore, Status
        $info.VMHost = $vmhost.Name
        $info.Datastore = $dsName
        $info.Status = $testList[$dsName]
        $info
    }
}

<#
.SYNOPSIS
Check a set of hosts to see if they see the same datastores.  This script
does not filter local datastores.
 
.PARAMETER clusters
An array of the hosts you want to check.
 
.EXAMPLE
.\Validate-Datatores.ps1 (Get-Cluster cluster1 | Get-VMHost)
#>

########################### Update Manager #############################

$SHOST = "esx000pbvmw001.federated.fds"

Get-VMHost -Name $SHOST | set-vmhost -State Maintenance

Attach-Baseline -Baseline $staticBaseline, $criticalPatchBaseline -Entity Host

Stage-Patch -Entity $SHOST

Scan-inventory -entity $SHOST
 
Remediate-Inventory –Entity Host –Baseline $baselines –HostFailureAction Retry –HostNumberOfRetries 2 -HostDisableMediaDevices $true 
get-baseline -name "HPE1" | remediate-inventory -entity $SHOST –HostFailureAction Retry –HostNumberOfRetries 2 -HostDisableMediaDevices $true -ClusterDisableHighAvailability $true 
 
# Remove selected host from Maintenance mode
write-host "Removing host from Maintenance Mode"
Get-VMHost -Name $SHOST | set-vmhost -State Connected
 
# Display Popup when finished.
[System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
[System.Windows.Forms.MessageBox]::Show("The Patching for " + $SHOST + " is now complete..")






