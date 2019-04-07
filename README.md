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



#####################TrimEndOfLine#######################

$file = "c:\temp\file.txt"
$content = Get-Content $file
$content | Foreach {$_.TrimEnd()} | Set-Content $file

############################VLAN TESTING ######################
<#
.SYNOPSIS
    Tests VLAN connectivity on a host.

.DESCRIPTION
    Gets all the VDSwitches and portgroups on a host configured with a VLAN and
    tests each VLAN by creating a test portgroup and vmkernel interface, assigning
    IP info from a CSV file and pinging the target IP addresses for each VLAN.
    If VLAN info isn't in the CSV file it is skipped.

.PARAMETER hostnames
    One or more hostnames to test VLANs on.  Hostnames can be comma separated or piped to the script from a file.

.PARAMETER vCenter
    The vCenter to connect to.  This can be left blank if the powercli session is already connected.

.PARAMETER csvFile
    The CSV file containing VLAN test info.  Defaults to .\TestVMHostVlans.csv

.PARAMETER vlan
    If specified, only this VLAN will be tested.  Allows for a single VLAN to be quickly tested without
    having to check all of them.

.PARAMETER output
    The name of the output file.  The results will be exported to CSV format and saved in this file.

.EXAMPLE
    .\Test-VMHostVlans.ps1 -hostnames myesxhost.domain.com

    Test all vlans on a single host.

.EXAMPLE
    Get-Content Hostlist.txt | .\Test-VMHostVlans.ps1

    Test all vlans on all hosts listed in the file.

.EXAMPLE
    Get-Cluster VC-Clustername | Get-VMHost | .\TestVMHostVlans.ps1 -vlan 4

    Tests vlan 4 on all hosts in the cluster.

.EXAMPLE
	get-vmhost -name esx001pbvmw163.federated.fds | .\Test-VMHostVlans.ps1

.NOTES
    Because this testing uses a vmkernel port, if the vCenter vlan is one of the vlans that it tests a host
    communication error (vmodl.fault.HostCommunication) will be reported when the test vmkernel port is 
    changed from the vCenter vlan to the next vlan being tested.  This can safely be ignored since the actual 
    management vmk does not have a communication issue, only the test vmk is affected.
#>
#Requires -modules VMware.VimAutomation.Core, VMware.VimAutomation.Vds
[CmdletBinding()]
param (
    [Parameter(Mandatory=$false,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
    [Alias('Name')]
    [string[]]$hostnames,
    $vCenter,
     $csvFile = ".\CSVFILENAME WITH TEST IP",  # LN Prod VLANS
    
    $vlan,
    $output = "TestResults-$(Get-Date -format 'yyyy.MM.dd.HHmm').csv"
)
Begin {
    Import-Module VMware.VimAutomation.Core, VMware.VimAutomation.Vds
    If ($vCenter -ne $null) { 
        Connect-VIServer $vCenter | Out-Null
    }

    If ((Test-Path $csvFile) -eq $true) {
        $vlanTestIPs = Import-Csv $csvFile
    }
    Else {
        Write-Host "The input CSV file '$csvFile' does not exist."
        Exit
    }
    $results = @()  # array containing the results of all tests
    $testPgPrefix = 'vlan-testing-psscript' # prefix for name of test portgroup
}

Process {
    Foreach ($hostname in $hostnames) {
        # Get the vmhost and esxcli for network diag (vmkping)
        $vmhost = Get-VMHost -Name $hostname
        $esxcli = get-esxcli -vmhost $vmhost
        If ($vmhost -eq $null -or $esxcli -eq $null) {
            #Write-Host "Failed to get vmhost or esxcli for: $hostname"
            Continue  # continue with next host
        }

        # Get VDSwitches for the host
        #Write-Host "Getting VDSwitches for $hostname"
        $vdswitches = Get-VDSwitch -VMHost $vmhost

        ForEach ($vdswitch in $vdswitches) {
            Write-Verbose "Beginning vdswitch: $vdswitch"
            $testPortgroup, $vmk = $null  # reset vdswitch variables
            
            # Portgroup names must be unique - get the ID of the current vdswitch and
            # append it to the test portgroup name
            $vdswitchId = $vdswitch.Id.Split('-')[-1]
            $testPgName = "$testPgPrefix-$vdswitchId"

            # If a vlan was specified, get the portgroup for that vlan.  Otherwise get all portgroups
            # configured with a vlan.
            If ($vlan -ne $null) {
                $portgroups = Get-VDPortgroup -VDSwitch $vdswitch | Where {$_.VlanConfiguration.VlanID -eq $vlan -and $_.Name -notmatch $testPgName}
            }
            Else {
                $portgroups = Get-VDPortgroup -VDSwitch $vdswitch | Where {$_.VlanConfiguration.Vlantype -eq "Vlan" -and $_.Name -notmatch $testPgName}
            }

            # Loop through each production portgroup and test the vlan using a test portgroup
            ForEach ($prodPortgroup in $portgroups) {
                Write-Verbose "Beginning portgroup: $portgroup"
                $status, $message = $null  # reset portgroup variables

                # Get production portgroup info to configure the test portgroup
                $vlanid = $prodPortgroup.VlanConfiguration.VlanID
                $prodPolicy = Get-VDUplinkTeamingPolicy -VDPortgroup $prodPortgroup
                $activeUplinks = $prodPolicy.ActiveUplinkPort
                $standbyUplinks = $prodPolicy.StandbyUplinkPort
                $unusedUplinks = $prodPolicy.UnusedUplinkPort
                $prodPortgroup = $null
                $prodPolicy = $null

                # Get test IP info from CSV
                $vlanInfo = $vlanTestIPs | Where 'Vlan' -eq $vlanid
                If ($vlanInfo -eq $null) {
                    Write-Host "Skipping vlan: $vlanid. No test IP in CSV file."

                    # Save results for this portgroup/vlan
                    $properties = [ordered]@{
                        'Hostname' = $hostname
                        'VDSwitch' = $vdswitch
                        'Uplink' = $null
                        'VLAN' = $vlanid
                        'Tx' = ''
                        'Rx' = ''
                        'Status' = 'No IP'
                        'Message' = 'No vlan info in CSV file.'
                    }
                    $results += New-Object -TypeName PSObject -Property $properties
                    Continue  # next portgroup/vlan
                }

                $testIP = $vlanInfo.TestIP
                $testMask = $vlanInfo.TestMask
                $targetIP = $vlanInfo.TargetIP
                #Write-Host "Testing vlan: $vlanid, Source: $testIP, Destination: $targetIP"

                Try {
                    # Get/create test portgroup
                    $testPortgroup = Get-VDPortgroup -VDSwitch $vdswitch -Name $testPgName -ErrorAction SilentlyContinue
                    If ($testPortgroup -eq $null) {
                        Write-Verbose "Creating test portgroup on vdswitch: $vdswitch"
                        $testPortgroup = New-VDPortgroup -VDSwitch $vdswitch -Name $testPgName
                    }
                    # Configure vlan on test portgroup
                    Write-Verbose "Setting vlan $vlanid on test portgroup: $testPortgroup"
                    Set-VDVlanConfiguration -VDPortgroup $testPortgroup -VlanId $vlanid | Out-Null

                    # Get/create vmkernel interface for testing
                    $vmk = Get-VMHostNetworkAdapter -VMHost $vmhost -VMKernel | Where {$_.PortGroupName -eq $testPortgroup.Name} -ErrorAction SilentlyContinue
                    If ($vmk -eq $null) {
                        Write-Verbose "Creating test vmk adapter on vdswitch: $vdswitch"
                        $vmk = New-VMHostNetworkAdapter -VMHost $vmhost -VirtualSwitch $vdswitch -PortGroup $testPortgroup
                    }
                    If ($testIP -match 'dhcp') {
                        Write-Verbose "Configuring test vmk for dhcp"
                        Set-VMHostNetworkAdapter -VirtualNic $vmk -Dhcp -Confirm:$false | Out-Null
                    }
                    Else {
                        Write-Verbose "Configuring test vmk with IP $testIP, mask $testMask"
                        Set-VMHostNetworkAdapter -VirtualNic $vmk -IP $testIP -SubnetMask $testMask -Confirm:$false | Out-Null
                    }

                }
                Catch {
                    #Write-Host "Error creating test portgroup/vmk : $($error[0].Exception)"
                    $message = "$($error[0].Exception)"
                }
            
                # Get active uplinks on test portgroup
                $testUplinks = (Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup).ActiveUplinkPort

                # Set uplink policy on test portgroup if it doesn't match

                If ($activeUplinks -ne $testUplinks) {
                    Write-Verbose "Setting uplinks on test portgroup: $testPortgroup"
                    If ($standByUplinks -ne $null) {
                        Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup | Set-VDUplinkTeamingPolicy -StandbyUplinkPort $standbyUplinks | Out-Null
                    }
                    If ($unusedUplinks -ne $null) {
                        Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup | Set-VDUplinkTeamingPolicy -UnusedUplinkPort $unusedUplinks | Out-Null
                    }
                    Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup | Set-VDUplinkTeamingPolicy -ActiveUplinkPort $activeUplinks | Out-Null
                    
                    $testUplinks = (Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup).ActiveUplinkPort
                }

                Write-Verbose "Active uplinks to test: $testUplinks"
            
                ForEach ($uplink in $testUplinks) {
                    # Reset variables
                    $result, $status, $message = $null
                
                    # Set current uplink active and others to unused
                    If ($testUplinks.Count -gt 1) {
                        Get-VDUplinkTeamingPolicy -VDPortgroup $testPortgroup | Set-VDUplinkTeamingPolicy -ActiveUplinkPort $uplink -UnusedUplinkPort ($testUplinks -notmatch $uplink) | Out-Null
                    }
                
                   # Write-Host "Testing uplink: $uplink"

                    # Ping test IP
                    $result = @($esxcli.Network.Diag.Ping(3,$false,$true,$targetIP,$vmk,$null,$true,$false,$null,$null,$null,$null,$null))
                
                    If ($result.Summary -ne $null) {
                        If ($result.Summary.Recieved -eq $result.Summary.Transmitted) {
                            $status = "Passed"
                        }
                        ElseIf ($result.Summary.Recieved -gt 0) {
                            $status = "Partial"
                        } 
                        Else {
                            $status = "Failed"
                        }
                       # Write-Host "Packets Sent: $($result.Summary.Transmitted), Received: $($result.Summary.Recieved)"
                    } 
                    Else {
                        $status = "Failed"
                        $message = 'No results from "esxcli network diag ping".'
                       # Write-Host 'No results from "esxcli network diag ping".'
                    }
                
                    # Save results
                    $properties = [ordered]@{
                        'HostName' = $hostname
                        'VDSwitch' = $vdswitch
                        'Uplink' = $uplink
                        'VLAN' = $vlanid
                        'Status' = $status
                        'Tx' = $result.Summary.Transmitted
                        'Rx' = $result.Summary.Recieved
                        'Message' = $message
                    }
                    $results += New-Object -TypeName PSObject -Property $properties
                } # end uplink loop 
            } # end portgroup loop

            # Remove test vmkernel
            If ($vmk -ne $null) {

                Write-Verbose "Removing test vmk on vdswitch: $vdswitch"
                Remove-VMHostNetworkAdapter -Nic $vmk -Confirm:$false | Out-Null 
            }
            #Remove-VDPortGroup -VDPortGroup $testPortgroup -Confirm:$false | Out-Null
       } # end vdswitch loop
   } # end foreach loop
} # end process block

End {
    # Save results to CSV
    #$results | Export-Csv -Path - $output -NoTypeInformation
    $results | Export-Csv -Append -Path  $output -NoTypeInformation

    # Write results to the console
    $results | Format-Table
}




##############################
