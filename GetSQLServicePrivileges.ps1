param(
   [Parameter(Mandatory=$true)]
   [pscredential]$cred,

   [Parameter(Mandatory=$true)]
   $listPath
)


$computerList = @()
$outputList = @()

#Local temporary path
$localTempPath = "C:\temp\"

#Local Temporary Security Policy File
$localTempFile = "securitypolicies.txt"

#output path
$outputPath = $PSScriptRoot + "\" + "output.csv"


#UserRightAssignments
$URAList = @()
$URAList += New-Object psobject -Property @{Policy = "SeServiceLogonRight"; Description = "Log on as a service"}
$URAList += New-Object psobject -Property @{Policy = "SeAssignPrimaryTokenPrivilege"; Description =  "Replace a process-level token"}
$URAList += New-Object psobject -Property @{Policy = "SeChangeNotifyPrivilege"; Description =  "Bypass traverse checking"}
$URAList += New-Object psobject -Property @{Policy = "SeIncreaseQuotaPrivilege"; Description =  "Adjust memory quotas for a process"}
$URAList += New-Object psobject -Property @{Policy = "SeManageVolumePrivilege"; Description =  "Perform volume maintenance tasks"}
$URAList += New-Object psobject -Property @{Policy = "SeLockMemoryPrivilege"; Description =  "Lock pages in memory"}

##########################
#Script Functions

#Get Account Name from SID
function Get-AccountName {
param(
    [String] $principal
)
    $result = ""

    If ( $principal[0] -eq "*" ) 
    {
        $SIDName = $principal.Substring(1)
        $sid = New-Object System.Security.Principal.SecurityIdentifier($SIDName)
        $result = $sid.Translate([Security.Principal.NTAccount])
    }
    Else
    {
        $result = $principal
    }

    , $result
}










############################
#Execute Script

try
{
    $computerList = Get-Content -Path $listPath -ErrorAction Stop
}
catch
{
    Write-Warning -Message "Could not read content of list"
    Write-Warning -Message $_
    exit 1
}


#Check if there are rows
if($computerList.Count -eq 0)
{
    Write-Warning -Message "Nothing to do"
    exit 1
}


foreach($pc in $computerList)
{
    #Export User Right Assignment Permissions to C:\temp\URA.txt
    #Will be deleted afterwards
    try
    {
        Invoke-Command -ComputerName $pc -Credential $cred -ErrorAction Stop -ScriptBlock {
        
            #Check Temp Path exists
            if(!(Test-Path("C:\temp\")))
            {
                New-Item -Path "C:\temp\" -ItemType Directory
            }

            secedit /export /areas USER_RIGHTS /cfg "C:\temp\securitypolicies.txt"
        }
    }
    catch
    {
        $outputList += New-Object psobject -Property @{Server = $pc; Privilege = "n/a"; isNTServiceMSSQLset = "0"; Description = "Could not connect to server"}
        continue;
        
    }


    #Check if file and content exists
    $checkFile = Invoke-Command -ComputerName $pc -Credential $cred -ScriptBlock {
        Test-Path "C:\temp\securitypolicies.txt"
    }

    if($checkFile -match "False")
    {
        #Server not successfull - goto next server
        $outputList += New-Object psobject -Property @{Server = $pc; Privilege = "n/a"; isNTServiceMSSQLset = "0"; Description = "Could not connect to server"}
        continue;
    }

    #Get Content of Security Policy txt
    $thisContent = Invoke-Command -ComputerName $pc -Credential $cred -ScriptBlock {
        Get-Content -Path "C:\temp\securitypolicies.txt"
    }

    if($thisContent.Count -eq 0)
    {
        #something went wrong
        $outputList += New-Object psobject -Property @{Server = $pc; Privilege = "n/a"; isNTServiceMSSQLset = "0"; Description = "Could not connect to server"}
        continue;
    }
    
    #delete file
    Invoke-Command -ComputerName $pc -Credential $cred -ScriptBlock {
        Remove-Item -Path "C:\temp\securitypolicies.txt" -Force
    } 
    
    #Write data to list
    $currentPolicies = @() 

    $thisContent | Select-String '^(Se\S+) = (\S+)'| ForEach-Object {
        $tmpPrivilege = $null
        $tmpPrincipals = $null

        $tmpPrivilege = $_.Matches[0].Groups[1].Value
        $tmpPrincipals = $_.Matches[0].Groups[2].Value -split ','

        $tmpPrincList = @()
        foreach($principal in $tmpPrincipals)
        {
            $tName = $null

            if($principal[0] -eq "*")
            {
                #Get name of principal
                $tName = Invoke-Command -ComputerName $pc -Credential $cred -ScriptBlock ${Function:Get-AccountName} -ArgumentList $principal
                if($tName)
                {
                    $tmpPrincList += $tName
                }
                else
                {
                    #$tmpPrincList += 'NA'
                    $tmpPrincList += New-Object psobject -Property @{PSComputerName = $pc; RunspaceId = "00000000-0000-0000-0000-000000000000"; Value = "NA"}
                    
                }
            }
            else
            {
                #$tmpPrincList += 'NA'
                $tmpPrincList += New-Object psobject -Property @{PSComputerName = $pc; RunspaceId = "00000000-0000-0000-0000-000000000000"; Value = "NA"}
            }  
        }
            
        #Add infos to currentPolicies list
        $currentPolicies += New-Object psobject -Property @{Policy = $tmpPrivilege; PrincList = $tmpPrincList}
    }

    #Loop through URALIST and match data
    Write-Host $pc
    foreach($ura in $URAList)
    {
        $tmpPolicy = $ura.Policy
        $tmpDesc = $ura.Description
        
        $tmpOutPrincipals = @()
        $tmpOutPrincipals = $currentPolicies | Where-Object{$_.Policy -eq "$tmpPolicy"} | Select-Object -ExpandProperty PrincList
        $tmpOutPrincValues = $tmpOutPrincipals | Select -ExpandProperty Value

       
        $tmpThisResult = 0
        foreach($tmp in $tmpOutPrincValues)
        {
            
            if($tmp -like "*SERVICE\MSSQL*")
            {
                $tmpThisResult = 1
                break;
            }
            
            
        }
        $outputList += New-Object psobject -Property @{Server = $pc; Privilege = $tmpPolicy; isNTServiceMSSQLset = $tmpThisResult; Description = $tmpDesc}
    }
    
}

$outputList | Select-Object Server, Privilege, isNTServiceMSSQLset, Description | Export-Csv -Path $outputPath -Delimiter ";" -NoTypeInformation
