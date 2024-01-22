#################################################################################################################
## PowerShell script demonstrating how to post data to custom Log Analytics tables using the Log Ingestion API ##
#################################################################################################################


#region --------------------------------------------- Variables ---------------------------------------------------------------
# The URI of the data collection endpoint in your Azure subscription
$DataCollectionEndpointURI = "https://dce-logsingestion-1234.eastus-1.ingest.monitor.azure.com"
# Your tenant Id
$TenantId = "99990ab-ad09-459d-8443-d9b052ab9100"
# The application (client) Id of the Azure AD app you created
$AppId = "87654321-a707-41e3-8bea-85b9740c893d"
# The thumbprint of the certificate you added to the local machine store
$CertificateThumbprint = "AC9E8E65776D89A34CD64B144E5ACA05DEF34DAD"
# Speeds up web requests
$ProgressPreference = 'SilentlyContinue'
# Enforce TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#endregion --------------------------------------------------------------------------------------------------------------------


#region --------------------------------------------- Functions ---------------------------------------------------------------
# Function to get an access token from Microsoft Entra using a certificate
Function Get-Oath2AccessTokenFromCertificate {
    Param($TenantId,$AppId,[System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,$Scope)

    $CertificateBase64Hash = [System.Convert]::ToBase64String($Certificate.GetCertHash())
    $StartDate = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpiration = [math]::Round((New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds, 0)
    $NotBefore = [math]::Round((New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds, 0)

    $JWTHeader = @{
        alg = "RS256"
        typ = "JWT"
        x5t = $CertificateBase64Hash -replace '\+', '-' -replace '/', '_' -replace '='
    }

    $JWTPayLoad = @{
        aud = "https://login.microsoftonline.com/$TenantId/oauth2/token"
        exp = $JWTExpiration  
        iss = $AppId  
        jti = [guid]::NewGuid()  
        nbf = $NotBefore  
        sub = $AppId  
    }

    $JWTHeaderToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTHeader | ConvertTo-Json))
    $EncodedHeader = [System.Convert]::ToBase64String($JWTHeaderToByte)
    $JWTPayLoadToByte = [System.Text.Encoding]::UTF8.GetBytes(($JWTPayload | ConvertTo-Json))
    $EncodedPayload = [System.Convert]::ToBase64String($JWTPayLoadToByte)
    $JWT = $EncodedHeader + "." + $EncodedPayload
    $PrivateKey = ([System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate))
    $RSAPadding = [Security.Cryptography.RSASignaturePadding]::Pkcs1
    $HashAlgorithm = [Security.Cryptography.HashAlgorithmName]::SHA256
    $Signature = [Convert]::ToBase64String($PrivateKey.SignData([System.Text.Encoding]::UTF8.GetBytes($JWT), $HashAlgorithm, $RSAPadding)) -replace '\+', '-' -replace '/', '_' -replace '='

    $JWT = $JWT + "." + $Signature

    $Body = @{
        client_id = $AppId
        client_assertion = $JWT
        client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        scope = $Scope
        grant_type = "client_credentials"
    }

    $Url = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"

    $Header = @{Authorization = "Bearer $JWT"}

    $PostSplat = @{
        ContentType = 'application/x-www-form-urlencoded'
        Method = 'POST'
        Body = $Body
        Uri = $Url
        Headers = $Header
    }
            
    $Request = Invoke-RestMethod @PostSplat -ErrorAction SilentlyContinue
    return $Request
}

# Function to post data to the Logs Ingestion API
Function Send-LogIngestionAPIPost {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [String]
        $DataCollectionEndpointURI,
        [Parameter(Mandatory = $true)]
        [String]
        $DataCollectorImmutableID,
        [Parameter(Mandatory = $true)]
        [String]
        $Table,
        [Parameter(Mandatory = $true)]
        [Object]
        $Data,
        [Parameter(Mandatory = $true)]
        [string]
        $Token
    )

    # Create headers and set the URI to post to
    $headers = @{"Authorization" = "Bearer $Token"; "Content-Type" = "application/json; charset=utf8" }
    $uri = "$DataCollectionEndpointURI/dataCollectionRules/$DataCollectorImmutableID/streams/Custom-$Table"+"?api-version=2023-01-01"

    # Single items must be converted to an array
    If (-not ($Data -is [Array]))
    {
        $Data = @($Data)
    }

    # Convert the data to json
    If ($Data.Count -eq 1)
    {
        # PowerShell pipeline will enumerate arrays, passing items one at a time. 
        # Therefore an array with a single item will not been seen as an array on the other side of the pipeline.
        # Therefore we need to use InputObject instead of piping to preserve the array.
        # Be aware of the issue with NoteProperties mentioned below
        # PowerShell Core can use the -AsArray parameter to get around this issue
        If ($PSVersionTable.PSEdition -eq "Core")
        {
            $Json = $Data | ConvertTo-Json -Depth 100 -Compress -AsArray
        }
        else 
        {
           $Json = ConvertTo-Json -InputObject $Data -Depth 100 -Compress 
        }        
    }
    else 
    {
        # For arrays with multiple items, pipeline enumeration is more reliable than InputObject
        # Example: if you use Add-Member to add NoteProperties to an object, the NoteProperties are ignored when using InputObject since they are not native to the object itself.
        $Json = $Data | ConvertTo-Json -Depth 100 -Compress
    }

    # Make sure the json is UTF8 encoded
    $jsonBytes = [Text.Encoding]::UTF8.GetBytes($Json)

    # Check if we're likely to exceed the 1MB limit
    If ($jsonBytes.length -gt 1048000)
    {
        # Data is too large for a single post, so split it up

        # First, make sure we have more than one item
        If ($Data.Count -eq 1)
        {
            return "Data is too large for a single post"
        }
        
        # Calculate the average row size
        $averageRowSize = $JsonBytes.length / $Data.count

        # Calculate the number of rows that will fit in ~1MB
        $batchCount = [math]::Floor(1048000 / $averageRowSize)

        # Play it safe - take 20% off the batch count
        $batchCount = $batchCount - [math]::Floor($batchCount / 100 * 20)

        # Post the data in batches
        $skipValue = 0
        do {
            # Create the batch
            $batch = $Data | Select -Skip $skipValue -First $batchCount

            # Convert the data to json
            $Json = $batch | ConvertTo-Json -Depth 100 -Compress

            # Make sure the json is UTF8 encoded
            $jsonBytes = [Text.Encoding]::UTF8.GetBytes($Json)

            # Post the data
            try 
            {
                $response = Invoke-WebRequest -Uri $uri -Method "Post" -Body $jsonBytes -Headers $headers  
                $response
            }
            catch 
            {          
                $e = $_
                # Retry if we get a 429
                If ($e.Exception.Response.StatusCode -eq 429)
                {
                    $i = 0
                    $e = $null
                    do {
                        Start-Sleep -Seconds 30
                        try 
                        {
                            $response = Invoke-WebRequest -Uri $uri -Method "Post" -Body $jsonBytes -Headers $headers  
                            $response
                            Remove-Variable e -ErrorAction SilentlyContinue
                            $i = 6 # break the loop
                        }
                        catch 
                        {
                            $e = $_
                            $i ++
                        }          
                    } while ($e.Exception.Response.StatusCode -eq 429 -and $i -lt 5)
                }
                If ($e -is [System.Management.Automation.ErrorRecord])
                {
                    If ($e.Exception.Response)
                    {
                        # Get a response body if we have one - helpful for troubleshooting
                        $StatusCode = $e.Exception.Response.StatusCode
                        try 
                        {
                            $responseStream = $e.Exception.Response.GetResponseStream()
                            $reader = New-Object System.IO.StreamReader($responseStream)
                            $reader.BaseStream.Position = 0
                            $reader.DiscardBufferedData()
                            $responseBody = $reader.ReadToEnd(); # Should contain error.code and error.message
                            $reader.Close();
                        }
                        catch 
                        {
                            $responseBody = ""
                        }
                        [PSCustomObject]@{
                            StatusCode = $StatusCode
                            ResponseBody = ConvertFrom-Json $responseBody
                        }
                    }
                    else 
                    {
                        $e.Exception.Message    
                    }
                }
                else 
                {
                    $e
                }
            }

            $skipValue += $batchCount
        }
        while ($skipValue -lt $Data.Count)
    }
    # If not, post one time
    else 
    {   
        try 
        {
            $response = Invoke-WebRequest -Uri $uri -Method "Post" -Body $jsonBytes -Headers $headers  
            return $response
        }
        catch 
        {          
            $e = $_
            # Retry if we get a 429
            If ($e.Exception.Response.StatusCode -eq 429)
            {
                $i = 0
                $e = $null
                do {
                    Start-Sleep -Seconds 60
                    try 
                    {
                        $response = Invoke-WebRequest -Uri $uri -Method "Post" -Body $jsonBytes -Headers $headers  
                        return $response
                    }
                    catch 
                    {
                        $e = $_
                        $i ++
                    }          
                } while ($e.Exception.Response.StatusCode -eq 429 -and $i -lt 5)
            }
            If ($e -is [System.Management.Automation.ErrorRecord])
            {
                If ($e.Exception.Response)
                {
                    # Get a response body if we have one - helpful for troubleshooting
                    $StatusCode = $e.Exception.Response.StatusCode
                    try 
                    {
                        $responseStream = $e.Exception.Response.GetResponseStream()
                        $reader = New-Object System.IO.StreamReader($responseStream)
                        $reader.BaseStream.Position = 0
                        $reader.DiscardBufferedData()
                        $responseBody = $reader.ReadToEnd(); # Should contain error.code and error.message
                        $reader.Close();
                    }
                    catch 
                    {
                        $responseBody = ""
                    }
                    
                    return [PSCustomObject]@{
                        StatusCode = $StatusCode
                        ResponseBody = ConvertFrom-Json $responseBody
                    }
                }
                else 
                {
                    return $e.Exception.Message    
                }
            }
            else 
            {
                return $e
            }
        } 
    }    
}

# Function to get the Microsoft Entra device Id
Function Get-EntraDeviceID {
    $AADCert = (Get-ChildItem Cert:\Localmachine\MY | Where {$_.Issuer -match "CN=MS-Organization-Access"})
    If ($null -ne $AADCert)
    {
        return $AADCert.Subject.Replace('CN=','')
    }
    # try some other ways to get the AaddeviceId in case ther cert is missing somehow
    else 
    {
        $AadDeviceId = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\CCM" -Name AadDeviceId -ErrorAction SilentlyContinue | Select -ExpandProperty AadDeviceId
        If ($null -eq $AadDeviceId)
        {
            try 
            {
                $dsreg = dsregcmd /status
                $DeviceIdMatch = $dsreg | Select-String -SimpleMatch "DeviceId" 
                If ($DeviceIdMatch -eq 1)
                {
                    return $DeviceIdMatch.Line.Split()[-1]
                } 
            }
            catch {}
        }
        Else
        {
            return $AadDeviceId
        }
    }
}

# Function to get the Microsoft Intune device Id
Function Get-IntuneDeviceId {
    $IntuneCert = (Get-ChildItem Cert:\*\MY -Recurse | Where {$_.Issuer -eq "CN=Microsoft Intune MDM Device CA"})
    If ($null -ne $IntuneCert)
    {
        # Sometimes an expired cert may still exist
        if ($IntuneCert.GetType().BaseType.Name -eq "Array")
        {
            $IntuneCert = $IntuneCert | Sort NotAfter -Descending | Select -First 1 
        }
        return $IntuneCert.Subject.Replace('CN=','')
    }
}

# Function to return details of the current logged-in user/s
Function Get-CurrentUser {
    # ref https://www.reddit.com/r/PowerShell/comments/7coamf/query_no_user_exists_for/
    $header=@('SESSIONNAME', 'USERNAME', 'ID', 'STATE', 'TYPE', 'DEVICE')
    $Sessions = query session
    [array]$ActiveSessions = $Sessions | Select -Skip 1 | Where {$_ -match "Active"}
    If ($ActiveSessions.Count -ge 1)
    {
        $LoggedOnUsers = @()
        $indexes = $header | ForEach-Object {($Sessions[0]).IndexOf(" $_")}        
        for($row=0; $row -lt $ActiveSessions.Count; $row++)
        {
            $obj=New-Object psobject
            for($i=0; $i -lt $header.Count; $i++)
            {
                $begin=$indexes[$i]
                $end=if($i -lt $header.Count-1) {$indexes[$i+1]} else {$ActiveSessions[$row].length}
                $obj | Add-Member NoteProperty $header[$i] ($ActiveSessions[$row].substring($begin, $end-$begin)).trim()
            }
            $LoggedOnUsers += $obj
        }

        foreach ($LoggedOnUser in $LoggedOnUsers)
        {
            $LoggedOnDisplayName = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\$($LoggedOnUser.ID)" -Name LoggedOnDisplayName -ErrorAction SilentlyContinue |
                Select -ExpandProperty LoggedOnDisplayname
            If ($LoggedOnDisplayName)
            {
                Add-Member -InputObject $LoggedOnUser -Name LoggedOnDisplayName -MemberType NoteProperty -Value $LoggedOnDisplayName -Force
            }
            $LoggedOnUserSid = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\SessionData\$($LoggedOnUser.ID)" -Name LoggedOnUserSid -ErrorAction SilentlyContinue |
                Select -ExpandProperty LoggedOnUserSid
            If ($LoggedOnUserSid)
            {
                Add-Member -InputObject $LoggedOnUser -Name LoggedOnUserSid -MemberType NoteProperty -Value $LoggedOnUserSid -Force
            }
            $LogonCachePath = "HKLM:\SOFTWARE\Microsoft\IdentityStore\LogonCache"
            $UserLogonCache = Get-ChildItem -Path $LogonCachePath -Recurse -ErrorAction SilentlyContinue | 
                where {$_.Property -contains "DisplayName" -and $_.GetValue("DisplayName") -eq "$LoggedOnDisplayName"} | 
                Select -First 1
            If ($UserLogonCache.Count -eq 1)
            {
                try 
                {
                    $IdentityName = $UserLogonCache.GetValue("IdentityName")
                }
                catch 
                {}
                If ($IdentityName)
                {
                    Add-Member -InputObject $LoggedOnUser -Name UserPrincipalName -MemberType NoteProperty -Value $IdentityName -Force
                }
            }
        }

        $LoggedOnUsersString = ($LoggedOnUsers.LoggedOnDisplayName -Join "  ||  ").Replace('[','').Replace(']','')
        $LoggedOnUsersPrincipalNameString = ($LoggedOnUsers.UserPrincipalName -Join "  ||  ").Replace('[','').Replace(']','')
        return [PSCustomObject]@{
            CurrentUser = $LoggedOnUsersString
            UserPrincipalName = $LoggedOnUsersPrincipalNameString
        }
    }
}
#endregion --------------------------------------------------------------------------------------------------------------------


#region ----------------------------------------- Get device information ------------------------------------------------------
# Gathers some basic data about the device
$ComputerName = [System.Net.Dns]::GetHostName()
$CurrentUser = Get-CurrentUser
$EntraDeviceId = Get-EntraDeviceID
$IntuneDeviceId = Get-IntuneDeviceId
$ComputerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue | Select Manufacturer,Model
$LogicalDisk = @(Get-CimInstance Win32_LogicalDisk -ErrorAction SilentlyContinue | Select DeviceId,Description,FileSystem,MediaType,FreeSpace,Size,VolumeName)

$DeviceInfo = [PSCustomObject]@{
    ComputerName = $ComputerName
    CurrentUser = $CurrentUser.CurrentUser
    UserPrincipalName = $CurrentUser.UserPrincipalName
    EntraDeviceId = $EntraDeviceId
    IntuneDeviceId = $IntuneDeviceId
    Manufacturer = $ComputerSystem.Manufacturer
    Model = $ComputerSystem.Model
    LogicalDisk = $LogicalDisk
}

## Output to json file for sample data when creating the Log Analytics table
# ConvertTo-Json -InputObject @($DeviceInfo) -Depth 5 -Compress | Out-File C:\Temp\DeviceInfo.json -Force

## View the data types of the DeviceInfo entries. For comparison with the created Log Analytics table.
# $DeviceInfo | Get-Member -Type NoteProperty | Select Name,Definition
#endregion --------------------------------------------------------------------------------------------------------------------


#region --------------------------------------- Get Application log entries ---------------------------------------------------
# Pulls the last 2500 entries from the Application log. This generates data that is over the 1MB limit for a single post, and
# demonstrates how we split over-sized data into batches to post to Log Analytics.
$ApplicationEvents = Get-WinEvent -LogName Application -MaxEvents 2500 -ErrorAction SilentlyContinue | Select -Property * -ExcludeProperty Keywords,Id,Properties

## Output to json file for sample data when creating the Log Analytics table
# $ApplicationEvents | Select -First 100 | ConvertTo-Json -Depth 10 -Compress | Out-File C:\Temp\ApplicationEvents.json -Force

## View the data types of the Application log entries. For comparison with the created Log Analytics table.
# $ApplicationEvents | Get-Member -Type NoteProperty | Select Name,Definition
#endregion --------------------------------------------------------------------------------------------------------------------


#region --------------------------------------- Get access token for API ------------------------------------------------------
# The certificate must be installed in the local machine certificate store or accessible via the certificate provider
$Params = @{
    TenantId = $TenantId
    AppId = $AppId
    Certificate = (Get-Item Cert:\LocalMachine\My\$CertificateThumbprint)
    Scope = "https://monitor.azure.com//.default"
}
$TokenRequest = Get-Oath2AccessTokenFromCertificate @Params
$Token = $TokenRequest.access_token
#endregion --------------------------------------------------------------------------------------------------------------------


#region -------------------------------- Post the Device data to Log Analytics ------------------------------------------------
$Params = @{
    DataCollectionEndpointURI = $DataCollectionEndpointURI
    DataCollectorImmutableID = "dcr-123e9483825c41d5b3420f8fa454c8mp"
    Table = "DeviceInformation_CL"
    Data = $DeviceInfo
    Token = $Token
}
$response = Send-LogIngestionAPIPost @Params
$Response.StatusCode
#endregion --------------------------------------------------------------------------------------------------------------------


#region -------------------------------- Post the Application logs to Log Analytics ------------------------------------------------
$Params = @{
    DataCollectionEndpointURI = $DataCollectionEndpointURI
    DataCollectorImmutableID = "dcr-1opfded8a252432190f748e6e68a1t9i"
    Table = "ApplicationEvents_CL"
    Data = $ApplicationEvents
    Token = $Token
}
$response = Send-LogIngestionAPIPost @Params
$Response.StatusCode
#endregion --------------------------------------------------------------------------------------------------------------------

