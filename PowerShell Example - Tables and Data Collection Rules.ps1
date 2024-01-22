## Example PowerShell code for working with Log Analytics tables and the Logs Ingestion API in Azure ##

# Permissions: recommend Contributor permissions to the Log Analytics workspace
# Recommend using PowerShell Core 7 or later due to some issues with dependencies in the Az modules with Windows PowerShell 5.1

#region -------------------------------------- Import Modules and Authenticate -----------------------------------------------------
#Requires -Version 7
#Requires -Modules @{ModuleName='Az.Resources';ModuleVersion='6.12.1'}
#Requires -Modules @{ModuleName='Az.Accounts';ModuleVersion='2.13.2'}
#Requires -Modules @{ModuleName='Az.Monitor';ModuleVersion='5.0.0'}
#Requires -Modules @{ModuleName='Az.OperationalInsights';ModuleVersion='3.2.0'}
Import-Module -Name Az.Resources -MinimumVersion 6.12.1
Import-Module -Name Az.Accounts -MinimumVersion 2.13.2
Import-Module -Name Az.Monitor -MinimumVersion 5.0.0
Import-Module -Name Az.OperationalInsights -MinimumVersion 3.2.0
$null = Connect-AzAccount -Subscription "Pay-As-You-Go" -TenantId '99990ab-ad09-459d-8443-d9b052ab9100'
#endregion -------------------------------------------------------------------------------------------------------------------------


#region ---------------------------------------- Reference: Get API Versions -------------------------------------------------------
# List the available API versions for a resource provider and resource type, for use with Invoke-AzRestMethod
# Note: The latest API is not always the default!

# Resource provider and resource type can be found from the resource ID, eg:
# /subscriptions/e7b7fedf-1234-4321-913b-a08ccd060d9a/resourcegroups/rg-reporting/providers/microsoft.operationalinsights/workspaces/log-devicereporting

$ProviderNamespace = "Microsoft.insights" #"Microsoft.operationalinsights"
$ResourceType = "dataCollectionRules" #"workspaces"

# Using Get-AzResourceProvider - does NOT return the default API version
Get-AzResourceProvider -ProviderNamespace $ProviderNamespace | 
    Where-Object { $_.ResourceTypes.ResourceTypeName -eq $ResourceType } |
    Select-Object -ExpandProperty ResourceTypes | 
    Select-Object -ExpandProperty ApiVersions

# Using Invoke-AzRestMethod - returns the default API version
$subscriptionId = "e7b7fedf-8a8f-4b0c-913b-a08ccd060d9a"#"99990ab-ad09-459d-8443-d9b052ab9100"
$resourceID = "/subscriptions/$subscriptionId/providers/$ProviderNamespace/resourceTypes"
$apiVersion = "2021-04-01"
$response = Invoke-AzRestMethod -Path "$resourceID`?api-version=$apiVersion" -Method GET
($response.Content | ConvertFrom-Json).Value | 
    Where-Object { $_.resourceType -eq $ResourceType } | 
    Select-Object defaultApiVersion,apiVersions
#endregion -------------------------------------------------------------------------------------------------------------------------


#region --------------------------------------------- Create a table ---------------------------------------------------------------
# Using Az.OperationalInsights module
# Note: Cannot pass additional column parameters with this method, such as description, isDefaultDisplay, isHidden
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "Devices_PS_CL" # Must be suffixed with "_CL"
$columns = @{
    'ComputerName' = 'string'
    'CurrentUser' = 'string'   
    'TimeGenerated' = 'DateTime' # Must include this column
}
$Params = @{
    ResourceGroupName = $resourceGroupName
    WorkspaceName = $workspaceName
    TableName = $tableName
    Column = $columns
}
New-AzOperationalInsightsTable @Params


# Using Az Rest Method
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$apiVersion = "2022-10-01"
$tableName = "Devices_REST_CL" # Must be suffixed with "_CL"
$tableHash = @{
    properties = @{
        schema = @{
            name = $TableName
            columns = @(
                [ordered]@{
                    name = "TimeGenerated" # Must include this column
                    type = "datetime"
                },    
                [ordered]@{
                    name = "ComputerName"
                    description = "The device friendly name"
                    type = "string"
                    isDefaultDisplay = $true
                    isHidden = $false
                },
                [ordered]@{
                    name = "CurrentUser"
                    description = "The current logged-on user"
                    type = "string"
                    isDefaultDisplay = $true
                    isHidden = $false
                }
            )
        }
    }
}
$resourceID = "/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"
Invoke-AzRestMethod -Path "$resourceID/tables/$tableName`?api-version=$apiVersion" -Method PUT -payload ($tableHash | ConvertTo-Json -Depth 4)
#endregion -------------------------------------------------------------------------------------------------------------------------


#region --------------------------------------- Create a data collection rule ------------------------------------------------------
# Creates a DCR for the table created above
# Prepare the rule parameters
$location = "eastus"
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$dataCollectionEndpointName = "dce-LogsIngestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "Devices_PS_CL" # Will also be used as the name of the DCR
$transformKql = "source | extend TimeGenerated = now()" # optional

$dataCollectionEndpointId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$dataCollectionEndpointName"
$workspaceResourceId = "/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"

# Create the rule in a hash table
# ref: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-structure
$dcrHash = @{
    location = $location
    properties = @{
        dataCollectionEndpointId = $dataCollectionEndpointId
        streamDeclarations = @{
            "Custom-$tableName" = @{
                columns = @(    
                    [ordered]@{
                        name = "ComputerName"
                        type = "string"
                    },
                    [ordered]@{
                        name = "CurrentUser"
                        type = "string"
                    }
                )
            }
        }
        destinations = @{
            logAnalytics = @(
                @{
                    workspaceResourceId = $workspaceResourceId
                    name = $workspaceName
                }
            )
        }
        dataFlows = @(
            @{
                streams = @(
                    "Custom-$tableName"
                )
                destinations = @(
                    $workspaceName
                )
                transformKql = $transformKql
                outputStream = "Custom-$tableName"
            }
        )
    }
}

# Using Az.Monitor module (option 1)
New-AzDataCollectionRule -Name $tableName -ResourceGroupName $resourceGroupName -JsonString ($dcrHash | ConvertTo-Json -Depth 5)

# Using Az.Monitor module (option 2)
# It creates and passes the objects required by the DCR instead of the JSON string from the above method
$streamDeclaration = @{
    "Custom-$tableName" = @{
        column = @( # This must be "Column" and not "Columns"!   
            [ordered]@{
                name = "ComputerName"
                type = "string"
            },
            [ordered]@{
                name = "CurrentUser"
                type = "string"
            }
        )
    }
}
$destinationObject = New-AzLogAnalyticsDestinationObject -WorkspaceResourceId $workspaceResourceId -Name $workspaceName
$dataFlowObject = New-AzDataFlowObject -Stream "Custom-$tableName" -Destination $workspaceName -TransformKql $transformKql -OutputStream "Custom-$tableName"
$Params = @{
    Name = $tableName
    ResourceGroupName = $resourceGroupName
    Location = $location
    DataCollectionEndpointId = $dataCollectionEndpointId
    DataFlow = $dataFlowObject
    StreamDeclaration = $streamDeclaration
    DestinationLogAnalytic = $destinationObject

}
New-AzDataCollectionRule @Params


# Using Az Rest Method
$tableName = "Devices_REST_CL"
$apiVersion = "2022-06-01"
#! Populate the $dcrHash variable again here so it uses the new table name !#
$resourceID = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$tableName"
Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=$apiVersion") -Method PUT -Payload ($dcrHash | ConvertTo-Json -Depth 5)
#endregion -------------------------------------------------------------------------------------------------------------------------


#region --------------------------------------------- Update a table ---------------------------------------------------------------
# Add additional columns to the table created above
# Using Az.OperationalInsights module
# Note: Cannot pass additional column parameters with this method, such as description, isDefaultDisplay, isHidden
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "Devices_PS_CL"
# Add some additional columns
$additionalColumns = @{
    'Manufacturer' = 'string'
    'Model' = 'string'
}
Update-AzOperationalInsightsTable -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -TableName $tableName -Column $additionalColumns


# Using Az Rest Method
#!! Should work, but doesn't? !!#
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "Devices_REST_CL"
# Add an additional column with description
$tableHash = @{
    properties = @{
        schema = [ordered]@{
            name = $tableName
            columns = @(
                [ordered]@{
                    name = "OSVersion"
                    type = "string"
                }
            )
        }
    }
}
$resourceID = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName"
$apiVersion = "2022-10-01" 
Invoke-AzRestMethod -Path "$resourceID/tables/$tableName`?api-version=$apiVersion" -Method PUT -payload ($tableHash | ConvertTo-Json -Depth 5)
#endregion -------------------------------------------------------------------------------------------------------------------------


#region --------------------------------------- Update a data collection rule ------------------------------------------------------
# Updates the DCR created above for the table created above, adding the additional columns
# Using Az.Monitor module
$resourceGroupName = "logsingestion"
$ruleName = "Devices_PS_CL"
$Rule = Get-AzDataCollectionRule -ResourceGroupName $resourceGroupName -Name $ruleName
$StreamDeclaration = $Rule.StreamDeclaration | ConvertFrom-Json
# Add new columns to the stream declaration
$StreamDeclaration."Custom-$ruleName".columns += [PSCustomObject]@{
    name = "Manufacturer"
    type = "string"
}
$StreamDeclaration."Custom-$ruleName".columns += [PSCustomObject]@{
    name = "Model"
    type = "string"
}
# Convert the stream declaration to a hash table
$newStreamDeclaration = @{
    "Custom-$ruleName" = @{
        Column = @( # This must be "Column" and not "Columns"!
        )
    }
}
foreach ($Column in $StreamDeclaration."Custom-$ruleName".columns)
{
    $newStreamDeclaration["Custom-$ruleName"].Column += @{
        name = $Column.name
        type = $Column.type
    }
}
# Update the rule - UI might not update immediately
$Rule | Update-AzDataCollectionRule -StreamDeclaration $newStreamDeclaration


# Using Az Rest Method
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$ruleName = "Devices_REST_CL"
$resourceID = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/dataCollectionRules/$ruleName"
$apiVersion = "2022-06-01" 
$dcRule = Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=$apiVersion") -Method GET
$dcRuleContent = $dcRule.Content | ConvertFrom-Json
# Add new columns to the stream declaration
$dcRuleContent.Properties.streamDeclarations."Custom-$ruleName".columns += [PSCustomObject]@{
    name = "Manufacturer"
    type = "string"
}
$dcRuleContent.Properties.streamDeclarations."Custom-$ruleName".columns += [PSCustomObject]@{
    name = "Model"
    type = "string"
}
Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=$apiVersion") -Method PUT -Payload ($dcRuleContent | ConvertTo-Json -Depth 5)

# You could also dump the JSON to a file, edit it, and then update the rule
$file = "C:\Temp\dcRule.json"
$dcRule.Content | ConvertFrom-Json | ConvertTo-Json -Depth 20 | Out-File $File -Force
Invoke-Item $File
# Edit and save the file, then read it and post
$dcRuleContent = Get-Content $file -Raw 
Invoke-AzRestMethod -Path ("$ResourceId"+"?api-version=$apiVersion") -Method PUT -Payload $dcRuleContent
#endregion -------------------------------------------------------------------------------------------------------------------------


#region ----------------------------------------- Migrate a table (table 1) --------------------------------------------------------
# These steps are required to migrate (recreate) a table from one workspace to another, from the older API to the newer.
# Only the table schema is migrated, not the data.
# Same workspace migration is the same process, but requires a new table name
# 1. Get the table schema from the source workspace
# 2. Make any required changes to the schema
# 3. Create the table in the destination workspace
# 4. Create a data collection rule for the destination table

# Reference: data types supported by the older HTTP data collector API vs the Logs Ingestion API
# -----------------------------------------
# | Old API data type | New API data type |
# -----------------------------------------
# | string            | string            |
# | boolean           | boolean           |
# | datetime          | datetime          |
# | guid (as string)  | guid              |
# | double            | int, long or real |
# | -                 | dynamic           |
# -----------------------------------------

# Data types notes:
# int (int32, whole numbers only): range -2,147,483,648 to 2,147,483,647
# long (int64, whole numbers only): range -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807
# real (double, decimal): range very small to very large!
# if in doubt, real is a good default choice for numbers as it can handle both whole numbers and decimals
# Use dynamic data type if:
# - you are unsure of the data type, or 
# - you want to store multiple data types in the same column, or
# - you want to store an array of values

##################################################
# Get the table schema from the source workspace #
##################################################
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "DeviceInformation_CL" # case senstive
$sourceTable = Get-AzOperationalInsightsTable -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -TableName $tableName
[System.Collections.Generic.List[PSCustomObject]]$sourceColumns = $sourceTable.Schema.Columns | Sort-Object -Property Name | Select-Object Name,Type 

###########################################
# Make any required changes to the schema #
###########################################
# Review the columns and data types
# Check for:
# - Duplicate column names with different data types (eg guid and string)
# - Use of reserved words (eg "Time" and "Id")
# - Data types not supported by the new API (eg double)
# - Data types that need to be changed (eg guid to string)
# - Column name suffixes that you want to remove (eg "_s")
# - Column names starting with a number
$sourceColumns | Format-Table -AutoSize

# Trim the last two characters from the column name (to remove the data type suffix, eg '_s')
$sourceColumns | foreach {
    If ($_.name.Substring($_.Name.Length-2,1) -eq "_")
    {
        $_.Name = $_.Name.substring(0,$_.Name.Length-2)
    }
}

# Example: Remove an unwanted column
#$sourceColumns.remove(($sourceColumns | where {$_.Name -eq "ActiveHoursMaxRange_d"}))

# Example: Change the data type of the "LogicalDisk" column to "dynamic"
($sourceColumns | where {$_.Name -eq "LogicalDisk"}).Type = "dynamic"

# Example: Change the name of the "Time" column to "LogTime" because "Time" is a reserved word
#($sourceColumns | where {$_.Name -eq "Time"}).Name = "LogTime"


# Create a hash table of the columns
$destinationColumns = [ordered]@{}
foreach ($sourceColumn in $sourceColumns) {
    $destinationColumns.Add($sourceColumn.Name, $sourceColumn.Type)
}

# Example: Add a new column
#$destinationColumns.Add("TemporaryEnterpriseFeatureControlState", "real")

# Add the required "TimeGenerated" column if it doesn't already exist
If (-not $destinationColumns.Keys.Contains("TimeGenerated")) {
    $destinationColumns.Add("TimeGenerated", "datetime")
}

#################################################
# Create the table in the destination workspace #
#################################################
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionMigrationDemo"
$tableName = "DeviceInformation_CL" # Must be suffixed with "_CL"
$Params = @{
    ResourceGroupName = $resourceGroupName
    WorkspaceName = $workspaceName
    TableName = $tableName
    Column = $destinationColumns
}
New-AzOperationalInsightsTable @Params

###############################################
# Prepare the data collection rule parameters #
###############################################
$location = "eastus"
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$dataCollectionEndpointName = "dce-LogsIngestion"
$workspaceName = "LogsIngestionMigrationDemo"
$tableName = "DeviceInformation_CL" 
$transformKql = "source | extend TimeGenerated = now()" # optional

$dataCollectionEndpointId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$dataCollectionEndpointName"
$workspaceResourceId = "/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"

######################################################
# Special handling required for the "guid" data type #
######################################################
If ($destinationColumns.values -contains "guid")
{
    $enumerated = $destinationColumns.GetEnumerator() | where {$_.Value -eq "guid"} 
    $enumerated | foreach {
        # Replace the data type "guid" with "string" because the data collection rule schema does not support the "guid" data type
        $destinationColumns["$($_.Name)"] = "string"
        # Add a transform to convert the string to a guid expected by the table
        if ($transformKql.Length -gt 0)
        {
            $transformKql = "$transformKql | extend $($_.Name) = toguid($($_.Name))"
        }
        else 
        {
            $transformKql = "source | extend $($_.Name) = toguid($($_.Name))"
        }
    }
}

###########################################################
# Create the objects required by the data collection rule #
###########################################################
# Create the base stream declaration as a hash table
$streamDeclaration = @{
    "Custom-$tableName" = @{
        column = @()
    }
}

# Add the columns to the stream declaration, from the new table schema defined earlier
foreach ($columnKey in $destinationColumns.Keys)
{
    $streamDeclaration."Custom-$tableName".column += [ordered]@{
        name = $columnKey
        type = $destinationColumns["$columnKey"]
    }
}

$destinationObject = New-AzLogAnalyticsDestinationObject -WorkspaceResourceId $workspaceResourceId -Name $workspaceName
$dataFlowObject = New-AzDataFlowObject -Stream "Custom-$tableName" -Destination $workspaceName -TransformKql $transformKql -OutputStream "Custom-$tableName"

################################################################
# Create the data collection rule in the destination workspace #
################################################################
$Params = @{
    Name = $tableName
    ResourceGroupName = $resourceGroupName
    Location = $location
    DataCollectionEndpointId = $dataCollectionEndpointId
    DataFlow = $dataFlowObject
    StreamDeclaration = $streamDeclaration
    DestinationLogAnalytic = $destinationObject
}
New-AzDataCollectionRule @Params
#endregion -------------------------------------------------------------------------------------------------------------------------


#region ----------------------------------------- Migrate a table (table 2) --------------------------------------------------------
# These steps are required to migrate (recreate) a table from one workspace to another, from the older API to the newer.
# Only the table schema is migrated, not the data.
# Same workspace migration is the same process, but requires a new table name
# 1. Get the table schema from the source workspace
# 2. Make any required changes to the schema
# 3. Create the table in the destination workspace
# 4. Create a data collection rule for the destination table

# Reference: data types supported by the older HTTP data collector API vs the Logs Ingestion API
# -----------------------------------------
# | Old API data type | New API data type |
# -----------------------------------------
# | string            | string            |
# | boolean           | boolean           |
# | datetime          | datetime          |
# | guid (as string)  | guid              |
# | double            | int, long or real |
# | -                 | dynamic           |
# -----------------------------------------

# Data types notes:
# int (int32, whole numbers only): range -2,147,483,648 to 2,147,483,647
# long (int64, whole numbers only): range -9,223,372,036,854,775,808 to 9,223,372,036,854,775,807
# real (double, decimal): range very small to very large!
# if in doubt, real is a good default choice for numbers as it can handle both whole numbers and decimals
# Use dynamic data type if:
# - you are unsure of the data type, or 
# - you want to store multiple data types in the same column, or
# - you want to store an array of values

##################################################
# Get the table schema from the source workspace #
##################################################
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionDemo"
$tableName = "ApplicationEvents_CL" # case senstive
$sourceTable = Get-AzOperationalInsightsTable -ResourceGroupName $resourceGroupName -WorkspaceName $workspaceName -TableName $tableName
[System.Collections.Generic.List[PSCustomObject]]$sourceColumns = $sourceTable.Schema.Columns | Sort-Object -Property Name | Select-Object Name,Type 

###########################################
# Make any required changes to the schema #
###########################################
# Review the columns and data types
# Check for:
# - Duplicate column names with different data types (eg guid and string)
# - Use of reserved words (eg "Time" and "Id")
# - Data types not supported by the new API (eg double)
# - Data types that need to be changed (eg guid to string)
# - Column name suffixes that you want to remove (eg "_s")
# - Column names starting with a number
$sourceColumns | Format-Table -AutoSize

# Trim the last two characters from the column name (to remove the data type suffix, eg '_s')
$sourceColumns | foreach {
    If ($_.name.Substring($_.Name.Length-2,1) -eq "_")
    {
        $_.Name = $_.Name.substring(0,$_.Name.Length-2)
    }
}

# Example: Change the name of the "Bookmark_BookmarkXml" column to "Bookmark"
($sourceColumns | where {$_.Name -eq "Bookmark_BookmarkXml"}).Name = "Bookmark"

# Example: Change the name of the "UserId_Value" column to "UserId"
($sourceColumns | where {$_.Name -eq "UserId_Value"}).Name = "UserId"

# Example: Change the data type of the "Bookmark" column to "dynamic"
($sourceColumns | where {$_.Name -eq "Bookmark"}).Type = "dynamic"

# Example: Remove the column named "UserId_BinaryLength"
$sourceColumns.remove(($sourceColumns | where {$_.Name -eq "UserId_BinaryLength"}))


# Create a hash table of the columns
$destinationColumns = [ordered]@{}
foreach ($sourceColumn in $sourceColumns) {
    $destinationColumns.Add($sourceColumn.Name, $sourceColumn.Type)
}

# Example: Add a new column
#$destinationColumns.Add("TemporaryEnterpriseFeatureControlState", "real")

# Add the required "TimeGenerated" column if it doesn't already exist
If (-not $destinationColumns.Keys.Contains("TimeGenerated")) {
    $destinationColumns.Add("TimeGenerated", "datetime")
}

#################################################
# Create the table in the destination workspace #
#################################################
$resourceGroupName = "logsingestion"
$workspaceName = "LogsIngestionMigrationDemo"
$tableName = "ApplicationEvents_CL" # Must be suffixed with "_CL"
$Params = @{
    ResourceGroupName = $resourceGroupName
    WorkspaceName = $workspaceName
    TableName = $tableName
    Column = $destinationColumns
}
New-AzOperationalInsightsTable @Params

###############################################
# Prepare the data collection rule parameters #
###############################################
$location = "eastus"
$subscriptionId = "99990ab-ad09-459d-8443-d9b052ab9100"
$resourceGroupName = "logsingestion"
$dataCollectionEndpointName = "dce-LogsIngestion"
$workspaceName = "LogsIngestionMigrationDemo"
$tableName = "ApplicationEvents_CL" 
$transformKql = "source | extend TimeGenerated = now()" # optional

$dataCollectionEndpointId = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.Insights/dataCollectionEndpoints/$dataCollectionEndpointName"
$workspaceResourceId = "/subscriptions/$subscriptionId/resourcegroups/$resourceGroupName/providers/microsoft.operationalinsights/workspaces/$workspaceName"

######################################################
# Special handling required for the "guid" data type #
######################################################
If ($destinationColumns.values -contains "guid")
{
    $enumerated = $destinationColumns.GetEnumerator() | where {$_.Value -eq "guid"} 
    $enumerated | foreach {
        # Replace the data type "guid" with "string" because the data collection rule schema does not support the "guid" data type
        $destinationColumns["$($_.Name)"] = "string"
        # Add a transform to convert the string to a guid expected by the table
        if ($transformKql.Length -gt 0)
        {
            $transformKql = "$transformKql | extend $($_.Name) = toguid($($_.Name))"
        }
        else 
        {
            $transformKql = "source | extend $($_.Name) = toguid($($_.Name))"
        }
    }
}

###########################################################
# Create the objects required by the data collection rule #
###########################################################
# Create the base stream declaration as a hash table
$streamDeclaration = @{
    "Custom-$tableName" = @{
        column = @()
    }
}

# Add the columns to the stream declaration, from the new table schema defined earlier
foreach ($columnKey in $destinationColumns.Keys)
{
    $streamDeclaration."Custom-$tableName".column += [ordered]@{
        name = $columnKey
        type = $destinationColumns["$columnKey"]
    }
}

$destinationObject = New-AzLogAnalyticsDestinationObject -WorkspaceResourceId $workspaceResourceId -Name $workspaceName
$dataFlowObject = New-AzDataFlowObject -Stream "Custom-$tableName" -Destination $workspaceName -TransformKql $transformKql -OutputStream "Custom-$tableName"

################################################################
# Create the data collection rule in the destination workspace #
################################################################
$Params = @{
    Name = $tableName
    ResourceGroupName = $resourceGroupName
    Location = $location
    DataCollectionEndpointId = $dataCollectionEndpointId
    DataFlow = $dataFlowObject
    StreamDeclaration = $streamDeclaration
    DestinationLogAnalytic = $destinationObject
}
New-AzDataCollectionRule @Params
#endregion -------------------------------------------------------------------------------------------------------------------------
