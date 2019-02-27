<#
1. Update Lines 5-8 with your AAD Info
2. Update Line 28 with the output path for the data
#>
$subscriptionName = "Visual Studio Enterprise"
$resourceGroupName = "myMSUserApp"
$storageAccountName = "myStorageAccount"
$tableName = "MFA"

# Log on to Azure and set the active subscription
Add-AzureRMAccount
Select-AzureRmSubscription -SubscriptionName $subscriptionName

# Get the storage key for the storage account
$storageAccountKey = (Get-AzureRmStorageAccountKey -ResourceGroupName $resourceGroupName -Name $storageAccountName).Value[0]

# Get a storage context
$ctx = New-AzureStorageContext -StorageAccountName $storageAccountName -StorageAccountKey $storageAccountKey

# Get a reference to the table
$table = Get-AzureStorageTable -Name $tableName -Context $ctx 

# Partition Key 
$partitionKey = "MFAUserData"

# CSV with export from MSOLUser with MFA Info
# Import CSV with data
$csv = Import-CSV "C:\temp\MFAUsers-16Feb19-withMFAApp-All.CSV" 

[int]$entryCount = 1
[int]$rowCount = 0

# Azure Table Storage Batch Operations
[Microsoft.WindowsAzure.Storage.Table.TableBatchOperation]$batchOperation = New-Object -TypeName Microsoft.WindowsAzure.Storage.Table.TableBatchOperation

Measure-Command {
    foreach ($line in $csv) { 
        $rowCount++
        $entity = New-Object -TypeName Microsoft.WindowsAzure.Storage.Table.DynamicTableEntity -ArgumentList $partitionKey, $entryCount      
        $entryCount++ 
        Write-Host "$($partitionKey), $($line.UPN), $($line.MFAMethod) " 

        $entity.Properties.Add("User", $line.user) 
        $entity.Properties.Add("UPN", $line.UPN) 
        $entity.Properties.Add("MFAMethod", $line.MFAMethod)
        $entity.Properties.Add("MFAApp", $line.MFAApp)
        $entity.Properties.Add("MFAAppDeviceName", $line.MFAAppDeviceName)
        $entity.Properties.Add("MFAPhone", $line.MFAPhone)
        $entity.Properties.Add("MFAEmail", $line.MFAEmail)
        $entity.Properties.Add("MFAStatus", $line.MFAStatus)

        if ($rowCount -le 100) {
            # Add to Batch. Batches max of 100 rows
            $batchOperation.InsertOrReplace($entity) 
        }
        else {
            # Commit 100 rows to the Table
            $rowCount = 0
            $table.CloudTable.ExecuteBatch($batchOperation)
            [Microsoft.WindowsAzure.Storage.Table.TableBatchOperation]$batchOperation = New-Object -TypeName Microsoft.WindowsAzure.Storage.Table.TableBatchOperation
        }
    }
    if ($batchOperation.Count -ne 0) {
        $table.CloudTable.ExecuteBatch($batchOperation)
    }
}

