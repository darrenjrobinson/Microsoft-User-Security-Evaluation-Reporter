# Microsoft-User-Security-Evaulation-Reporter
Evaluating and Reporting on Azure Active Directory/Active Directory Users Security Posture

## Problem
A Security Administrator within an Organisation enables security related configuration options on an Azure Tenant to implement security controls that align an organisation with Microsoft recommendations and best practice. 
The Azure Security Score provides an evaluation on the alignment of an organisation with best practice, however to some extent it still requires end users to have the right configuration for security related elements of their profile. But as a Service Desk Operator or Cyber Security Officer there isn’t a single view of a user’s security posture that can give you an individual user security score summary.

## Introduction
Microsoft User Security Evaluation Reporter (USER) is an Azure AD and Active Directory tool for use by the Service Desk and Cyber Security Officers to get instant visibility of an organisations Azure Security Score that allows them to then evaluate current risks within an organisation right down to individual users.
When the Azure WebApp loads the current Azure Security Score is retrieved, evaluated and displayed for alignment with Microsoft Recommendations. Also, on load the last 5 Active Security Risk Events are displayed. 
The Service Desk Operator or Cyber Security Officer can select one of the recent Security Events and drill down further into the associated identity. They will be quickly able to understand the users’ individual security posture aligned with best practice. 
What are the recent Security Risk Events for that user? Does that user;
*	Have MFA enabled? Is MFA enabled with an Authenticator App as the primary method?
*	Is the users Active Directory password in the Pwned Passwords v4 list from Have I Been Pwned?
*	Has the user recently being attempting Azure Password Reset functions?
*	What are the last 10 logins for that user? 
*	What is the base user information for that user and what devices are registered to that user? Is the device Azure AD Joined?
Guidance is given for the retrieved user based on the configuration of the security options or risks associated with their profile. 
### Service Desk Operator
Likewise, any user in the environment can be searched for and returned. When a Service Desk Operator receives a call for a user they can use Microsoft USER to search for and retrieve that user. 
Does the user have multiple accounts (Hybrid (AD and Azure AD), Cloud Only and/or B2B)? What is the users recent activity? 
As part of the call with the end user the Service Desk Operator could configure the users AD/AAD account to require a password change on next logon if their password has been Pwned. They can advise and talk the user through changing their primary MFA method to use an Authenticator App over SMS. They can see if the user has been having problems using Azure Password Reset and why that maybe failing (e.g fuzzy password violation). They can also review the recent logons for the user and if the user’s Windows Desktop isn’t Azure AD Joined they can talk the user through doing that. 

## Summary
Through everyday use of this tool as part of end-user interactions by the Service Desk Operators and Cyber Security Officers, the Security Posture of end users calling the Service Desk or those who are being flagged with Risk Events can be improved. 
Continuous improvement of end user security posture will also improve the Azure Security Score for the organisation enforcing and aligning with the configuration implemented by the Security Administrators. 

# Setup Requirements
To get and utilise the full functionality of this project you will need an environment that has;
* Active Directory
* Azure Active Directory (synchronised from Active Directory with Azure AD Connect)
* Users enrolled for Azure MFA
* Azure Self Service Password Reset
* Azure App Service for an Azure WebApp and Azure Functions

## 1. Azure AD Application
Using the Azure Portal and the Azure Active Directory Blade register an application. The application will require the following permissions;
* AuditLog.Read.All
* Directory.Read.All
* IdentityRiskEvent.Read.All
* SecurityEvents.Read.All
* User.Read
* User.Read.All

## 2. Azure Functions
The MSUser-Hackathon-azFunctions.zip archive contains the Azure Functions used by the project.
All the functions are PowerShell v1 Functions.  
You will need to create an Azure Function App Plan and Azure Function App. 
* They leverage Managed Service Identity to access the Azure Key Vault. Enable this under the 'Networking' => 'Identity' section of Platform Features for your Azure Function App. Use System Assigned.
* IMPORTANT: Before uploading the Azure Functions under Function App Settings set the Runtime Version to ~1. These PowerShell Functions will not run under v2. 
* Under Platform Features => API => CORS remove the existing Allowed Origins and add * to allow all initially. Once you have your app deployed and you know the name of the WebApp replace * with the WebApp URL.
You can now upload the MSUser-Hackathon-azFunctions.zip archive  using Kudu. For each of the Functions you will need to get the URL from the Azure Functions Blade in the Azure Portal and update the 'lookups.js' file in the webapp with the path to each one.
Each Function contains a 'Modules' directory that contains a slightly modified version of the PSMSGraph PowerShell Module available from my (fork of the PSMSGraph Module here) https://github.com/darrenjrobinson/PSMSGraph
The modification allows the automation of the regeneration of oAuth Tokens from within Azure Functions. The modified version is included in the Azure Functions export. 

### MSUser
This Function isn't actively called but can be used as a test function for MS Graph Queries
A folder under this function named Tokens is required. It contains token artifacts for the registered AzureAD App that allows regeneration of JWT oAuthv2 tokens. Note: The Access Token and Refresh Token is not stored in this folder, but in the Azure KeyVault. See Authentication Tokens below for generating Tokens for the Web App. 

Update the following lines with your AppID and AppSecret
$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

### MSUser-Batch
This Function is called when looking up a user from the WebApp to return information from Micrsofot Graph. It utilises Microsoft Graph JSON Batching 
* Detailed post on JSON Batching (Batching Microsoft Graph API Requests with JSON Batching and PowerShell) https://blog.darrenjrobinson.com/batching-microsoft-graph-api-requests-with-json-batching-and-powershell/

Update the following lines with your AppID and AppSecret
$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

### MSUser-MFA
This Function is called to retrieve a users MFA settings. As user MFA settings are not currently avaialble via Microsoft Graph the information is exported from Azure Active Directory using the MSOnline PowerShell Module and put into Azure Table Service. The MSUser-MFA Function queries the Azure Table Service for the users MFA settings. The Azure Storage Connection information is stored in Azure Key Vault. Update the MSUser-MFA Function to provide the path to the Key Vault for your Storage Key and Storage Account Name. See Azure Key Vault section below for creating these entries.
* $vaultSecretstorageAccountkeyURI = 'https://yourKeyVault.vault.azure.net/secrets/storageAccountkey?'
* $vaultSecretstorageAccountNameURI = 'https://yourKeyVault.vault.azure.net/secrets/storageAccountName?'

#### Example to export users MFA Configuration using the MSOnline Module
* $Accounts = (Get-MsolUser -All | Where-Object {$_.StrongAuthenticationMethods -ne $Null} | Sort-Object DisplayName)
* See MFA-User-Config-Settings.ps1 for an example script to export MFA User Settings

#### How to import data into Azure Table Service with PowerShell
* Detailed post on loading data into Azure Table Service (Loading and Querying Data in Azure Table Storage using PowerShell) https://blog.darrenjrobinson.com/loading-and-querying-data-in-azure-table-storage-using-powershell/

* See Load-MFA-User-Settings-AzureTableService.ps1 for an example script to import MFA data into Azure Table Service

### MSUser-PwnedPassword
This Function checks the selected users Active Directory Password to see if it has been compromised. The Function uses Remote PowerShell to connect to an AD Domain Joined host and run the Lithnet Password Protection for Active Directory Module. It returns the users Pwned Password Status.
The connections settings for the host to remote powershell into are store in the Azure Key Vault
* More information on the Lithnet Password Protection for Active Directory can be found here (Lithnet Password Protection for Active Directory) https://blog.darrenjrobinson.com/lithnet-password-protection-for-active-directory/
* Ensure you implemented appropriate security controls for your organisation to restrict access to this functionality
* Update the MSUser-PwnedPassword Azure Function with the Key Vault URL's for ADDCHost, ADDCUser and ADDCPassword. See Azure Key Vault section below for creating these entries. 
* Configure the host you will be connecting to within the Active Directory environment to validate Pwned Password User Status for Remote PowerShell. (See this post for configuring that) https://blog.darrenjrobinson.com/remotely-managing-your-fimmim-synchronisation-server-using-powershell-and-the-lithnet-miis-automation-powershell-module/ 

### MSUser-PwnedPwdDemo
This Function is a demo function to simulate the return of a users password status. It simply returns randomly true or false. 

### MSUser-RiskEvents
This Function is called on page load to return the 5 most recent Risk Events that are flagged as Active and display them in the app. 

Update the following lines with your AppID and AppSecret
$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

### MSUser-SearchUsers
This Function is called when using the Find User search facility in the WebApp. It returns a table of users where the name entered matches the DisplayName attribute in Azure AD.

Update the following lines with your AppID and AppSecret
$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

### MSUser-SecureScore
This Function is called on page load to return the Azure Secure Score and display it in the app. 

Update the following lines with your AppID and AppSecret
$graphAppCredPwd = ConvertTo-SecureString "yourAppSecret" -AsPlainText -Force
$graphAppCreds = New-Object System.Management.Automation.PSCredential ("yourAppID", $graphAppCredPwd)

## 3. Azure Key Vault
The Azure Key Vault is used for secrets associated with the MS User App.
### Microsoft Graph Tokens
Two entries are required for authentication of the MS User Web App to Azure AD. 
* AccessToken - This contains a valid AAD oAuth Token for the Registered App. See Generating Tokens
* RefreshToken - This contains a valid Refresh Token for the Registered App. See Generating Tokens
* ADDCHost - The FQDN of the Host to connect to, to check a users password pwned status
* ADDCUser - User Account used to connect to the ADDCHost with to verify pwned password status
* ADDCPassword - Password for the ADDCUser account
* storageAccountName - Name of the Azure Storage Account that contains the Azure Table Service Table for MFA Users Configuration data
* storageAccountkey - Azure Storage Account Key that contains the Azure Table Service MFA Users Configuration data
### Managed Service Identity
In order for the Azure Function App to be able to retrieve and update secrets in the Key Vault the Function App will need permissions. 
In the Key Vault under 'Access policies' add your Function App with;
* Secret Permissions - minimum of Get, List and Set

## 4. Authentication Tokens
The MSUser Azure Function mentioned above contains a subdirectory named Tokens. To generate the files to go into this directory, on a local workstation use the Generate-Artifiacts-to-Automate-New-oAuth-Tokens.ps1 script. 
The script uses the (PSMSGraph PowerShell Module available here) https://github.com/markekraus/PSMSGraph 
Update the before execution to contain your AppID and AppSecret for the AAD App created in Step 1. Also update for the path you wish to output the artifacts too and for your AAD Tenant name. 
* Put the generated artifacts (except the AccessToken and RefreshToken) into the Tokens directory user the MSUser Azure Function. 
* Put the AccessToken into the KeyVault under the name AccessToken. Create an Azure Function Application Setting named 'vaultSecretATURI' and put the Key Vault AccessToken URI in it. As these tokens will roll, don't give the URI to a specific token. Use the URI for the Secret e.g. https://myKeyVault.vault.azure.net/secrets/AccessToken? 
* Put the RefreshToken into the KeyVault under the name RefreshToken. Create an Azure Function Application Setting named 'vaultSecretRTURI' and put the Key Vault RefreshToken URI in it. As these tokens will roll, don't give the URI to a specific token. Use the URI for the Secret e.g. https://myKeyVault.vault.azure.net/secrets/RefreshToken?  

## 5. NodeJS WebApp
The Client WebApp is a NodeJS WebApp. 

### Application Insights
Azure Application Insights are enabled for this WebApp. In order to see the insights you will need to;
* create an Application Insights in your Resource Group for this app
* update the 'console.html' file ~ line 47 with your Instrumentation Key retreived after creating Applicaton Insights in the previous step
* update the 'app.js' file ~ line 11 with your Instrumentation Key 

### Azure Container Registry
Create an Azure Container Registry if you don't already have one (using the guide found here)
https://docs.microsoft.com/en-us/azure/container-registry/container-registry-get-started-portal

### Dockerize the WebApp
Download and extract the NodeJS WebApp from here and extract to a local directory. Open the Folder containing the WebApp in VSCode. Install the VSCode Azure and Docker extensions if you don't already have them. 
Create the Docker Image and deploy to the ACR you created in the previous step using VS Code. (Step by Step guide can be found here) https://code.visualstudio.com/tutorials/docker-extension/getting-started
* The WebApp is NodeJS 
* the pre-configured port is 7071
* the cmd to start is 'node bin/www'
* use az acr login --name 'your azure container registry name' in VSCode to authenticate before pushing the docker image to ACR (if you didn't create the ACR via VSCode (e.g you created it via the Azure Portal or have an existing ACR))

### Deploy the WebApp from ACR
Using VSCode and the Docker extension right click on the image and 'Deploy Image to Azure App Service'

### Secure the WebApp
It is highly recommended that you restrict access to this app. Ideally;
* publish the WebApp using Azure AD App Proxy
* configure network access lists under WebApp => Settings => Networking 
