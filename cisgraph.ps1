## powershell scriot with graph access to check cis controls
set-executionpolicy -executionpolicy unrestricted
Install-Module Microsoft.graph
Connect-mggraph -scope "policy.read.all", "User.Read.All", "directory.read.all", "Organization.Read.All", "Group.Read.All"

## for the graph get request use: https://developer.microsoft.com/en-us/graph/graph-explorer
## sign in with global admin and press on modify permissions to consent on reading and getting token


##############################################
##########  ACCOUNT/AUTHENTICATION  ##########
##############################################


## 1.1.1 (L1) Ensure Security Defaults is disabled on Azure Active Directory (Manual)
Get-MgPolicyIdentitySecurityDefaultEnforcementPolicy | ft IsEnabled

## 1.1.2 (L1) Ensure multifactor authentication is enabled for all users in administrative roles (Automated)
GET https://graph.microsoft.com/beta/security/secureScores

## 1.1.4 (L1) Ensure multifactor authentication is enabled for all users (Manual)
GET https://graph.microsoft.com/beta/security/secureScores

## 1.1.7 (L1) Ensure that between two and four global admins are designated (Automated)

$globalAdminRole = Get-MgDirectoryRole -Filter "RoleTemplateId eq '62e90394-69f5-4237-9190-012177145e10'"
$globalAdmins = Get-MgDirectoryRoleMember -DirectoryRoleId $globalAdminRole.Id
Write-Host "*** There are" $globalAdmins.Count "Global Administrators assigned."

## 1.1.12 (L1) Ensure that password hash sync is enabled for hybrid deployments (Manual)
Get-MgOrganization | ft OnPremisesSyncEnabled

## 1.1.16 (L2) Ensure that only organizationally managed/approved public groups exist (Manual)
Get-MgGroup | where {$_.Visibility -eq "Public"} | select DisplayName,Visibility

## 1.1.22 (L1) Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' (Manual)
Get-MgOrganization | ft OnPremisesSyncEnabled

## 1.1.22 (L1) Ensure 'Restrict non-admin users from creating tenants' is set to 'Yes' (Manual)
Select-MgProfile -Name beta
$mgpolicy = Get-MgPolicyAuthorizationPolicy
$mgpolicy.DefaultUserRolePermissions.AdditionalProperties

## 1.2 (L1) Ensure modern authentication for Exchange Online is enabled (Automated)
Connect-ExchangeOnline
Get-OrganizationConfig | Format-Table -Auto Name, OAuth*

## 1.3 (L1) Ensure modern authentication for SharePoint applications is required (Automated)
Connect-SPOService -Url https://tenant-admin.sharepoint.com  ## replace tenant with target company
Get-SPOTenant | ft LegacyAuthProtocolsEnabled

## 1.4 (L1) Ensure the 'Password expiration policy' is set to 'Set passwords to never expire (recommended)' (Automated)
Get-MgDomain -DomainId <Domain Name> | ft PasswordValidityPeriodInDays


########################################
###########  APP Permissions  ##########
########################################


## 2.3 (L2) Ensure 'External sharing' of calendars is not available (Automated)
Connect-ExchangeOnline
Get-SharingPolicy | Where-Object { $_.Domains -like '*CalendarSharing*' }

## 2.5 (L2) Ensure Safe Attachments for SharePoint, OneDrive, and Microsoft Teams is Enabled (Automated)
Connect-ExchangeOnline
Get-AtpPolicyForO365 | fl Name,EnableATPForSPOTeamsODB

## 2.6 (L2) Ensure Office 365 SharePoint infected files are disallowed for download (Automated)
Connect-SPOService -Url https://tenant-admin.sharepoint.com  ## replace tenant with target company
Get-SPOTenant | Select-Object DisallowInfectedFileDownload

## 2.12 (L1) Ensure SharePoint and OneDrive integration with Azure AD B2B is enabled (Manual)
Connect-SPOService -Url https://tenant-admin.sharepoint.com  ## replace tenant with target company
Get-SPOTenant | ft EnableAzureADB2BIntegration


########################################
###########  Data Management  ##########
########################################


## 3.1 (L2) Ensure the customer lockbox feature is enabled (Automated)
Connect-ExchangeOnline
Get-OrganizationConfig |Select-Object CustomerLockBoxEnabled

## 3.3 (L2) Ensure 'external access' is restricted in the Teams center (Manual)
Connect-MicrosoftTeams
Get-CsTenantFederationConfiguration | fl AllowTeamsConsumer,AllowPublicUsers,AllowFederatedUsers,AllowedDomains

## 3.5 (L1) Ensure DLP policies are enabled for Microsoft Teams (Manual)
Connect-ExchangeOnline
Import-Module ExchangeOnlineManagement
Get-DlpCompliancePolicy
Get-DlpCompliancePolicy -Identity "POLICYNAME FROM ABOVE" | Select-Object TeamsLocation*

## 3.6 (L2) Ensure that SharePoint guest users cannot share items they don't own (Automated)
Connect-SPOService
Get-SPOTenant | ft PreventExternalUsersFromResharing

## 3.7 (L2) Ensure external file sharing in Teams is enabled for only approved cloud storage services (Manual)
Connect-MicrosoftTeams
Get-CsTeamsClientConfiguration | select AllowDropbox,AllowBox,AllowGoogleDrive,AllowShareFile,AllowEgnyte

################################################################################
########## EMAIL SECURITY and EXCHANGE ########## all use Connect-ExchangeOnline
################################################################################

## 4.1 (L1) Ensure the Common Attachment Types Filter is enabled (Automated)
Get-MalwareFilterPolicy -Identity Default | Select-Object EnableFileFilter

## 4.2 (L1) Ensure Exchange Online Spam Policies are set to notify administrators (Automated)
Get-HostedOutboundSpamFilterPolicy | Select-Object Bcc*, Notify*

## 4.3 (L1) Ensure all forms of mail forwarding are blocked and/or disabled (Automated)
Get-TransportRule | Where-Object {$_.RedirectMessageTo -ne $null} | ft Name,RedirectMessageTo

## 4.4 (L1) Ensure mail transport rules do not whitelist specific domains (Automated)
Get-TransportRule | Where-Object {($_.setscl -eq -1 -and $_.SenderDomainIs -ne $null)} | ft Name,SenderDomainIs

## 4.5 (L2) Ensure Safe Attachments policy is enabled (Automated)
Get-SafeAttachmentPolicy | where-object {$_.Enable -eq "True"}

## 4.6 (L1) Ensure that an anti-phishing policy has been created (Automated)
Get-AntiPhishPolicy | ft name,enabled,PhishThresholdLevel,EnableMailboxIntelligenceProtection,EnableMailboxIntelligence,EnableSpoofIntelligence

## 4.7 (L1) Ensure that DKIM is enabled for all Exchange Online Domains (Automated)
Get-DkimSigningConfig

## 4.8 (L1) Ensure that SPF records are published for all Exchange Domains (Manual)
nslookup -type=txt domain1.com
https://graph.microsoft.com/v1.0/domains/[DOMAIN.COM]/serviceConfigurationRecords

## 4.9 (L1) Ensure DMARC Records for all Exchange Online domains are published (Manual)
nslookup -type=txt _dmarc.domain1.com

## 4.10 (L1) Ensure notifications for internal users sending malware is Enabled (Automated)
Get-MalwareFilterPolicy | fl Identity,EnableInternalSenderAdminNotifications, InternalSenderAdminAddress

## 4.11 (L2) Ensure MailTips are enabled for end users (Automated)
Get-OrganizationConfig |Select-Object MailTipsAllTipsEnabled,MailTipsExternalRecipientsTipsEnabled, MailTipsGroupMetricsEnabled,MailTipsLargeAudienceThreshold

############################################################
##########  AUDIT  ########## all use Connect-ExchangeOnline
############################################################

## 5.2 (L1) Ensure Microsoft 365 audit log search is Enabled (Automated)
Get-AdminAuditLogConfig | FL UnifiedAuditLogIngestionEnabled

## 5.3 (L1) Ensure mailbox auditing for all users is Enabled (Automated)
Get-OrganizationConfig | Format-List AuditDisabled

## 5.7 (L1) Ensure user role group changes are reviewed at least weekly (Manual)
$startDate = ((Get-date).AddDays(-7)).ToShortDateString()
$endDate = (Get-date).ToShortDateString()
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate -RecordType AzureActiveDirectory -Operations "Add member to role."

## 5.10 (L1) Ensure the Account Provisioning Activity report is reviewed at least weekly (Manual)
$startDate = ((Get-date).AddDays(-7)).ToShortDateString()
$endDate = (Get-date).ToShortDateString()
Search-UnifiedAuditLog -StartDate $startDate -EndDate $endDate | Where-Object { $_.Operations -eq "add user." }

## 5.12 (L1) Ensure the spoofed domains report is reviewed weekly (Automated)
Get-SpoofIntelligenceInsight

## 5.14 (L1) Ensure the 'Restricted entities' report is reviewed weekly (Manual)
Get-BlockedSenderAddress

## 5.15 (L1) Ensure Guest Users are reviewed at least biweekly (Manual)
Connect-MgGraph -Scopes "User.Read.All"
Get-MgUser -All -Property UserType,UserPrincipalName | Where {$_.UserType -ne "Member"} | Format-Table UserPrincipalName, UserType

##########################################################
########## STORAGE  ##########  all use Connect-SPOService
##########################################################

## 6.1 (L2) Ensure SharePoint external sharing is managed through domain whitelist/blacklists (Automated)
Get-SPOTenant | fl SharingDomainRestrictionMode,SharingAllowedDomainList

## 6.2 (L2) Block OneDrive for Business sync from unmanaged devices (Automated)
Get-SPOTenantSyncClientRestriction | fl TenantRestrictionEnabled,AllowedDomainList

## 6.3 (L1) Ensure expiration time for external sharing links is set (Automated)
Get-SPOTenant | fl RequireAnonymousLinksExpireInDays

## 6.5 (L2) Ensure additional storage providers are restricted in Outlook on the web (Automated)
Connect-ExchangeOnline
Get-OwaMailboxPolicy | Format-Table Name, AdditionalStorageProvidersAvailable


