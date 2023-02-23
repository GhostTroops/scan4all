# Detections and mitigations for ProxyLogon (CVE-2021-26855 + CVE-2021-26857)

• Patch https://techcommunity.microsoft.com/t5/exchange-team-blog/released-march-2021-exchange-server-security-updates/ba-p/2175901

• Run literally one script to fix it https://github.com/microsoft/CSS-Exchange/tree/main/Security

• Monitor IIS logs or place SACL to monitor when anything is written to `C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\`

• Restrict access to OWA to VPN 

• Several mitigation scripts by MS here https://github.com/microsoft/CSS-Exchange/tree/main/Security

• CVE-2021-26857 exploitation can be detected via the Windows Application event logs

• Exploitation of this deserialization bug will create Application events with the following properties:

		• Source: MSExchange Unified Messaging
		
		• EntryType: Error
		
		• Event Message Contains: System.InvalidCastException
		
		• Following is PowerShell command to query the Application Event Log for these log entries:		
			`Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }`
			
Resource:

https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/

