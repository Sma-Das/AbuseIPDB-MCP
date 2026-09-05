// Package reporting validates AbuseIPDB report intake.
package reporting

// Category is an AbuseIPDB report category.
type Category struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Categories is the complete category list published by AbuseIPDB.
var Categories = []Category{
	{1, "DNS Compromise", "Altering DNS records resulting in improper redirection."},
	{2, "DNS Poisoning", "Falsifying domain server cache (cache poisoning)."},
	{3, "Fraud Orders", "Fraudulent orders."},
	{4, "DDoS Attack", "Participating in a distributed denial-of-service attack, usually as part of a botnet."},
	{5, "FTP Brute-Force", "Brute-force attacks against FTP services."},
	{6, "Ping of Death", "Oversized or malformed IP packet attacks."},
	{7, "Phishing", "Phishing websites or email."},
	{8, "Fraud VoIP", "Fraudulent voice-over-IP activity."},
	{9, "Open Proxy", "Open proxy, open relay, or Tor exit node."},
	{10, "Web Spam", "Comment/forum spam, HTTP referrer spam, or other CMS spam."},
	{11, "Email Spam", "Spam email content, infected attachments, or phishing email."},
	{12, "Blog Spam", "CMS blog comment spam."},
	{13, "VPN IP", "IP address associated with a VPN; use with another category."},
	{14, "Port Scan", "Scanning for open ports and vulnerable services."},
	{15, "Hacking", "General hacking activity not covered by a more specific category."},
	{16, "SQL Injection", "Attempts at SQL injection."},
	{17, "Spoofing", "Email sender spoofing."},
	{18, "Brute-Force", "Credential brute-force attacks against web logins or services."},
	{19, "Bad Web Bot", "Scrapers or crawlers that ignore robots.txt, make excessive requests, or spoof user agents."},
	{20, "Exploited Host", "A host likely compromised and being used for attacks or malicious content."},
	{21, "Web App Attack", "Attempts to probe or exploit web applications, plugins, or administration tools."},
	{22, "SSH", "Secure Shell abuse; use with a more specific category where possible."},
	{23, "IoT Targeted", "Abuse targeting an Internet of Things device."},
}

func validCategory(id int) bool {
	return id >= Categories[0].ID && id <= Categories[len(Categories)-1].ID
}
