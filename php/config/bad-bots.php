<?php

return [
	'blocked' => [
		'sqlmap', 'nikto', 'masscan', 'zgrab', 'dirbuster', 'dirb',
		'gobuster', 'wfuzz', 'nmap', 'Nmap Scripting Engine',
		'hydra', 'metasploit', 'havij',
		'acunetix', 'nessus', 'openvas', 'w3af', 'skipfish', 'arachni',
		'vega', 'burpsuite', 'ZmEu', 'libwww-perl', 'lwp-trivial',
		'binlar', 'BlackWidow', 'BlowFish', 'CazoodleBot', 'comodo',
		'DISCo', 'dotbot', 'EmailSiphon', 'EmailWolf', 'ExaBot',
		'flicky', 'larbin', 'LeechFTP', 'Niki-Bot', 'PageGrabber',
		'SurveyBot', 'webcollage', 'Webster', 'Zeus', 'zmeu',
		'obot', 'psbot', 'python-requests/2', 'Go-http-client/1',
		// Fuzzing / scanning tools
		'ffuf', 'nuclei', 'interactsh', 'wfuzz',
		// Vulnerability scanners
		'qualysguard', 'tenable', 'appscan', 'webscarab',
		// Exploitation frameworks / tools
		'pangolin', 'sqlninja', 'w3af',
		// Crawlers / recon tools
		'shodan', 'censys', 'binaryedge', 'criminalip',
		'shadowserver', 'grayhatwarfare',
		// Brute-force / password tools
		'medusa',
		// Additional scanners
		'golismero', 'joomscan', 'wpscan', 'droopescan',
		// Exploitation frameworks / payloads
		'msf/', 'msfconsole', 'msfpayload', 'jndi-exploit', 'log4j-scanner',
		'interactsh-client', 'routersploit', 'beef-', 'xsser', 'fimap',
		'grabber', 'uniscan', 'vega/', 'paros', 'websecurify', 'n-stealth',
		'webinspect', 'ibm appscan', 'hp webinspect', 'dotdotpwn', 'jexboss',
		'commix', 'tplmap', 'ysoserial', 'nabuu',
	],
	'allowed' => [
		'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
		'YandexBot', 'Sogou', 'facebot', 'ia_archiver',
	],
	// Block requests with a missing/empty User-Agent header
	'block_empty_user_agent' => true,
];
