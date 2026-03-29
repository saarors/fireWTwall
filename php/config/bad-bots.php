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
    ],
    'allowed' => [
        'Googlebot', 'Bingbot', 'Slurp', 'DuckDuckBot', 'Baiduspider',
        'YandexBot', 'Sogou', 'facebot', 'ia_archiver',
    ],
    // Block requests with a missing/empty User-Agent header
    'block_empty_user_agent' => true,
];
