vuln_scripts = {    
    # FTP
    21: [
        'ftp-anon',
        'ftp-bounce',
        'ftp-syst',
        'ftp-vsftpd-backdoor',
        'ftp-proftpd-backdoor',
        'ftp-vuln-cve2010-4221',
        'ftp-libopie',
        'ftp-vuln-cve2011-2528',
        'ftp-vuln-cve2015-3306',
        'ftp-brute',
        'ftp-info',
        'ftp-version'
    ],
    # SSH
    22: [
        'ssh-hostkey',
        'ssh-auth-methods',
        'sshv1',
        'ssh2-enum-algos',
        'ssh-brute',
        'ssh-publickey-acceptance',
        'ssh-run',
        'ssh2-brute'
    ],
    # Telnet
    23: [
        'telnet-encryption',
        'telnet-ntlm-info',
        'telnet-brute',
        'telnet-auth',
        'telnet-proto-alias',
        'telnet-info'
    ],
    # SMTP
    25: [
        'smtp-vuln-cve2010-4344',
        'smtp-vuln-cve2011-1720',
        'smtp-vuln-cve2011-1764',
        'smtp-commands',
        'smtp-enum-users',
        'smtp-open-relay',
        'smtp-strangeport',
        'smtp-ntlm-info',
        'smtp-brute',
        'smtp-brute-auth'
    ],
    # DNS
    53: [
        'dns-recursion',
        'dns-zone-transfer',
        'dns-nsid',
        'dns-cache-snoop',
        'dns-random-srcport',
        'dns-service-discovery',
        'dns-fuzz',
        'dns-brute'
    ],
    # HTTP
    80: [
        'http-apache-server-status',
        'http-auth',
        'http-brute',
        'http-default-accounts',
        'http-enum',
        'http-fileupload-exploiter',
        'http-frontpage-login',
        'http-headers',
        'http-methods',
        'http-phpmyadmin-dir-traversal',
        'http-php-version',
        'http-sql-injection',
        'http-stored-xss',
        'http-dombased-xss',
        'http-reflection-xss',
        'http-cross-site-scripting',
        'http-shellshock',
        'http-vuln-cve2009-3960',
        'http-vuln-cve2010-0738',
        'http-vuln-cve2011-3192',
        'http-vuln-cve2011-3368',
        'http-vuln-cve2012-1823',
        'http-vuln-cve2013-0156',
        'http-vuln-cve2013-7091',
        'http-vuln-cve2014-2126',
        'http-vuln-cve2014-2127',
        'http-vuln-cve2014-2128',
        'http-vuln-cve2014-2129',
        'http-vuln-cve2014-3704',
        'http-vuln-cve2015-1427',
        'http-vuln-cve2015-1635',
        'http-vuln-cve2017-5638',
        'http-wordpress-enum',
        'http-wordpress-brute',
        'http-drupal-enum',
        'http-drupal-enum-users',
        'http-robots.txt',
        'http-enum-hosts',
        'http-webdav-scan',
        'http-webdav-probe',
        'http-webdav-brute'
    ],
    # HTTPS
    443: [
        'ssl-heartbleed',
        'ssl-poodle',
        'ssl-ccs-injection',
        'ssl-dh-params',
        'ssl-enum-ciphers',
        'ssl-cert',
        'ssl-known-key',
        'ssl-date',
        'http-vuln-cve2013-7091',
        'http-cross-site-scripting',
        'http-shellshock',
        'http-dombased-xss',
        'http-stored-xss',
        'http-sql-injection',
        'http-enum',
        'http-methods',
        'http-phpmyadmin-dir-traversal',
        'http-php-version',
        'http-vuln-cve2017-5638',
        'http-wordpress-enum',
        'http-wordpress-brute',
        'http-webdav-scan',
        'http-webdav-probe',
        'http-webdav-brute'
    ],
    # SMB
    445: [
        'smb-vuln-conficker',
        'smb-vuln-cve2009-3103',
        'smb-vuln-ms08-067',
        'smb-vuln-ms10-054',
        'smb-vuln-ms10-061',
        'smb-vuln-ms17-010',
        'smb-vuln-regsvc-dos',
        'smb-enum-shares',
        'smb-enum-users',
        'smb-os-discovery',
        'smb-protocols',
        'smb-security-mode',
        'smb-system-info',
        'smb2-security-mode',
        'smb2-capabilities',
        'smb2-time',
        'smb2-vuln-cve2017-7494',
        'smb2-brute'
    ],
    # NetBIOS
    137: [
        'nbstat',
        'broadcast-netbios-master-browser',
        'netbios-smb-os-discovery',
        'nbtstat',
        'netbios-info'
    ],
    # LDAP
    389: [
        'ldap-rootdse',
        'ldap-novell-getpass',
        'ldap-brute',
        'ldap-search',
        'ldap-default-pw',
        'ldap-vuln-cve2009-2445'
    ],
    # Microsoft SQL Server
    1433: [
        'ms-sql-brute',
        'ms-sql-config',
        'ms-sql-dump-hashes',
        'ms-sql-empty-password',
        'ms-sql-info',
        'ms-sql-ntlm-info',
        'ms-sql-tables',
        'ms-sql-xp-cmdshell',
        'ms-sql-schemata',
        'ms-sql-ntlmbrute'
    ],
    # MySQL
    3306: [
        'mysql-brute',
        'mysql-databases',
        'mysql-empty-password',
        'mysql-info',
        'mysql-users',
        'mysql-variables',
        'mysql-vuln-cve2012-2122',
        'mysql-dump-hashes',
        'mysql-pwd-policy',
        'mysql-query'
    ],
    # PostgreSQL
    5432: [
        'pgsql-brute',
        'pgsql-databases',
        'pgsql-empty-password',
        'pgsql-schema',
        'pgsql-users',
        'pgsql-info',
        'pgsql-brute-force',
        'pgsql-version'
    ],
    # RDP
    3389: [
        'rdp-enum-encryption',
        'rdp-ntlm-info',
        'rdp-vuln-ms12-020',
        'rdp-vuln-ms14-058',
        'rdp-banner',
        'rdp-pubkey',
        'rdp-brute',
        'rdp-info'
    ],
    # VNC
    5900: [
        'vnc-brute',
        'vnc-info',
        'realvnc-auth-bypass',
        'vnc-banner',
        'vnc-vuln-cve2012-0617',
        'vnc-pubkey',
        'vnc-enum'
    ],
    # SNMP
    161: [
        'snmp-brute',
        'snmp-hh3c-logins',
        'snmp-info',
        'snmp-interfaces',
        'snmp-netstat',
        'snmp-processes',
        'snmp-sysdescr',
        'snmp-win32-users',
        'snmp-uptime',
        'snmp-mibs'
    ],
    # Telnet
    2323: [
        'telnet-brute',
        'telnet-ntlm-info',
        'telnet-encryption',
        'telnet-info',
        'telnet-ssl'
    ],
    # HTTP
    8080: [
        'http-title',
        'http-methods',
        'http-enum',
        'http-vuln-cve2017-5638',
        'http-dombased-xss',
        'http-stored-xss',
        'http-sql-injection',
        'http-unsafe-output-escaping',
        'http-vuln-cve2013-7091',
        'http-shellshock',
        'http-cross-site-scripting',
        'http-jenkins'
    ],
    # SIP
    5060: [
        'sip-brute',
        'sip-methods',
        'sip-enum-users',
        'sip-call-spoof',
        'sip-options-enum',
        'sip-vuln-cve2017-2217'
    ],
    # RPCBind
    111: [
        'rpcinfo',
        'nfs-ls',
        'nfs-statfs',
        'nfs-showmount',
        'rpc-grind',
        'rpc-svcinfo',
        'rpc-info',
        'rpc-dce'
    ],
    # Redis
    6379: [
        'redis-info',
        'redis-brute',
        'redis-auth',
        'redis-dump',
        'redis-keyscan',
        'redis-command-info'
    ],
    # MongoDB
    27017: [
        'mongodb-brute',
        'mongodb-info',
        'mongodb-databases',
        'mongodb-users',
        'mongodb-dump',
        'mongodb-version',
        'mongodb-sysinfo'
    ],
    # ElasticSearch
    9200: [
        'http-enum',
        'http-title',
        'http-methods',
        'http-auth',
        'elasticsearch',
        'elasticsearch-create-index',
        'elasticsearch-info',
        'elasticsearch-brute',
        'elasticsearch-sqli',
        'elasticsearch-vuln-cve2015-1427'
    ],
    # MQTT
    1883: [
        'mqtt-subscribe',
        'mqtt-brute',
        'mqtt-version',
        'mqtt-publish'
    ],
    8883: [
        'mqtt-subscribe',
        'mqtt-brute',
        'mqtt-version',
        'mqtt-publish'
    ],
    # AMQP
    5672: [
        'amqp-info',
        'amqp-queue',
        'amqp-brute',
        'amqp-publish',
        'amqp-consume'
    ],
    # Rlogin
    513: [
        'rlogin-brute',
        'rlogin-enum-users',
        'rlogin-info',
        'rlogin-ssl'
    ],
    # Rsync
    873: [
        'rsync-brute',
        'rsync-list-modules',
        'rsync-info',
        'rsync-version'
    ],
    # NTP
    123: [
        'ntp-monlist',
        'ntp-info',
        'ntp-peers',
        'ntp-version',
        'ntp-service-info'
    ],
    # IRC
    6667: [
        'irc-info',
        'irc-botnet-channels',
        'irc-unrealircd-backdoor',
        'irc-brute',
        'irc-enum-users',
        'irc-server-info'
    ],
    # Apple Filing Protocol (AFP)
    548: [
        'afp-brute',
        'afp-ls',
        'afp-path-vuln',
        'afp-info',
        'afp-auth'
    ],
    # SAP
    50000: [
        'sap-info',
        'sap-epa',
        'sap-abrase',
        'sap-brute',
        'sap-version',
        'db2-info',
        'db2-version',
        'db2-brute',
        'db2-query'
    ],
    # PPTP
    1723: [
        'pptp-version',
        'pptp-brute',
        'pptp-info',
        'pptp-auth'
    ],
    # TeamViewer
    5938: [
        'teamviewer-info',
        'teamviewer-version',
        'teamviewer-brute',
        'teamviewer-auth'
    ],
    # SVN
    3690: [
        'svn-brute',
        'svn-info',
        'svn-repo-enum',
        'svn-publish',
        'svn-dump'
    ],
    # SMTP
    587: [
        'smtp-commands',
        'smtp-enum-users',
        'smtp-open-relay',
        'smtp-brute',
        'smtp-auth-info'
    ],
    # POP3
    110: [
        'pop3-brute',
        'pop3-capabilities',
        'pop3-ntlm-info',
        'pop3-info',
        'pop3-version'
    ],
    # IMAP
    143: [
        'imap-brute',
        'imap-capabilities',
        'imap-ntlm-info',
        'imap-info',
        'imap-version'
    ],
    # Oracle TNS Listener
    1521: [
        'oracle-tns-version',
        'oracle-brute',
        'oracle-sid-brute',
        'oracle-info',
        'oracle-enum'
    ],
    # Kubernetes API
    6443: [
        'kubernetes-version',
        'kubernetes-brute',
        'kubernetes-api-info',
        'kubernetes-brute-auth'
    ],
    # CouchDB
    5984: [
        'http-couchdb-stats',
        'couchdb-databases',
        'couchdb-version',
        'couchdb-info',
        'couchdb-brute'
    ],
    # Git
    9418: [
        'git-info',
        'git-dump',
        'git-repo-enum',
        'git-version'
    ],
    # Docker
    2375: [
        'docker-info',
        'docker-version',
        'docker-brute',
        'docker-unauth'
    ],
    2376: [
        'docker-tls',
        'docker-version',
        'docker-info'
    ],
    # VNC
    5901: [
        'vnc-brute',
        'vnc-info',
        'realvnc-auth-bypass',
        'vnc-banner',
        'vnc-vuln-cve2012-0617',
        'vnc-pubkey',
        'vnc-enum'
    ],
    # Memcached
    11211: [
        'memcached-info',
        'memcached-brute',
        'memcached-version',
        'memcached-dump'
    ],
    # Kubernetes etcd
    2379: [
        'etcd-info',
        'etcd-version',
        'etcd-brute'
    ],
    # CUPS (Common UNIX Printing System)
    631: [
        'cups-info',
        'cups-version',
        'cups-enum',
        'cups-brute'
    ],
    # GitLab
    8929: [
        'gitlab-info',
        'gitlab-version',
        'gitlab-api-info'
    ],
    # Proxy (General)
    8081: [
        'http-proxy-brute',
        'http-proxy-auth',
        'http-proxy-info',
        'http-proxy-version'
    ],
    3128: [
        'http-proxy-brute',
        'http-proxy-auth',
        'http-proxy-info',
        'http-proxy-version'
    ],
    # FTP
    2121: [
        'ftp-brute',
        'ftp-info',
        'ftp-version',
        'ftp-anon'
    ],
    # RDP
    3390: [
        'rdp-enum-encryption',
        'rdp-ntlm-info',
        'rdp-vuln-ms12-020',
        'rdp-vuln-ms14-058'
    ],
    # WebDAV
    80: [
        'http-webdav-scan',
        'http-webdav-probe',
        'http-webdav-brute'
    ],
    443: [
        'http-webdav-scan',
        'http-webdav-probe',
        'http-webdav-brute'
    ],
    # TeamSpeak
    9987: [
        'teamspeak-info',
        'teamspeak-brute',
        'teamspeak-version'
    ],
    # Oracle HTTP Server
    7777: [
        'oracle-http-info',
        'oracle-http-version',
        'oracle-http-brute'
    ],
    # IBM DB2
    50000: [
        'db2-info',
        'db2-version',
        'db2-brute',
        'db2-query'
    ],
    # Apple Remote Desktop
    3283: [
        'ard-info',
        'ard-version',
        'ard-brute'
    ],
    # IAX (Inter-Asterisk eXchange)
    4569: [
        'iax-info',
        'iax-version',
        'iax-brute'
    ],
    # GitLab Runner
    9140: [
        'gitlab-runner-info',
        'gitlab-runner-version',
        'gitlab-runner-brute'
    ],
    # InfluxDB
    8086: [
        'influxdb-info',
        'influxdb-version',
        'influxdb-brute'
    ],
    # Grafana
    3000: [
        'grafana-info',
        'grafana-version',
        'grafana-brute'
    ],
    # Plex Media Server
    32400: [
        'plex-info',
        'plex-version',
        'plex-brute'
    ],
    # Redis Sentinel
    26379: [
        'redis-sentinel-info',
        'redis-sentinel-brute'
    ],
    # Zabbix
    10051: [
        'zabbix-info',
        'zabbix-version',
        'zabbix-brute'
    ],
    # Consul
    8500: [
        'consul-info',
        'consul-version',
        'consul-brute'
    ],
    # Vault
    8200: [
        'vault-info',
        'vault-version',
        'vault-brute'
    ],
    # Plex Media Server
    32400: [
        'plex-info',
        'plex-version',
        'plex-brute'
    ],
    # Apache Tomcat
    8080: [
        'http-tomcat-manager',
        'http-tomcat-users',
        'http-tomcat-brute'
    ],
    # WildFly (JBoss)
    8080: [
        'http-jboss-manager',
        'http-jboss-users',
        'http-jboss-brute'
    ],
    # WebLogic
    7001: [
        'weblogic-info',
        'weblogic-version',
        'weblogic-brute'
    ],
    # WebSphere
    9060: [
        'websphere-info',
        'websphere-version',
        'websphere-brute'
    ],
    # HAProxy
    1936: [
        'haproxy-info',
        'haproxy-version',
        'haproxy-brute'
    ],
    # Splunk
    8000: [
        'splunk-info',
        'splunk-version',
        'splunk-brute'
    ],
    # SonarQube
    9000: [
        'sonarqube-info',
        'sonarqube-version',
        'sonarqube-brute'
    ],
    # Nexus Repository
    8081: [
        'nexus-info',
        'nexus-version',
        'nexus-brute'
    ],
    # Artifactory
    8082: [
        'artifactory-info',
        'artifactory-version',
        'artifactory-brute'
    ],
    # Kibana
    5601: [
        'kibana-info',
        'kibana-version',
        'kibana-brute'
    ],
    # Grafana
    3000: [
        'grafana-info',
        'grafana-version',
        'grafana-brute'
    ],
    # MQTT
    8883: [
        'mqtt-subscribe',
        'mqtt-brute',
        'mqtt-version',
        'mqtt-publish'
    ],
    # All ports
    'general': [
        'vulners',
        'vuln',
        'banner',
        'fingerprint-strings',
        'http-enum',
        'http-methods',
        'ssl-cert',
        'ssh2-enum-algos',
        'smtp-commands',
        'broadcast-ping',
        'asn-query',
        'ip-geolocation-maxmind',
        'traceroute-geolocation',
        'whois',
        'sniffer-detect',
        'firewalk',
        'mac-address',
        'nbstat',
        'osfingerprint',
        'traceroute',
        'ssl-known-key',
        'ssl-poodle',
        'ssl-heartbleed',
        'ssl-dh-params',
        'ssl-enum-ciphers',
        'ssl-ccs-injection',
        'ftp-bounce',
        'dns-recursion',
        'dns-service-discovery',
        'smb-enum-shares',
        'smb-enum-users',
        'smb-os-discovery',
        'smb-security-mode',
        'smb-system-info',
        'smb2-enum',
        'smb2-info',
        'smb2-version',
        'smb2-brute'
    ]
}