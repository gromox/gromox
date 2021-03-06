[Unit]
Description=Gromox POP3 server
Documentation=man:pop3(8gx)
PartOf=gromox-mra.target
After=mariadb.service mysql.service

[Service]
Type=simple
ExecStart=@libexecdir@/gromox/pop3

[Install]
WantedBy=multi-user.target
