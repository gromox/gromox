[Unit]
Description=Gromox timer service
Documentation=man:timer(8gx)
PartOf=gromox-sa.target

[Service]
Type=simple
User=gromox
ExecStart=@libexecdir@/gromox/timer

[Install]
WantedBy=multi-user.target
