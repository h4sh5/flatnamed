sudo setcap 'cap_net_bind_service=+ep' ./flatnamed
./flatnamed $@
