TR_x69:= \
	bbfdmd dm-service icwmp obuspa obudpst \
	bulkdata periodicstats stunc twamp \
	udpecho-client udpecho-server userinterface \
	usermngr xmppc timemngr dnsmngr ddnsmngr dhcpmngr \
	self-diagnostics packet-capture-diagnostics \
	usbmngr bridgemngr tr143 tr471 \
	wifidmd netmngr sysmngr gateway-info

IOWRT_PROFILE_PACKAGES := \
		$(TR_x69)
