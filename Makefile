VERSION=1.0

DEBIAN =  -s dir --url https://github.com/flussonic/ssh-proxy --description "SSH proxy server" \
-m "Max Lapshin <max@erlyvideo.org>" --vendor "Erlyvideo, LLC" --license MIT \
--post-install ../postinst --config-files /etc/ssh-proxy/ssh-proxy.conf


package: 
	rm -rf tmproot
	mkdir -p tmproot/usr/sbin
	cp ssh-proxy.erl tmproot/usr/sbin/
	cd tmproot && ../fpm.erl -f -t deb -n ssh-proxy -v $(VERSION) $(DEBIAN) -a amd64 --category net lib etc/ssh-proxy usr && cd ..
	mv tmproot/*.deb .
	rm -rf tmproot

