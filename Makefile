generate_dev_keys:
	cd dev && \
	ssh-keygen -t rsa -b 4096 -f user_ca -C user_ca && \
	ssh-keygen -f user-key -b 4096 -t rsa && \
	ssh-keygen -s user_ca -I niqote -n niqote -V +1d user-key.pub