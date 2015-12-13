all:
	make -C real-server
	make -C mitm-server

clean:
	make -C real-server clean
	make -C mitm-server clean
