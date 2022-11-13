
# all: echo_client echo_server perf_client perf_server
# %: %.c
#	gcc -o $@ $^ unp.c $(CFLAGS) $(LIBS)



all: echo_client echo_server
%: %.c
	gcc -o $@ $^ unp.c ../csrc/rtcp.c \
		-Wl,--wrap,socket \
		-Wl,--wrap,bind \
		-Wl,--wrap,listen \
		-Wl,--wrap,connect \
		-Wl,--wrap,accept \
		-Wl,--wrap,read \
		-Wl,--wrap,write \
		-Wl,--wrap,close \
		-Wl,--wrap,getaddrinfo \
		-Wl,--wrap,send \
		-Wl,--wrap,recv \
		-L/home/echostone/桌面/CompNet/rtcp/target/debug -lrtcp
