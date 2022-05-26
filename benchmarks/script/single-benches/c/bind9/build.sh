

export ROOT=`pwd`
export target=bind-9.19.1
export BING_HOME="$ROOT/bind_fuzz"

#dependences
apt-get install -y python-ply
apt-get install -y libuv1.dev

function compile ()
{
	if [ -d "$ROOT/$target" ]; then
		rm -rf $ROOT/$target*
	fi
	
	if [ ! -d "$BING_HOME" ]; then
	    mkdir "$BING_HOME"
	fi
	
	wget https://downloads.isc.org/isc/bind9/9.19.1/bind-9.19.1.tar.xz
	tar -xvf bind-9.19.1.tar.xz
	cd $target

	set -ex
	export CC="afl-cc -lxFuzztrace"
	export CXX="afl-c++ -lxFuzztrace"

	./configure \
			--prefix="$BING_HOME"/ \
			--without-gssapi \
			--disable-chroot \
			--disable-linux-caps \
			--without-libtool \
			--enable-epoll \
			--disable-backtrace \
			--with-openssl=yes \
			--disable-doh

	make -j4
	make install
	
	cd -
}


cd $ROOT
compile


