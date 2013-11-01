
all:
	protoc Mumble.proto --python_out=.
	tar xfz celt-0.7.0.tar.gz
	cd celt-0.7.0; ./configure && make
	cp celt-0.7.0/libcelt/.libs/libcelt.so.0.0.0 ./libcelt.so
	python -m py_compile mstream.py

clean:
	rm -f *.pyc
	rm -f *~
	rm -f ./libcelt.so
	rm -rf celt-0.7.0
	rm -f Mumble_pb2.py
	rm -f mstream.log

