PALISADE_INCLUDES= -I /usr/local/include/palisade/binfhe -I /usr/local/include/palisade/cereal -I /usr/local/include/palisade -I /usr/local/include/palisade/pke -I /usr/local/include/palisade/core
PALISADE_STATIC_LIBS=/usr/local/lib/libPALISADEbinfhe_static.a /usr/local/lib/libPALISADEpke_static.a /usr/local/lib/libPALISADEcore_static.a 
CXX=g++

all: bgv

bgv: bgv.cpp include/PALISADEContainer.h
	$(CXX) $(PALISADE_INCLUDES) -o $@ $< $(PALISADE_STATIC_LIBS)

clean:
	rm bgv
	rm -rf container
