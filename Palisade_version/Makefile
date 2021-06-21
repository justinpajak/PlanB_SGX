PALISADE_INCLUDES= -I /usr/local/include/palisade/binfhe -I /usr/local/include/palisade/cereal -I /usr/local/include/palisade -I /usr/local/include/palisade/pke -I /usr/local/include/palisade/core
PALISADE_STATIC_LIBS=/usr/local/lib/libPALISADEbinfhe_static.a /usr/local/lib/libPALISADEpke_static.a /usr/local/lib/libPALISADEcore_static.a 
CXX=g++

all: palbgv

palbgv: palbgv.cpp
	$(CXX) $(PALISADE_INCLUDES) -o $@ $< $(PALISADE_STATIC_LIBS)

clean:
	rm -f bin/inverse
	rm -f bin/specialMult
	rm -f bin/makeData
	rm -f bin/secondMult
	rm -rf bin/container
	rm -rf bin/ctexts
	rm -rf bin/result
