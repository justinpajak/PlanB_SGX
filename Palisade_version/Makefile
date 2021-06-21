PALISADE_INCLUDES= -I /usr/local/include/palisade/binfhe -I /usr/local/include/palisade/cereal -I /usr/local/include/palisade -I /usr/local/include/palisade/pke -I /usr/local/include/palisade/core
PALISADE_STATIC_LIBS=/usr/local/lib/libPALISADEbinfhe_static.a /usr/local/lib/libPALISADEpke_static.a /usr/local/lib/libPALISADEcore_static.a 
CXX=g++
BINARIES=bin
INCLUDE=include

linearIncludes= $(INCLUDE)/matrix_operations.h $(INCLUDE)/PALISADEContainer.h
all: $(BINARIES)/specialMult $(BINARIES)/makeData $(BINARIES)/inverse $(BINARIES)/secondMult 

initialize: 
	mkdir -p bin/ctexts bin/container bin/result
	touch bin/result/beta.txt

$(BINARIES)/% : src/%.cpp $(linearIncludes)
	$(CXX)  $(PALISADE_INCLUDES) -o $@ $< $(PALISADE_STATIC_LIBS)

clean:
	rm -f bin/inverse
	rm -f bin/specialMult
	rm -f bin/makeData
	rm -f bin/secondMult
	rm -rf bin/container
	rm -rf bin/ctexts
	rm -rf bin/result
