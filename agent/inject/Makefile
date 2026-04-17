# inject/Makefile — builds stub.bin from stub.asm
# Requires: nasm
# On Ubuntu: sudo apt-get install -y nasm

STUB_BIN := stub.bin

.PHONY: all clean

all: $(STUB_BIN)

$(STUB_BIN): stub.asm
	nasm -f bin -o $@ $<
	@echo "stub.bin: $$(wc -c < $@) bytes"

clean:
	rm -f $(STUB_BIN)
