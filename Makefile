CC     = x86_64-w64-mingw32-gcc
STRIP  = x86_64-w64-mingw32-strip
CFLAGS = -I _include -Os -masm=intel -fno-stack-protector -mno-stack-arg-probe -DBOF

BOFS = \
	bin/add-groupmember.x64.o \
	bin/add-rbcd.x64.o \
	bin/add-ace.x64.o \
	bin/add-shadowcredentials.x64.o \
	bin/set-owner.x64.o \

.PHONY: all clean

all: banner $(BOFS)
	@echo ""
	@echo "build complete. load acl-abuse.py in havoc script manager."
	@echo ""

bin/%.x64.o: src/%.c | bin/
	@printf "  %-20s" "$(<F)"
	@$(CC) $(CFLAGS) -c $< -o $@
	@$(STRIP) --strip-unneeded $@
	@echo " ok"

bin/:
	@mkdir -p bin/

banner:
	@echo ""
	@echo "acl-abuse-havoc"
	@echo "AD ACL abuse via inline LDAP"
	@echo ""

clean:
	@rm -rf bin/
	@echo "  cleaned."