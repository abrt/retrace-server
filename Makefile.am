ACLOCAL_AMFLAGS = -I m4
SUBDIRS = doc po src test

DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

EXTRA_DIST = autogen.sh gen-version retrace-server-version retrace-server.spec.in

dist_doc_DATA = README.md

RPM_DIRS = --define "_sourcedir `pwd`" \
	   --define "_rpmdir `pwd`" \
	   --define "_specdir `pwd`" \
	   --define "_builddir `pwd`" \
	   --define "_srcrpmdir `pwd`"

rpm:
	autoconf --force
	$(MAKE) dist
	rpmbuild $(RPM_DIRS) -ba $(PACKAGE_NAME).spec

srpm:
	autoconf --force
	$(MAKE) dist
	rpmbuild $(RPM_DIRS) -bs $(PACKAGE_NAME).spec

# value for overriding from command line
# e.g: make scratch-build DIST=f15
DIST=rawhide
scratch-build: srpm
	koji build --scratch dist-$(DIST) `make srpm | grep Wrote | cut -d' ' -f2`

.PHONY: release-fix
release-fix:
	OLD_VER=$$(git describe --tags --match "[0-9]*" --abbrev=0 HEAD 2>/dev/null); \
	MAJOR_VER=$$(echo $$OLD_VER | cut -d. -f 1); \
	MINOR_VER=$$(echo $$OLD_VER | cut -d. -f 2); \
	FIX_VER=$$(echo $$OLD_VER | cut -d. -f 3); \
	$(MAKE) release OLD_VER=$$OLD_VER NEW_VER="$$MAJOR_VER.$$MINOR_VER.$$((FIX_VER+1))"

.PHONY: release-minor
release-minor:
	OLD_VER=$$(git describe --tags --match "[0-9]*" --abbrev=0 HEAD 2>/dev/null); \
	MAJOR_VER=$$(echo $$OLD_VER | cut -d. -f 1); \
	MINOR_VER=$$(echo $$OLD_VER | cut -d. -f 2); \
	$(MAKE) release OLD_VER=$$OLD_VER NEW_VER="$$MAJOR_VER.$$((MINOR_VER+1)).0"

.PHONY: release-major
release-major:
	OLD_VER=$$(git describe --tags --match "[0-9]*" --abbrev=0 HEAD 2>/dev/null); \
	MAJOR_VER=$$(echo $$OLD_VER | cut -d. -f 1); \
	$(MAKE) release OLD_VER=$$OLD_VER NEW_VER="$$((MAJOR_VER+1)).0.0"

.PHONY: release
release:
	echo "* $$(LANG='en.UTF-8' date +'%a %b %d %Y') $$(git config --get user.name) <$$(git config --get user.email)> $$NEW_VER-1" | sort > /tmp/changelog.tmp; \
	git log --oneline $$OLD_VER..HEAD | awk '{$$1=""; if (a[$$0]++ == 0) print "-" $$0} END {print ""}' | grep -v -e "- Merge" -e "- testsuite:" -e "- make:" >> /tmp/changelog.tmp; \
	sed "$$(grep -n changelog retrace-server.spec.in | cut -f1 -d: | head -n 1)"'r /tmp/changelog.tmp' -i retrace-server.spec.in; \
	sed 's|DEF_VER=.*$$|DEF_VER='$$NEW_VER'|' -i gen-version; \
	git add gen-version retrace-server.spec.in; \
	git commit -m "New version $$NEW_VER"; \
	git tag "$$NEW_VER"; \
	echo -n "$$NEW_VER" > retrace-server-version
	autoconf --force
	$(MAKE) dist
