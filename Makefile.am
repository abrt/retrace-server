ACLOCAL_AMFLAGS = -I m4
SUBDIRS = doc po src

DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

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
