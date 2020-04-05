from tito.common import run_command
from tito.tagger import VersionTagger

class MesonVersionTagger(VersionTagger):
    def _set_meson_project_version(self, version):
        version = version.split('-', maxsplit=1)[0]

        run_command('meson rewrite kwargs set project / version %s' % (version))
        run_command('git add -- meson.build')

    def _tag_release(self):
        new_version = self._bump_version()
        self._check_tag_does_not_exist(self._get_new_tag(new_version))
        self._set_meson_project_version(new_version)
        self._update_package_metadata(new_version)
