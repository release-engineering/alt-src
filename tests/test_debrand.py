from __future__ import print_function

import os
import sys
from mock import MagicMock, call, patch

from hamcrest import assert_that, not_, contains_string, equal_to
import pytest
import yaml

from alt_src.alt_src import Stager

TESTS_PATH = os.path.dirname(__file__)
MODULES_PATH = os.path.join(TESTS_PATH, 'data', 'module_source')

@pytest.fixture
def fake_rpm_header():
    return {
        1000: 'foo-package',
        1001: '1.0',
        1002: '1',
        1004: 'foo package',
        1106: 1
    }

spec_rule_config = u'''
[spec some text]
patch=foo.patch
'''

simplepatch_rule_config = u'''
[simplepatch some text]
patch=foo.patch
'''

simplepatch_rule_config_fuzz = u'''
[simplepatch some text]
patch=foo.patch
fuzz=3
'''

re_rule_config = u'''
[re some text]
match=nothing
replace=everything
'''

re_rule_config_count = u'''
[re some text]
mode=line
count=1
match=nothing
replace=everything
'''

re_rule_config_modeline_count = u'''
[re some text]
mode=line
count=1
match=nothing
replace=everything
'''


patch_rule_config_add = u'''
[patch some text]
method=add
patch=foo.patch
apply=n
'''


patch_rule_config_add_num = u'''
[patch some text]
method=add
patch=foo.patch
apply=n
num=3
'''


patch_rule_config_del = u'''
[patch some text]
method=del
patch=patch-zero.patch
'''


patch_rule_config_del_num = u'''
[patch some text]
method=del
num=0
'''


source_rule_config_add = u'''
[source some text]
method=add
source=foo-source
'''


source_rule_config_add_num = u'''
[source some text]
method=add
source=foo-source
num=3
'''


source_rule_config_replace = u'''
[source some text]
method=replace
source=foo-source
name=source-zero
'''


source_rule_config_replace_num = u'''
[source some text]
method=replace
source=foo-source
num=0
'''


script_rule_config = u'''
[script some text]
script=some-script
'''

mmd_rule_config = u'''
[mmd some text]
yaml_path=data
  components
  rpms
  .*
  ref
  stream-(.*)$
replace=stream-centos-\\1
'''

mmd_rule_config1 = u'''
[mmd some text]
yaml_path=data
  api
  rpms
  .*
  post(.*)
replace=pre\\1
'''

mmd_rule_config2 = u'''
[mmd some text]
yaml_path=data
  api
  rpms
replace=pre\\1
'''


FOO_PACKAGE_SPEC = u'''
Summary: Dummy package to provide nothing
Name: dummy-foo
Version: 1.0
Release: 1
Group: System Environment/Base
License: MIT
BuildArch: noarch
Provides: nothing and nothing
Patch0: patch-zero.patch
Patch1: patch-once.patch
Source0: source-zero
Source1: source-one

%description
This package is not real. And provides nothing

%files
%patch0
'''


@pytest.fixture
def fake_mmd():
    with open(os.path.join(MODULES_PATH, "modulemd.txt")) as f:
        yield f.read()

@pytest.fixture
def fake_src_mmd():
    with open(os.path.join(MODULES_PATH, "modulemd.src.txt")) as f:
        return yaml.load(f)


@pytest.fixture()
def test_dir(tmp_path):
    d = tmp_path / 'test'
    d.mkdir()
    yield d


@pytest.fixture()
def rules_dir(test_dir):
    d = test_dir / 'rules_dir'
    d.mkdir()
    yield d


@pytest.fixture()
def checkout_dir(test_dir):
    d = test_dir / 'checkout'
    d.mkdir()
    s = d / 'SOURCES'
    s.mkdir()
    yield d


@pytest.fixture()
def work_dir(test_dir):
    d = test_dir / 'workdir'
    d.mkdir()
    yield d


@pytest.fixture
def koji_get_rpm_header(fake_rpm_header):
    with patch('koji.get_rpm_header') as patched_koji_get_rpm_header:
        patched_koji_get_rpm_header.return_value = fake_rpm_header
        yield fake_rpm_header


@pytest.fixture
def read_srpm(koji_get_rpm_header):
    return koji_get_rpm_header


@pytest.fixture
def read_mmd(fake_mmd, fake_src_mmd, checkout_dir):
    koji_client_session = patch('koji.ClientSession')
    koji_path_info = patch('koji.PathInfo')
    patched_koji_client_session = koji_client_session.start()
    patched_koji_path_info = koji_path_info.start()
    patched_koji_client_session.return_value.getBuild.return_value = {
        'extra': {'typeinfo': {'module': {'modulemd_str': fake_mmd}}}}
    patched_koji_path_info.typedir = checkout_dir
    with open(str(checkout_dir / 'SOURCES' / "modulemd.src.txt"), "w") as f:
        yaml.dump(fake_src_mmd, f)
    yield fake_mmd
    koji_client_session.stop()
    koji_path_info.stop()


@pytest.fixture
def read_source(read_srpm, read_mmd):
    # pylint:disable=unused-argument
    yield None

@pytest.fixture
def options(request, rules_dir):
    config = {
        'rulesdir': str(rules_dir),
        'debrand': True,
        'changelog_user': 'pytest',
        'git_name': 'pytest',
        'git_email': 'pytest@notexists.com',
        'koji_hub': None,
        'koji_topdir': None,
        'commit_format': "fake imported: %s"
    }
    yield MagicMock(cfile=None,
                    source=request.param['source'],
                    koji=request.param.get('koji', False),
                    branch=request.param['branch'],
                    config=config)

@pytest.fixture
def rule_cfg(request, rules_dir):
    fname = rules_dir / ('%s.cfg' % request.param['fname'])
    fname.write_text(request.param['rule_cfg'])
    yield fname

@pytest.fixture
def spec_file(request, checkout_dir):
    # pylint:disable=unused-argument
    d = checkout_dir / 'SPECS'
    d.mkdir()
    fname = d / ('%s.spec' % request.param['fname'])
    fname.write_text(FOO_PACKAGE_SPEC)
    yield fname


@pytest.fixture
def stager_setup(request, read_source, rule_cfg, options, checkout_dir,
                 spec_file, work_dir, rules_dir):
    # pylint:disable=unused-argument
    with patch('os.path.isfile') as patched_isfile:
        s = Stager(options)
        s.checkout = str(checkout_dir)
        s.workdir = str(work_dir)
        s.log_cmd = MagicMock()
        s.get_output = MagicMock()
        s.get_output.side_effect = [('', 0), ('x\n', 0), ('\n', 0)]
        yield (s, str(spec_file), str(rules_dir), patched_isfile, str(checkout_dir))


def stager_setup_params(source, branch, rule_cfg):
    return (None,
            {'source': '%s.src.rpm' % source, 'branch': branch},
            {'fname': source, 'rule_cfg': rule_cfg},
            {'fname': source})


def stager_setup_mmd_params(modname, branch, rule_cfg):
    return (None,
            {'source': 'modulemd.src.txt', 'branch': branch, "koji": True},
            {'fname': modname, 'rule_cfg': rule_cfg},
            {'fname': modname})


@pytest.mark.parametrize(
    'stager_setup,options,rule_cfg,spec_file,expected',
    [stager_setup_params('foo-package', 'test-b', spec_rule_config) +
     (('patch -r - --no-backup-if-mismatch {spec_file} {rules_dir}/foo.patch',),),
     stager_setup_params('foo-package', 'test-b', simplepatch_rule_config) +
     (('patch -r - --no-backup-if-mismatch -p1 -i {rules_dir}/foo.patch',),),
     stager_setup_params('foo-package', 'test-b', simplepatch_rule_config_fuzz) +
     (('patch -r - --no-backup-if-mismatch -p1 -i {rules_dir}/foo.patch -F', 3),)
    ],
    ids=['spec', 'simplepatch', 'simplepatch-fuzz'],
    indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_spec(stager_setup, expected):
    # pylint: disable=unused-variable
    stager, spec_file, rules_dir, _, _ = stager_setup
    stager.read_source_file()
    stager.debrand()
    expected_cmd = []
    for e in expected:
        if isinstance(e, str):
            expected_cmd.extend(e.format(**locals()).split(' '))
        else:
            expected_cmd.append(e)
    assert stager.log_cmd.mock_calls[0] == call(expected_cmd, cwd=stager.checkout)


@pytest.mark.parametrize(
    'stager_setup,options,rule_cfg,spec_file,expected',
    [stager_setup_params('foo-package', 'test-b', re_rule_config) +
     ({'nothing': 0},),
     stager_setup_params('foo-package', 'test-b', re_rule_config_count) +
     ({'nothing': 2, 'everything': 2},),
     stager_setup_params('foo-package', 'test-b', re_rule_config_modeline_count) +
     ({'nothing': 2, 'everything': 2},),
    ],
    ids=['re-all', 're-count', 're-modeline-count'],
    indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_re(stager_setup, expected):
    # pylint: disable=unused-variable
    stager, spec_file, _, _, _ = stager_setup
    stager.read_source_file()
    stager.debrand()
    with open(spec_file) as f:
        spec = f.read()
        spec_words = []
        for line in spec.split('\n'):
            spec_words.extend(line.split(' '))
        for word, count in expected.items():
            print(spec_words)
            assert spec_words.count(word) == count

@pytest.mark.parametrize('stager_setup,options,rule_cfg,spec_file,expected',
                         [stager_setup_params('foo-package', 'test-b', patch_rule_config_add) +
                          (contains_string('Patch2: foo.patch'),),
                          stager_setup_params('foo-package', 'test-b', patch_rule_config_add_num) +
                          (contains_string('Patch3: foo.patch'),),
                          stager_setup_params('foo-package', 'test-b', patch_rule_config_del) +
                          (not_(contains_string('Patch0: patch-zero.patch')),),
                          stager_setup_params('foo-package', 'test-b', patch_rule_config_del_num) +
                          (not_(contains_string('Patch0: patch-zero.patch')),),
                         ],
                         ids=['add-patch', 'add-patch-num', 'del-patch-name', 'del-patch-num'],
                         indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_patch(stager_setup, expected):
    # pylint: disable=unused-variable
    stager, spec_file, _, patched_isfile, _ = stager_setup
    patched_isfile.side_effect = [False, False, False]
    stager.read_source_file()
    with patch('shutil.copy2') as _:
        stager.debrand()
        with open(spec_file) as f:
            spec = f.read()
            print(spec)
            assert_that(spec, expected)


@pytest.mark.parametrize(
    'stager_setup,options,rule_cfg,spec_file,expected',
    [stager_setup_params('foo-package', 'test-b', source_rule_config_add) +
     (contains_string('Source2:\tfoo-source'),),
     stager_setup_params('foo-package', 'test-b', source_rule_config_add_num) +
     (contains_string('Source3:\tfoo-source'),),
     stager_setup_params('foo-package', 'test-b', source_rule_config_replace) +
     (not_(contains_string('Souce0: source-zero')),),
     stager_setup_params('foo-package', 'test-b', source_rule_config_replace_num) +
     (not_(contains_string('Source0: source-zero')),),
    ],
    ids=['add-source', 'add-source-num', 'replace-source-name', 'replace-source-num'],
    indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_source(stager_setup, expected):
    # pylint: disable=unused-variable
    stager, spec_file, _, patched_isfile, _ = stager_setup
    patched_isfile.side_effect = [False, False, False]
    stager.read_source_file()
    with patch('shutil.copy2') as _:
        stager.debrand()
        with open(spec_file) as f:
            spec = f.read()
            print(spec)
            assert_that(spec, expected)


@pytest.mark.parametrize('stager_setup,options,rule_cfg,spec_file,expected',
                         [stager_setup_params('foo-package', 'test-b', script_rule_config) +
                          (("{rules_dir}/some-script {checkout_dir} {spec_file}",),),
                         ],
                         ids=['run-script'],
                         indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_script(stager_setup, expected):
    # pylint: disable=unused-variable
    stager, spec_file, rules_dir, patched_isfile, checkout_dir = stager_setup
    patched_isfile.side_effect = [True, True, True]
    stager.read_source_file()
    stager.debrand()
    expected_cmd = []
    for e in expected:
        if isinstance(e, str):
            expected_cmd.extend(e.format(**locals()).split(' '))
        else:
            expected_cmd.append(e)
    assert stager.log_cmd.mock_calls[0] == call(expected_cmd, cwd=stager.checkout)

@pytest.mark.parametrize('stager_setup,options,rule_cfg,spec_file,expected',
                         [stager_setup_mmd_params('postgresql', 'test-b', mmd_rule_config) +
                          (contains_string('ref: stream-centos-9.6'),),
                          stager_setup_mmd_params('postgresql', 'test-b', mmd_rule_config1) +
                          (contains_string('pregresql'),),
                         ],
                         ids=['mmd-replace-in-dict', 'mmd-replace-in-list'],
                         indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_mmd(stager_setup, expected):
    stager, _, _, patched_isfile, checkout_dir = stager_setup #pylint: disable=unused-variable
    patched_isfile.side_effect = [True, True, True]
    stager.source_file = os.path.join(MODULES_PATH, "modulemd.src.txt")
    stager.get_output.side_effect = [('\n', 0), ('', 0), ('\n', 0)]

    stager.import_sources()
    stager.read_source_file()
    stager.debrand()
    with open(os.path.join(checkout_dir, "SOURCES", "modulemd.src.txt")) as f:
        mmd = f.read()
        print(mmd)
        assert_that(mmd, expected)


@pytest.mark.parametrize('stager_setup,options,rule_cfg,spec_file',
                         [stager_setup_mmd_params('postgresql', 'test-b', mmd_rule_config2)],
                         ids=['mmd-replace-no-change'],
                         indirect=['stager_setup', 'options', 'rule_cfg', 'spec_file'])
def test_rule_mmd_no_change(stager_setup):
    stager, _, _, patched_isfile, checkout_dir = stager_setup # pylint: disable=unused-variable
    patched_isfile.side_effect = [True, True, True]
    stager.source_file = os.path.join(MODULES_PATH, "modulemd.src.txt")
    stager.get_output.side_effect = [('\n', 0), ('', 0), ('\n', 0)]

    stager.import_sources()
    stager.read_source_file()
    stager.debrand()
    with open(os.path.join(checkout_dir, "SOURCES", "modulemd.src.txt")) as f:
        mmd1 = yaml.load(f)

    with open(os.path.join(MODULES_PATH, "modulemd.src.txt")) as f:
        mmd2 = yaml.load(f)

    assert_that(mmd1, equal_to(mmd2))
