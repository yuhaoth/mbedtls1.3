import os
import hashlib
import glob
import hashlib

vsx_dir = "visualc/VS2013"
vsx_ext = "vcxproj"
vsx_app_tpl_file = f"scripts/data_files/vs2013-app-template.{vsx_ext}"
vsx_main_tpl_file = f"scripts/data_files/vs2013-main-template.{vsx_ext}"
vsx_main_file = f"{vsx_dir}/mbedTLS.{vsx_ext}"
vsx_sln_tpl_file = "scripts/data_files/vs2013-sln-template.sln"
vsx_sln_file = f"{vsx_dir}/mbedTLS.sln"

programs_dir = 'programs'
mbedtls_header_dir = 'include/mbedtls'
psa_header_dir = 'include/psa'
source_dir = 'library'
test_source_dir = 'tests/src'
test_header_dir = 'tests/include/test'
test_drivers_header_dir = 'tests/include/test/drivers'
test_drivers_source_dir = 'tests/src/drivers'

thirdparty_header_dirs = [
    '3rdparty/everest/include/everest'
]
thirdparty_source_dirs = [
    '3rdparty/everest/library',
    '3rdparty/everest/library/kremlib',
    '3rdparty/everest/library/legacy'
]

# Directories to add to the include path.
# Order matters in case there are files with the same name in more than
# one directory: the compiler will use the first match.
include_directories = [
    'include',
    '3rdparty/everest/include/',
    '3rdparty/everest/include/everest',
    '3rdparty/everest/include/everest/vs2013',
    '3rdparty/everest/include/everest/kremlib',
    'tests/include'
]

# Directories to add to the include path when building the library, but not
# when building tests or applications.
library_include_directories = [
    'library'
]
library_include_directories = ';'.join([f"../../{dir}" for dir in library_include_directories + include_directories])

excluded_files = [
    '3rdparty/everest/library/Hacl_Curve25519.c'
]
excluded_files = {file: 1 for file in excluded_files}

vsx_hdr_tpl = '    <ClInclude Include="..\\\\..\\\\{NAME}" />\n'
vsx_src_tpl = '\n'

def content_to_file(content, filename):
    with open(filename, 'w') as f:
        f.write(content)


def slurp_file(filename):
    with open(filename) as f:
        return f.read()


def gen_app_guid(appname):
    h = hashlib.md5(f'mbedTLS:{appname}'.encode('utf-8')).hexdigest().upper()
    return '{{{}-{}-{}-{}-{}}}'.format(h[:8], h[8:12], h[12:16], h[16:20], h[20:])


def gen_app(path, template, dir, ext):
    appname = os.path.basename(path)
    guid = gen_app_guid(path)
    path = path.replace('/', '\\')

    srcs = f"<ClCompile Include=\"..\\..\\programs\\{path}.c\" />"
    if appname in ["ssl_client2", "ssl_server2", "query_compile_time_config"]:
        srcs += "\n    <ClCompile Include=\"..\\..\\programs\\test\\query_config.c\" />"
    if appname in ["ssl_client2", "ssl_server2"]:
        srcs += "\n    <ClCompile Include=\"..\\..\\programs\\ssl\\ssl_test_lib.c\" />"

    content = template
    content = content.replace("<SOURCES>", srcs)
    content = content.replace("<APPNAME>", appname)
    content = content.replace("<GUID>", guid)
    content = content.replace("INCLUDE_DIRECTORIES\n", ';'.join([ f'../../{i}' for i in include_directories]))

    with open(os.path.join(dir, f"{appname}.{ext}"), 'w') as f:
        f.write(content)

def get_app_list():
    makefile_contents = slurp_file(os.path.join(programs_dir, 'Makefile'))
    start = makefile_contents.find('APPS =') + len('APPS =')
    end = makefile_contents.find('#', start)
    app_list_str = makefile_contents[start:end].replace('\\','').strip()

    return app_list_str.split()


def gen_app_files(app_list):
    vsx_tpl = slurp_file(vsx_app_tpl_file)

    for app in app_list:
        gen_app(app, vsx_tpl, vsx_dir, vsx_ext)


def gen_entry_list(tpl, *names):
    entries = ''

    for name in sorted(names):
        entry = tpl.replace(r'{NAME}', name)
        entries += entry

    return entries


def gen_main_file(headers, sources,
                  hdr_tpl, src_tpl,
                  main_tpl, main_out):
    header_entries = gen_entry_list(hdr_tpl, *headers)
    source_entries = gen_entry_list(src_tpl, *sources)

    with open(main_tpl) as f:
        out = f.read()
    out = out.replace("SOURCE_ENTRIES\n", source_entries)
    out = out.replace("HEADER_ENTRIES\n", header_entries)
    out = out.replace("INCLUDE_DIRECTORIES\n", library_include_directories)

    with open(main_out, 'w') as f:
        f.write(out)

def gen_vsx_solution(app_names):

    app_entries = ''
    vsx_sln_app_entry_tpl = r"""Project("{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}") = "{APPNAME}", "{APPNAME}.vcxproj", "{GUID}"
        ProjectSection(ProjectDependencies) = postProject
        {46CF2D25-6A36-4189-B59C-E4815388E554} = {46CF2D25-6A36-4189-B59C-E4815388E554}
    EndProjectSection
EndProject
"""

    vsx_sln_conf_entry_tpl = r"""        {GUID}.Debug|Win32.ActiveCfg = Debug|Win32
                {GUID}.Debug|Win32.Build.0 = Debug|Win32
                {GUID}.Debug|x64.ActiveCfg = Debug|x64
                {GUID}.Debug|x64.Build.0 = Debug|x64
                {GUID}.Release|Win32.ActiveCfg = Release|Win32
                {GUID}.Release|Win32.Build.0 = Release|Win32
                {GUID}.Release|x64.ActiveCfg = Release|x64
                {GUID}.Release|x64.Build.0 = Release|x64
"""
    conf_entries = ''
    for app_name in app_names:
        guid = gen_app_guid(app_name)
        app_name = os.path.basename(app_name)
        app_entry = vsx_sln_app_entry_tpl
        app_entry = app_entry.replace(r'{APPNAME}', app_name)
        app_entry = app_entry.replace(r'{GUID}', guid)
        app_entries += app_entry
        conf_entry = vsx_sln_conf_entry_tpl
        conf_entry = conf_entry.replace(r'{GUID}', guid)
        conf_entries += conf_entry
    out = slurp_file(vsx_sln_tpl_file)
    out = out.replace('APP_ENTRIES\n', app_entries)
    out = out.replace('CONF_ENTRIES\n', conf_entries)
    content_to_file(out, vsx_sln_file)


def del_vsx_files():
   for f in glob.glob(vsx_dir + '/*.' + vsx_ext):
      os.unlink(f)

   if os.path.exists(vsx_main_file):
      os.unlink(vsx_main_file)
   if os.path.exists(vsx_sln_file):
      os.unlink(vsx_sln_file)


def main():
   from mbedtls_dev.build_tree import chdir_to_root
   global source_dir
   chdir_to_root()

   del_vsx_files()

   app_list = get_app_list()

   gen_app_files(app_list)

   header_dirs = [
      mbedtls_header_dir,
      psa_header_dir,
      test_header_dir,
      test_drivers_header_dir,
      source_dir
   ] + thirdparty_header_dirs

   headers = set({})
   for header_dir in header_dirs:
      headers|=set(glob.glob(f"{header_dir}/*.h"))

   source_dirs = [
      source_dir,
      test_source_dir,
      test_drivers_source_dir
   ] + thirdparty_source_dirs

   sources = []
   for source_dir in source_dirs:
      sources.extend(glob.glob(f"{source_dir}/*.c"))

   headers = {header for header in headers if header not in excluded_files}
   sources = [source for source in sources if source not in excluded_files]
   headers = [header.replace('/', '\\') for header in headers]
   sources = [source.replace('/', '\\') for source in sources]

   hdr_tpl = '    <ClInclude Include="..\\..\\{NAME}" />\n'
   src_tpl = '    <ClCompile Include="..\\..\\{NAME}" />\n'

   gen_main_file(headers, sources,
               hdr_tpl, src_tpl,
               vsx_main_tpl_file,
               vsx_main_file)

   gen_vsx_solution(app_list)


if __name__ == '__main__':
   main()
