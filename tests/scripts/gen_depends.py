import itertools
import subprocess

jobs = subprocess.check_output(
    "tests/scripts/depends.py --list-jobs", shell=True).decode().split()
# print(len(jobs),jobs)

for psa, job in itertools.product([False, True], jobs):
    if job[0] == '!':
        job_name = 'not_' + job[1:].lower()
    else:
        job_name = job.lower()

    if psa:
        print(f'''
component_test_depends_py_{job_name} () {{
    msg "test/build: depends.py {job} (gcc)"
    tests/scripts/depends.py {job} --unset-use-psa
}}''')
    else:
        print(f'''
component_test_depends_py_{job_name}_psa () {{
    msg "test/build: depends.py {job} (gcc) with MBEDTLS_USE_PSA_CRYPTO defined"
    tests/scripts/depends.py {job} --unset-use-psa
}}''')
