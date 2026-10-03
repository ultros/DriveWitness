"""Development-only Python harness comparing the retained Python engine and C# CLI.
Python is not needed to build or run either C# application.
"""
import contextlib
import io
import json
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path

repo = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo / 'legacy' / 'python'))
sys.path.insert(0, str(repo / 'legacy' / 'python' / 'scripts'))
from performance_report import original_module
from dw.config import Config
from dw.scanner import Scanner
from dw.evidence import verify_database
import psutil

cli = repo / 'src' / 'DriveWitness.Cli' / 'bin' / 'Release' / 'net10.0-windows10.0.22000.0' / 'drivewitness-cli.exe'
if len(sys.argv) > 1:
    cli = Path(sys.argv[1]).resolve()
report = {'methodology': 'Three warm-cache repetitions per strategy over the same bounded dataset. Original SHA-1 has weaker guarantees. Python timings exclude module imports; C# process times include process startup/JIT. Also report C# engine time, which excludes process startup. No raw storage saturation claim.',
          'hardware': {'platform': platform.platform(), 'logical_cpus': os.cpu_count(), 'physical_cpus': psutil.cpu_count(logical=False), 'ram_bytes': psutil.virtual_memory().total},
          'dataset': {'small_files': 2000, 'small_bytes_each': 4096, 'medium_files': 4, 'medium_bytes_each': 16 * 1024 * 1024, 'total_bytes': 75300864},
          'results': {}}
original = original_module()
with tempfile.TemporaryDirectory(prefix='DriveWitness-port-profile-') as temp:
    home = Path(temp)
    data = home / 'data'
    data.mkdir()
    for i in range(2000):
        (data / f'small-{i:04}.bin').write_bytes(bytes([i % 256]) * 4096)
    for i in range(4):
        (data / f'medium-{i}.bin').write_bytes(bytes([i]) * (16 * 1024 * 1024))
    for label in ('original_sha1', 'python_serial', 'python_adaptive', 'csharp_serial', 'csharp_adaptive'):
        times, engine_times, summaries = [], [], []
        for i in range(3):
            print(f'{label} {i + 1}/3', flush=True)
            db = home / f'{label}-{i}.db'
            started = time.perf_counter()
            process_elapsed = None
            if label == 'original_sha1':
                conn = original.init_db(db)
                try:
                    with contextlib.redirect_stdout(io.StringIO()):
                        original.index_drive(str(data), conn, scan_time='2026-10-02T00:00:00+00:00')
                finally:
                    conn.close()
            elif label.startswith('python'):
                result = Scanner(db, Config(usn_enabled=False, workers=1 if label.endswith('serial') else None, performance=100)).run([str(data)])
                summaries.append(result['summary'])
            else:
                command = [str(cli), 'scan', str(data), '--db', str(db), '--no-usn', '--performance', '100', '--json']
                if label.endswith('serial'):
                    command += ['--workers', '1']
                process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                maximum_memory = 0
                observer = psutil.Process(process.pid)
                while process.poll() is None:
                    try:
                        maximum_memory = max(maximum_memory, observer.memory_info().rss)
                    except psutil.NoSuchProcess:
                        pass
                    time.sleep(.01)
                stdout, stderr = process.communicate()
                process_elapsed = time.perf_counter() - started
                if process.returncode:
                    raise RuntimeError(stderr)
                result = json.loads(stdout)
                assert result['status'] == 'COMPLETED' and result['summary']['errors'] == 0
                assert result['summary']['bytes_read'] == 75300864
                summaries.append(result['summary'])
                summaries[-1]['peak_working_set_bytes'] = maximum_memory
                engine_times.append(result['summary']['elapsed_seconds'])
                # Reverse interoperability: retained Python verifies newly generated C# manifests/roots.
                assert verify_database(db)['valid']
            times.append(process_elapsed if process_elapsed is not None else time.perf_counter() - started)
        report['results'][label] = {'seconds': times, 'median_seconds': statistics.median(times), 'summary': summaries[-1] if summaries else None}
        if engine_times:
            report['results'][label]['engine_seconds'] = engine_times
            report['results'][label]['median_engine_seconds'] = statistics.median(engine_times)
    process = subprocess.run([str(cli), 'benchmark', str(data), '--json'], capture_output=True, text=True, check=True)
    report['bounded_benchmark'] = json.loads(process.stdout)
    fixture = json.loads((repo / 'tests' / 'DriveWitness.Tests' / 'Fixtures' / 'python-v2.json').read_text())
    test_key = home / 'test-only-signing.pem'
    test_key.write_text(fixture['encrypted_pem'])
    environment = dict(os.environ, DW_TEST_SIGN_PASSWORD='test-only')
    signed_db = home / 'signed-interop.db'
    subprocess.run([str(cli), 'scan', str(data), '--db', str(signed_db), '--performance', '100', '--no-usn', '--json', '--sign-key', str(test_key), '--sign-password-env', 'DW_TEST_SIGN_PASSWORD'], env=environment, capture_output=True, text=True, check=True)
    signed = verify_database(signed_db)
    assert signed['valid'] and signed['signature_valid'], signed
    report['signed_reverse_interoperability'] = signed
    timings = report['results']['csharp_adaptive']['summary']['timings']
    service = {k: v for k, v in timings.items() if k != 'enumeration_wall_with_backpressure'}
    total = sum(service.values())
    report['csharp_subsystem_service_percent'] = {k: 100 * v / total for k, v in service.items()}
    report['dominant_measured_subsystem'] = max(service, key=service.get)
    report['service_percent_note'] = 'Aggregate instrumented service time; concurrent worker service times overlap and are not wall-clock fractions. Enumeration wall time includes backpressure and is excluded from service percentages. Process startup and scheduling/JIT overhead are not separate service components.'
target = repo / 'CSHARP_PERFORMANCE_REPORT.json'
target.write_text(json.dumps(report, indent=2), encoding='utf-8')
print(json.dumps({label: value['median_seconds'] for label, value in report['results'].items()}, indent=2))
print('Dominant measured subsystem:', report['dominant_measured_subsystem'])
