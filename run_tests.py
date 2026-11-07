import os
import sys
import glob
import importlib.util
import traceback

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

test_files = sorted(glob.glob(os.path.join(os.path.dirname(__file__), "tests", "**", "test_*.py"), recursive=True))

total = 0
passed = 0
failed = 0

print(f"=== DISCOVERED {len(test_files)} TEST FILES ===")

for tfile in test_files:
    mod_name = os.path.splitext(os.path.basename(tfile))[0]
    spec = importlib.util.spec_from_file_location(mod_name, tfile)
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print(f"[FAIL] Error loading {mod_name}: {e}")
        failed += 1
        continue

    for attr in dir(mod):
        if attr.startswith("test_") and callable(getattr(mod, attr)):
            func = getattr(mod, attr)
            total += 1
            try:
                func()
                passed += 1
                print(f"  {mod_name}.{attr} ... ok")
            except Exception as e:
                failed += 1
                print(f"  {mod_name}.{attr} ... FAIL: {e}")
                traceback.print_exc()

print(f"\n==========================================")
print(f"RESULTS: {passed}/{total} PASSED ({failed} failed)")
print(f"==========================================")

if failed > 0:
    sys.exit(1)
