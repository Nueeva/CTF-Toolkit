import marshal, dis

with open("chall (1)_extracted/chall.pyc", "rb") as f:
    f.read(16)
    code_obj = marshal.load(f)

print("--- Daftar Fungsi/Nama ---")
print(code_obj.co_names)

print("\n--- Disassembly (Alur Logika) ---")
dis.dis(code_obj)

