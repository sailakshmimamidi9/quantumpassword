import sqlite3

connection = sqlite3.connect("quantum_passwords.db")

tables = connection.execute(
    "SELECT name FROM sqlite_master WHERE type='table'"
).fetchall()

print("Tables:", tables)

for (table_name,) in tables:
    columns = connection.execute(
        f'PRAGMA table_info("{table_name}")'
    ).fetchall()
    print(f"\n{table_name} columns:")
    for column in columns:
        print(column[1])

connection.close()