"""Vulnerable SQL Injection benchmark."""

import sqlite3


def lookup_user_profile():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")

    # Source: input() (untrusted user input)
    user_name = input("Enter username: ")

    # Propagation: dynamic f-string query construction
    raw_query = f"SELECT * FROM users WHERE username = '{user_name}'"

    # Dangerous Sink: cursor.execute with dynamic concatenated query
    cursor.execute(raw_query)
    rows = cursor.fetchall()
    return rows


if __name__ == "__main__":
    lookup_user_profile()

