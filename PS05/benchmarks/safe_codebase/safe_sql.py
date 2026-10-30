"""Safe SQL Query benchmark (Parameterized query)."""

import sqlite3


def lookup_user_profile():
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (id INT, username TEXT, role TEXT)")

    user_name = input("Enter username: ")

    # Safe: Parameterized SQL query using placeholder '?'
    cursor.execute("SELECT * FROM users WHERE username = ?", (user_name,))
    rows = cursor.fetchall()
    return rows


if __name__ == "__main__":
    lookup_user_profile()

