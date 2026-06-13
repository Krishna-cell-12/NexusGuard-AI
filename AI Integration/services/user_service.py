def get_user_profile(db_connection, user_id: str):
    """Retrieve a user's profile safely using a parameterized query.

    Args:
        db_connection: A DB‑API compatible connection object.
        user_id (str): The identifier of the user whose profile is requested.
    Returns:
        The fetched row or ``None`` if the user does not exist.
    """
    cursor = db_connection.cursor()
    # Use a parameter placeholder to let the DB driver handle escaping and typing.
    query = "SELECT id, username, email, role FROM users WHERE id = %s"
    cursor.execute(query, (user_id,))
    return cursor.fetchone()
