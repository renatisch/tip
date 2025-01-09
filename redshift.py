#Connect to the cluster
import redshift_connector


def fetch_redshift_data(host:str, database:str, token:str):
    conn = redshift_connector.connect(
        host = host,
        database=database,
        port=5439,
        iam=True,
        token=token
    )
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM pg_user;")
    result: tuple = cursor.fetchall()
    return result
