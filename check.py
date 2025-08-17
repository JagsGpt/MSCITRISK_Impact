from sqlalchemy import create_engine, inspect, text
from app import app, AuditItem # Assuming app.py is in the same directory

# Use the same database URI as your Flask app
DATABASE_URI = "postgresql://postgres:Nagamal1!@localhost:5432/grc_db"
engine = create_engine(DATABASE_URI)

with engine.connect() as connection:
    inspector = inspect(connection)
    
    print("\n--- PostgreSQL Table Schema for audit_items ---")
    
    # Check if the table exists
    if 'audit_items' in inspector.get_table_names():
        columns = inspector.get_columns('audit_items')
        for column in columns:
            print(f"Column: {column['name']}, Type: {column['type']}")
    else:
        print("Table 'audit_items' does not exist in 'grc_db'.")
    
    print("--- End Schema Check ---\n")