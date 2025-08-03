#!/usr/bin/env python3
import psycopg2
import os
import json
from urllib.parse import urlparse

def extract_data():
    # Parse the DigitalOcean database URL
    database_url = os.environ.get('DIGITALOCEAN_DATABASE_URL')
    if not database_url:
        print("❌ DIGITALOCEAN_DATABASE_URL not found")
        return
    
    parsed = urlparse(database_url)
    
    try:
        # Create connection with minimal settings
        conn = psycopg2.connect(
            host=parsed.hostname,
            port=parsed.port,
            database=parsed.path[1:],  # Remove leading slash
            user=parsed.username,
            password=parsed.password,
            sslmode='require',
            connect_timeout=10
        )
        
        cursor = conn.cursor()
        print("✅ Connected to DigitalOcean database")
        
        # Quick table check
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name
        """)
        
        tables = cursor.fetchall()
        print(f"📋 Found {len(tables)} tables:")
        for table in tables:
            print(f"  - {table[0]}")
        
        # Check data counts in key tables
        key_tables = ['users', 'stores', 'products', 'orders', 'categories']
        
        print("\n📊 Data counts:")
        for table_name in key_tables:
            try:
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                count = cursor.fetchone()[0]
                print(f"  {table_name}: {count} records")
                
                # If there's data, show a sample
                if count > 0:
                    cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
                    sample = cursor.fetchone()
                    if sample:
                        # Get column names
                        cursor.execute(f"""
                            SELECT column_name 
                            FROM information_schema.columns 
                            WHERE table_name = '{table_name}' 
                            ORDER BY ordinal_position
                        """)
                        columns = [col[0] for col in cursor.fetchall()]
                        sample_dict = dict(zip(columns, sample))
                        print(f"    Sample: {json.dumps(sample_dict, default=str, indent=2)[:200]}...")
                        
            except Exception as e:
                print(f"  {table_name}: Error - {str(e)}")
        
        cursor.close()
        conn.close()
        print("\n✅ Data extraction completed")
        
    except Exception as e:
        print(f"❌ Connection failed: {str(e)}")

if __name__ == "__main__":
    extract_data()