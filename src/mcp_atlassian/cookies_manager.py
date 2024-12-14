import logging
import sqlite3
from typing import Optional, Dict, List
from datetime import datetime

logger = logging.getLogger("mcp-atlassian")

class CookieManager:
    """Manages Confluence cookies in SQLite database."""
    
    def __init__(self, db_path: str = "c:\\vault\\database\\assistant_state.db"):
        self.db_path = db_path
        self._ensure_tables()
    
    def _ensure_tables(self) -> None:
        """Ensure required tables exist in database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS cookies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT NOT NULL,
                        cookie_name TEXT NOT NULL,
                        cookie_value TEXT NOT NULL,
                        domain TEXT,
                        path TEXT DEFAULT '/',
                        expires TIMESTAMP,
                        http_only BOOLEAN DEFAULT 0,
                        secure BOOLEAN DEFAULT 0,
                        last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS auth_state (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        service TEXT UNIQUE NOT NULL,
                        auth_type TEXT NOT NULL,
                        last_success_auth TIMESTAMP,
                        last_auth_status TEXT,
                        credentials TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        except sqlite3.Error as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    def get_cookies(self, service: str = "confluence") -> Optional[Dict[str, str]]:
        """Get all cookies for a service as a dictionary."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT cookie_name, cookie_value FROM cookies WHERE service = ?",
                    (service,)
                )
                cookies = cursor.fetchall()
                return {name: value for name, value in cookies} if cookies else None
        except sqlite3.Error as e:
            logger.error(f"Error fetching cookies: {e}")
            return None
    
    def get_cookies_header(self, service: str = "confluence") -> Optional[str]:
        """Get cookies formatted as a header string."""
        cookies = self.get_cookies(service)
        if cookies:
            return "; ".join(f"{name}={value}" for name, value in cookies.items())
        return None
    
    def save_cookies(self, cookies: List[Dict], service: str = "confluence") -> bool:
        """Save multiple cookies to database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Clear existing cookies for the service
                conn.execute("DELETE FROM cookies WHERE service = ?", (service,))
                
                # Insert new cookies
                for cookie in cookies:
                    conn.execute("""
                        INSERT INTO cookies (
                            service, cookie_name, cookie_value, domain, 
                            path, expires, http_only, secure
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        service,
                        cookie["name"],
                        cookie["value"],
                        cookie.get("domain"),
                        cookie.get("path", "/"),
                        cookie.get("expires"),
                        cookie.get("httpOnly", False),
                        cookie.get("secure", False)
                    ))
                
                # Update auth state
                conn.execute("""
                    INSERT OR REPLACE INTO auth_state (
                        service, auth_type, last_success_auth, 
                        last_auth_status, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    service,
                    "cookie_based",
                    datetime.now().isoformat(),
                    "success",
                    datetime.now().isoformat()
                ))
                return True
        except sqlite3.Error as e:
            logger.error(f"Error saving cookies: {e}")
            return False
    
    def update_auth_state(
        self, 
        service: str, 
        status: str, 
        auth_type: str = "cookie_based"
    ) -> bool:
        """Update authentication state."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO auth_state (
                        service, auth_type, last_success_auth, 
                        last_auth_status, updated_at
                    ) VALUES (?, ?, ?, ?, ?)
                """, (
                    service,
                    auth_type,
                    datetime.now().isoformat() if status == "success" else None,
                    status,
                    datetime.now().isoformat()
                ))
                return True
        except sqlite3.Error as e:
            logger.error(f"Error updating auth state: {e}")
            return False
            
    def get_last_update(self, service: str = "confluence") -> Optional[datetime]:
        """Get timestamp of last cookie update."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    "SELECT MAX(last_updated) FROM cookies WHERE service = ?",
                    (service,)
                )
                result = cursor.fetchone()
                if result and result[0]:
                    return datetime.fromisoformat(result[0])
                return None
        except sqlite3.Error as e:
            logger.error(f"Error getting last update: {e}")
            return None