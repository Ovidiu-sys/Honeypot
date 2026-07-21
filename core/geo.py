
"""

IP geolocation using the MaxMind GeoLite2 database (free, offline).

Why offline instead of an API: A honeypot can receive thousands of connections per hour. An API with rate limiting would quickly fail, a local database has no limits

The GeoLite2-City.mmdb database can be downloaded for free from MaxMind after registration: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

Place the .mmdb file in the project's data/ directory. 

"""

from pathlib import Path
from typing import Optional, Tuple

try:
    import geoip2.database
    import geoip2.errors
    GEOIP2_AVAILABLE = True

except ImportError:
    GEOIP2_AVAILABLE = False

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "GeoLite2-City.mmdb"


class GeoLocator:
    def __init__(self,db_path: str = None):
        self._reader = None
        path = db_path or str(DB_PATH)

        if not GEOIP2_AVAILABLE:
            print("[geo] geoip2 is not installed. Geolocation is deactivated")
            return 
        if not Path(path).exists():
            print(f"[geo] {path} does not exist. Install GeoLite2-City.mmd from MaxMind")
            return 
        try:
            self._reader = geoip2.database.Reader(path)
        except Exception as e:
            print(f"[geo] couldn't be able to open GeoIP database: {e}")

    def lookup(self, ip: str) -> Tuple[Optional[str],Optional[str]]:
        # returns (country_name, city_name) for an given IP
        # returns (None, None) if the geolocation isn't available or the IP

        #private/loockback ( 127.x, 192.168.x, 10.x, etc )
        if self._reader is None:
            return None,None

        # The private IPs and lookback doesn't have a geolocation
        if self._is_private(ip):
            return "Local", None

        try:
            response = self._reader.city(ip)
            country = response.country.name
            city = response.city.name
            return country, city
        except geoip2.errors.AddressNotFoundError:
            return None, None
        except Exception:
            return None,None

    @staticmethod
    def _is_private(ip: str) -> bool:
        import ipaddress
        try:
            return ipaddress.ip_address(ip).is_private
        except ValueError:
            return False

    def close(self):
        if self._reader:
            self._reader.close()
