"""
Google Dorks Module for PyStalker.
Generates targeted queries and direct clickable search URLs for bug bounty OSINT.
"""
import urllib.parse
import requests
from core.config import API_KEYS, DEFAULT_TIMEOUT

def get_dork_list(domain: str, dork_type: str = "all") -> list:
    """Returns a list of targeted Google Dorks for a specific domain."""
    dorks = []

    login_dorks = [
        f"site:{domain} inurl:login OR inurl:signin OR inurl:auth OR inurl:portal",
        f"site:{domain} intitle:\"login\" OR intitle:\"sign in\" OR intitle:\"admin\"",
        f"site:{domain} intext:\"username\" intext:\"password\"",
        f"site:{domain} filetype:php inurl:login"
    ]

    file_dorks = [
        f"site:{domain} ext:env OR ext:sql OR ext:log OR ext:bak OR ext:conf",
        f"site:{domain} inurl:\".env\" OR inurl:\"config.php\" OR inurl:\".git/HEAD\"",
        f"site:{domain} \"AWS_ACCESS_KEY\" OR \"API_KEY\" OR \"SECRET_KEY\"",
        f"site:{domain} \"password\" OR \"credentials\" OR \"BEGIN RSA PRIVATE KEY\"",
        f"site:{domain} intitle:\"index of /\""
    ]

    admin_dorks = [
        f"site:{domain} inurl:wp-admin OR inurl:administrator OR inurl:cpanel",
        f"site:{domain} intitle:\"admin\" OR intitle:\"dashboard\"",
        f"site:{domain} \"welcome to phpmyadmin\" OR inurl:phpmyadmin",
        f"site:{domain} inurl:grafana OR inurl:kibana OR inurl:jenkins"
    ]

    if dork_type in ["all", "login"]:
        for d in login_dorks:
            dorks.append({"category": "Login & Auth", "query": d})

    if dork_type in ["all", "files"]:
        for d in file_dorks:
            dorks.append({"category": "Sensitive Files", "query": d})

    if dork_type in ["all", "admin"]:
        for d in admin_dorks:
            dorks.append({"category": "Admin & Infrastructure", "query": d})

    # Generate direct Google Search URLs
    for item in dorks:
        encoded_query = urllib.parse.quote(item["query"])
        item["search_url"] = f"https://www.google.com/search?q={encoded_query}"

    return dorks

def execute_google_api_dorks(dorks: list) -> list:
    """Executes dorks via Google Custom Search API if credentials are provided."""
    api_key = API_KEYS.get("GOOGLE_API_KEY")
    cse_id = API_KEYS.get("GOOGLE_CSE_ID")
    if not api_key or not cse_id:
        return dorks

    for item in dorks:
        try:
            url = "https://www.googleapis.com/customsearch/v1"
            params = {
                "key": api_key,
                "cx": cse_id,
                "q": item["query"],
                "num": 5
            }
            res = requests.get(url, params=params, timeout=DEFAULT_TIMEOUT)
            if res.status_code == 200:
                data = res.json()
                items = data.get("items", [])
                item["live_results"] = [i.get("link") for i in items if i.get("link")]
        except Exception:
            pass

    return dorks
