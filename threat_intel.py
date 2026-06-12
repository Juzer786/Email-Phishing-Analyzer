import requests
import base64

VT_API_KEY = "8dfb65730ebb326f412b456f23ad567ade38162a5f515e7e542a8865510b15d5"


def check_url_virustotal(url):

    try:

        url_id = base64.urlsafe_b64encode(
            url.encode()
        ).decode().strip("=")

        headers = {
            "x-apikey": VT_API_KEY
        }

        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers,
            timeout=10
        )

        if response.status_code != 200:
            return None

        data = response.json()

        stats = data["data"]["attributes"][
            "last_analysis_stats"
        ]

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0)
        }

    except Exception:
        return None