import pandas as pd
import vt
import re
import os
from flask import Flask, request
from dotenv import load_dotenv
import glob

from kql_parser import KQLParser

ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
url_pattern = re.compile("^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$")


load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DEBUG_ENABLED = bool(os.getenv('DEBUG'))

app = Flask(__name__)
kql_parser = KQLParser()
vt_client = vt.Client(VIRUSTOTAL_API_KEY)

@app.route("/", methods=['GET'])
def analyze_query():
    query = request.args.get("question")
    address = search_ip_or_url(query)
    if address is not None:
        return analyze_address_query(address)
    return kql_parser.convert_to_kql(query)


def analyze_address_query(address):
    try:
        url_id = vt.url_id(address)
        url = vt_client.get_object("/urls/{}", url_id)
        stats = url.last_analysis_stats
        is_malicious = stats["malicious"] > 0
        return f"""
        [{address=}][{is_malicious=}]
        <br>
        score: {stats["malicious"]}/{stats["harmless"] + stats["malicious"]}
        <br>
        {stats["malicious"] or "Zero"} security vendors flagged {address} as malicious
        """
    except vt.ClientConnectorError as e:
        return f'Failed to connect to VirusTotal:{e}'
    except Exception as e:
        return f"Failed to get responce from VirusTotal:{e}"


def search_ip_or_url(question):
    return search_pattern(question, ip_pattern) or search_pattern(question, url_pattern)


def search_pattern(question, pattern):
    search = pattern.search(question)
    return search.group() if search else None


if __name__ == "__main__":
    app.run(debug=DEBUG_ENABLED)

