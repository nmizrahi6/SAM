import random

import vt
import re
import os
from flask import Flask, request
from dotenv import load_dotenv

ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
url_pattern = re.compile(
    "^https?:\\/\\/(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&\\/=]*)$")

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DEBUG_ENABLED = bool(os.getenv('DEBUG'))

app = Flask(__name__)

fileName = "BotWords.txt"
splitterSymbol = '|'


@app.route("/", methods=['GET'])
def analyze_query():
    try:
        client = vt.Client(VIRUSTOTAL_API_KEY)
        address = search_ip_or_url(request.args.get("question"))
        url_id = vt.url_id(address)
        url = client.get_object("/urls/{}", url_id)
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
        return "Are you trying to get me crazy???  :("


@app.route('/bot', methods=['GET'])
def sendToBot():
    text = request.args.get("question").lower()
    with open(fileName) as f:
        lines = f.readlines()
        Words = {}

        for i in range(0, len(lines) - 1, 2):
            Words[(lines[i][lines[i].rfind(":") + 1:lines[i].rfind("\\")]).lower()] = \
                (lines[i + 1][lines[i + 1].rfind(":") + 1:lines[i + 1].rfind("\\")]).lower().split(splitterSymbol)

        if Words.get(text) == None:
            return "Unknown text"

        randomIndex = random.randint(0, len(Words.get(text)) - 1)

        return Words.get(text)[randomIndex]


def search_ip_or_url(question):
    return search_pattern(question, ip_pattern) or search_pattern(question, url_pattern)


def search_pattern(question, pattern):
    search = pattern.search(question)
    return search.group() if search else None


if __name__ == "__main__":
    app.run(debug=DEBUG_ENABLED)
