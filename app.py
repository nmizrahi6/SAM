import vt
import re
import os
import whois
from flask import Flask, request, json
from dotenv import load_dotenv
import glob
import random

from kql_parser import KQLParser

ip_pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
url_pattern = re.compile(r"""(?i)\b((?:https?:(?:/{1,3}|[a-z0-9%])|[a-z0-9.\-]+[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)/)(?:[^\s()<>{}\[\]]+|\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\))+(?:\([^\s()]*?\([^\s()]+\)[^\s()]*?\)|\([^\s]+?\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’])|(?:(?<!@)[a-z0-9]+(?:[.\-][a-z0-9]+)*[.](?:com|net|org|edu|gov|mil|aero|asia|biz|cat|coop|info|int|jobs|mobi|museum|name|post|pro|tel|travel|xxx|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cs|cu|cv|cx|cy|cz|dd|de|dj|dk|dm|do|dz|ec|ee|eg|eh|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|Ja|sk|sl|sm|sn|so|sr|ss|st|su|sv|sx|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)\b/?(?!@)))""")
score_pattern = re.compile(r'(good|bad|harmful|dangerous|damaging|malicious|suspicious|evil|ok|fine|safe|reputation)')
location_pattern = re.compile(r'(where|Where|address|location|country|place)')

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
DEBUG_ENABLED = bool(os.getenv('DEBUG'))

app = Flask(__name__)
kql_parser = KQLParser()
vt_client = vt.Client(VIRUSTOTAL_API_KEY)
# vt_client = vt.Client("d1e92706f60c662b5a2b9b79672086bfc39790123b0f70770373cc7bfad2fa0d")

fileName = "BotWords.txt"
splitterSymbol = '|'


@app.route("/", methods=['GET'])
def analyze_query():
    query = request.args.get("question")
    address = search_ip_or_url(query)
    result = None
    result_type = 'kql'
    if address is not None:
        result = get_analyze_func(query)(address)
        result_type = 'address'
    else:
        result = kql_parser.convert_to_kql(query)
    response = app.response_class(
        response=json.dumps({
            'result_type': result_type,
            'result': result,
            'formatted_result': result.replace('\n', '<br>')
        }),
        mimetype='application/json'
    )
    return response


# https://codesandbox.io/s/exciting-fermi-26eosc?file=/src/components/MindlerBotAvatar.jsx:168-224

def get_analyze_func(question):
    if search_pattern(question, score_pattern):
        return question_type["score"]
    elif search_pattern(question, location_pattern):
        return question_type["location"]
    return question_type["info"]


def analyze_info_address_query(address):
    try:
        whois_data = whois.whois(address)
        for i in ["updated_date", "expiration_date", "whois_server", "status", "registrar", "registrant_postal_code",
                  "referral_url", "name_servers", "name", "dnssec"]: whois_data.pop(i, None)
        return "This is what I found about " + address + ": \n" + str(whois_data)
    except whois.ClientConnectorError as e:
        return f'Failed to connect to whois:{e}'
    except Exception as e:
        return f"Failed to get a response from whois:{e}"


def analyze_location_address_query(address):
    try:
        whois_data = whois.whois(address)
        return str({i: whois_data[i] for i in {"address", "city", "state", "country"} if
                    whois_data[i] and whois_data[i] != "REDACTED FOR PRIVACY" and whois_data[i] != "null"})
    except whois.ClientConnectorError as e:
        return f'Failed to connect to whois:{e}'
    except Exception as e:
        return f"Failed to get a response from whois:{e}"


def analyze_score_address_query(address):
    try:
        url_id = vt.url_id(address)
        url = vt_client.get_object("/urls/{}", url_id)
        stats = url.last_analysis_stats
        is_malicious = stats["malicious"] > 0
        return f"""
        [{address=}][{is_malicious=}]
        score: {stats["malicious"]}/{stats["harmless"] + stats["malicious"]}
        {stats["malicious"] or "Zero"} security vendors flagged {address} as malicious
        """
    except vt.ClientConnectorError as e:
        return f'Failed to connect to VirusTotal:{e}'
    except Exception as e:
        return f"Failed to get a response from VirusTotal:{e}"


question_type = {"score": analyze_score_address_query, "info": analyze_info_address_query,
                 "location": analyze_location_address_query}


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
