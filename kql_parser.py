from enum import Enum, IntEnum
from typing import Dict, List, AnyStr, Pattern, Match, Callable, Type
from dataclasses import dataclass, field
import pandas as pd
from fuzzywuzzy import fuzz
from fuzzywuzzy import process
import re
import glob
from pathlib import Path
from pprint import pprint

FUZZY_MATCH_THRESHOLD = 70
TIME_FIELD_PLACEHOLDER = '<timeField>'


class QueryOrder(IntEnum):
    TableName = 0
    PreProcess = 0
    TimeFilter = 1
    BasicFilter = 2
    AdvancedFilter = 3
    Sort = 4
    Summarize = 5
    Project = 6
    Take = 7


class Table:
    TABLES: Dict = {}
    TABLES_BY_KEYWORD: Dict = {}

    def __init__(self,
                 name: str,
                 date_field_name: str,
                 schema: pd.DataFrame,
                 keywords: list = [],
                 filters: List = []
                 ):
        self.name = name
        self.schema = schema
        self.date_field_name = date_field_name
        self.filters = filters
        self.columns = set(schema.ColumnName)
        self.TABLES[name] = self
        self.register_keywords(keywords)

    @staticmethod
    def get(table_name):
        return Table.TABLES.get(table_name)

    def register_keywords(self, keywords):
        for keyword in keywords:
            self.TABLES_BY_KEYWORD[keyword] = self.name


class Filter:
    FILTER_STACK: List = []

    def __init__(self,
                 left_op: str = None,
                operator: str = None,
                right_op: str = None,
                placeholders: List[str] = [],
                table: Table = None
                 ):
        self.left_op = left_op or ''
        self.operator = operator or ''
        self.right_op = right_op or ''
        self.placeholders = placeholders
        self.table = table
        if self.table:
            self.table.filters.append(self)
        else:
            Filter.FILTER_STACK.append(self)

    def __str__(self):
        return f'{self.table.name if self.table else ""}| where {self.left_op} {self.operator} {self.right_op}'


@dataclass
class QueryTemplateRegexOperation:
    """Class for keeping track of an item in inventory."""
    nl_query_pattern: Pattern[str]
    kql_query_replace: Callable[[Match], str]

    def apply(self, text):
        return self.nl_query_pattern.sub(self.kql_query_replace, text)

current_table: Table = None
query_operators = []

def tokenize(replacer_func):
    def inner(*args):
        result = replacer_func(*args)
        if result[1] != '':
            query_operators.append(result)
        return ''
    return inner


@tokenize
def ignore(match: Match):
    return QueryOrder.PreProcess, ''


def resolve_table_name(table_name: str):
    resolved_table_name, confidence = process.extractOne(table_name, Table.TABLES.keys())
    if confidence >= FUZZY_MATCH_THRESHOLD:
        return resolved_table_name
    resolved_table_name_by_kw, confidence = process.extractOne(table_name, Table.TABLES_BY_KEYWORD.keys())
    resolved_table_name = Table.TABLES_BY_KEYWORD[resolved_table_name_by_kw]
    if confidence >= FUZZY_MATCH_THRESHOLD:
        return resolved_table_name
    raise Exception(f'could not resolve table for search term "{table_name}"')

def resolve_column_name(table: Table, column_name: str):
    resolved_field_name, confidence = process.extractOne(column_name, table.columns)
    if confidence >= FUZZY_MATCH_THRESHOLD:
        return resolved_field_name
    return None
    # raise Exception(f'could not resolve {column_name=} for table "{table.name}"')

def get_group(match, group):
    try:
        return match.group(group)
    except:
        return None

@tokenize
def get_time(match: Match):
    if get_group(match, 'all'):
        return ''
    number_str = get_group(match, 'number')
    number = number_str and int(number_str) or 1
    hours = get_group(match, 'hour')
    days = get_group(match, 'day')
    months = get_group(match, 'month')
    weeks = get_group(match, 'week')
    time_range_char = (hours and 'h') or (days and 'd') or (weeks and 'w') or (months and 'd')
    multiplier = (months and 30) or 1
    time_field = current_table.date_field_name if current_table else TIME_FIELD_PLACEHOLDER
    f = Filter(time_field, '>', f'ago({number * multiplier}{time_range_char})')
    return QueryOrder.TimeFilter, str(f)


@tokenize
def get_wildcard_search(match: Match):
    search_term = get_group(match, 'term')
    table_name = get_group(match, 'tableName')

    # resolved_table_name = resolve_table_name(table_name)
    # if resolved_table_name:
    #     current_table = Table.TABLES[resolved_table_name]
    # if resolved_table_name is not None:
    #     return f'{resolved_table_name} | where * contains "{search_term}"'
    return QueryOrder.AdvancedFilter,  f'| where * contains "{search_term}"'

@tokenize
def get_user_details(match: Match):
    user_id_field = get_group(match, 'entity')
    column = get_group(match, 'column')
    if current_table is not None and column is not None:
        resolved_column_name = resolve_column_name(current_table, column)
        if resolved_column_name:
            query_operators.append((QueryOrder.Project, f"| distinct {resolved_column_name}"))
    return QueryOrder.BasicFilter, f"| where * contains '{user_id_field}'"

@tokenize
def get_count(match: Match):
    return QueryOrder.Summarize, '| summarize count'

@tokenize
def get_limit(match: Match):
    if get_group(match, 'all'):
        return QueryOrder.Take, ''
    top = get_group(match, 'top') or get_group(match, 'top2') or 1
    return QueryOrder.Summarize, f'| take {top}'

@tokenize
def get_field_values(match: Match):
    value = get_group(match, 'value') or get_group(match, 'value2')
    column = get_group(match, 'column') or get_group(match, 'column2')
    bigger = get_group(match, 'bigger')
    smaller = get_group(match, 'smaller')
    op = (bigger and '>') or (smaller and '<') or '=~'
    resolved_column_name = resolve_column_name(current_table, column)
    if resolved_column_name:
        return QueryOrder.BasicFilter, f"| where {resolved_column_name} {op} '{value}'"
    else:
        return QueryOrder.BasicFilter, f"| where * {op} '{value}'"


ignore_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"(?:^is |(?:who|what)\b(?:'s| (?:is|are))?|(?:(?:show me|find|I want to see)))\s+", re.IGNORECASE),
    kql_query_replace=ignore
)

wildcard_search_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"(?:for|of) (?P<tableName>\w+ )?(?P<term>\S+)", re.IGNORECASE),
    kql_query_replace=get_wildcard_search
)

quantifier_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r'(?P<all>all )|top (?P<top>\d+)?|(?:the) (?P<top2>\d+)?(?: ?most| ?highest| )', re.IGNORECASE),
    kql_query_replace=get_limit
)
time_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r'(?:in|of|from)( the)? (?:[lp]ast|previous) (?P<number>\d+ )?(?:(?P<hour>hour)|(?P<day>day)|(?P<week>week)|(?P<month>month))s?',re.IGNORECASE),
    kql_query_replace=get_time
)

user_field_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"(?P<entity>\S+)'s (?P<column>\w+)", re.IGNORECASE),
    kql_query_replace=get_user_details
)

extract_fields_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"(?:with|where) (?:(?P<value>\S+) (?P<column>\S+))|(?:(?P<column2>\S+)(?:that)?(?:is |are )?(?:(?P<bigger>(?:bigger|more|larger) than )(?P<smaller>(?:smaller|less) than ))(?P<value2>\S+))", re.IGNORECASE),
    kql_query_replace=get_field_values
)

count_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"how many |Count ", re.IGNORECASE),
    kql_query_replace=get_count
)

user_field_op2 = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"the (?P<column>\w+) of (?P<entity>\S+)", re.IGNORECASE),
    kql_query_replace=get_user_details
)
user_field_op3 = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"(?P<column>\w+) (?:is|are|do|does) (?P<entity>\S+) (?:in|have)", re.IGNORECASE),
    kql_query_replace=get_user_details
)

risky_search_op = QueryTemplateRegexOperation(
    nl_query_pattern=re.compile(r"\brisky?", re.IGNORECASE),
    kql_query_replace=get_wildcard_search
)


def add_tablename_keywords():
    Table.TABLES['IdentityInfo'].register_keywords(['user', 'owner'])
    Table.TABLES['SecurityIncident'].register_keywords(['incident'])
    Table.TABLES['SecurityAlert'].register_keywords(['alert'])


def infer_table_name(query):
    table_names = list(Table.TABLES.keys()) + list(Table.TABLES_BY_KEYWORD.keys())
    table_likelihood = sorted([(fuzz.partial_ratio(table_name, query), table_name) for table_name in table_names])
    pprint(table_likelihood)
    likelihood, best_match = max(table_likelihood)
    if best_match not in Table.TABLES:
        best_match = Table.TABLES_BY_KEYWORD[best_match]
    return likelihood, best_match


class KQLParser:
    def __init__(self):
        self.init_tables()
        self.pipeline = [
                ignore_op,
                time_op,
                user_field_op,
                user_field_op2,
                user_field_op3,
                wildcard_search_op,
                quantifier_op,
                count_op,
                extract_fields_op
            ]

    def get_table_name(self, query):
        global current_table
        likelihood, table_name = infer_table_name(query)
        if likelihood > FUZZY_MATCH_THRESHOLD:
            current_table = Table.get(table_name)
        else:
            current_table = Table.TABLES['IdentityInfo']

    def init_tables(self):
        for csv in glob.glob('table_schemas/*.csv'):
            name = Path(csv).stem
            schema = pd.read_csv(csv)
            date_field_name = schema[schema.ColumnType == 'datetime'].ColumnName.iloc[0]
            Table(name, date_field_name, schema)
        add_tablename_keywords()

    def convert_to_kql(self, query):
        global query_operators
        self.get_table_name(query)
        query_operators = []
        query_operators.append((QueryOrder.TableName, current_table.name))
        text = query
        for op in self.pipeline:
            text = op.apply(text)
            print('------')
            print(text)
            pprint([op for order, op in sorted(query_operators)])
        kql_query = '\n'.join([op for order, op in sorted(query_operators)])
        return kql_query

# Who is [username] manager
# Show me all ongoing high severity incidents
# I want to see all anomalies from the past week for [username]

if __name__ == "__main__":
    kql_parser = KQLParser()
    query = "Who is the manager of Harry"
    query = "Who is the Harry's manager"
    query = "Who are the most risky users"
    query = "What department is the users with domain username@domain.com in"
    print(kql_parser.convert_to_kql(query))

