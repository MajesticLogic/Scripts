import json
from bs4 import BeautifulSoup

def generate_json_report(findings, output_path):
    with open(output_path, 'w') as f:
        json.dump({'findings': findings}, f, indent=2)

def generate_html_report(findings, output_path):
    html = BeautifulSoup('<html><body><h1>Analysis Report</h1><ul></ul></body></html>', 'html.parser')
    ul = html.find('ul')
    for f in findings:
        li = html.new_tag('li')
        li.string = f"[{f.get('type')}/{f.get('level', '')}] {f['match']}"
        ul.append(li)
    with open(output_path, 'w') as out:
        out.write(str(html.prettify()))
