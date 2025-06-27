import argparse
from analyzer.parser import extract_ast, find_cmdlets
from analyzer.indicators import analyze_commands
from analyzer.reporter import generate_json_report, generate_html_report

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='ps-analyzer')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()

    with open(args.input) as f:
        text = f.read()
    ast = extract_ast(text)
    cmds = find_cmdlets(ast)
    findings = analyze_commands([{'raw': text}] + [{'name': c['name']} for c in cmds])

    if args.output.endswith('.json'):
        generate_json_report(findings, args.output)
    else:
        generate_html_report(findings, args.output)
