from pwsh_ast_parser import parse

def extract_ast(script_text):
    tree = parse(script_text)
    return tree

def find_cmdlets(ast_tree):
    # Traverse AST to find CmdletInvocation nodes
    invocations = []
    for node in ast_tree.find_all('CmdletInvocation'):
        invocations.append({'name': node.name, 'args': node.arguments})
    return invocations
