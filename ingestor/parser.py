import ast
import os
import glob

class FunctionVisitor(ast.NodeVisitor):
    def __init__(self, filepath, source_code):
        self.filepath = filepath
        self.source_code = source_code
        self.functions = []

    def visit_FunctionDef(self, node):
        func_name = node.name
        # Get arguments
        args = [arg.arg for arg in node.args.args]
        
        # Get source code segment using ast.get_source_segment
        code = ast.get_source_segment(self.source_code, node)
        
        # Find all function calls inside this function body to understand imports/usage
        calls = [n.func.id for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
        calls += [n.func.attr for n in ast.walk(node) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]

        self.functions.append({
            "file_path": self.filepath,
            "function_name": func_name,
            "arguments": args,
            "code": code,
            "calls": list(set(calls)),
            "line_number": node.lineno
        })
        self.generic_visit(node)

def parse_directory(directory: str):
    """
    Recursively parses all Python files in the given directory.
    Returns a list of extracted functions with metadata.
    """
    parsed_data = []
    
    # Use glob to find all python files
    search_pattern = os.path.join(directory, "**", "*.py")
    files = glob.glob(search_pattern, recursive=True)
    
    for file_path in files:
        with open(file_path, "r", encoding="utf-8") as f:
            source_code = f.read()
            
        try:
            tree = ast.parse(source_code)
            visitor = FunctionVisitor(file_path, source_code)
            visitor.visit(tree)
            parsed_data.extend(visitor.functions)
        except SyntaxError as e:
            print(f"Syntax error parsing {file_path}: {e}")
            
    return parsed_data

if __name__ == "__main__":
    # Test the parser
    data = parse_directory("services")
    for d in data:
        print(f"Found: {d['function_name']} in {d['file_path']}")
