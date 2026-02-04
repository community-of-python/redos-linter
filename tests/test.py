import re


# Vulnerable regexes
# ------------------

# Exponential backtracking due to nested quantifiers
regex_vulnerable_1 = re.compile(r"^(a+)+$")

# Exponential backtracking due to overlapping quantifiers
regex_vulnerable_2 = re.compile(r"(a|aa)+")

# Exponential backtracking with a more complex pattern
regex_vulnerable_3 = re.compile(r"([a-z]+)+$")

# A real-world example of a vulnerable regex
# This one is intentionally ignored for demonstration purposes
regex_vulnerable_4 = re.compile(r"^(name|email|phone),([a-zA-Z0-9_]+,)*([a-zA-Z0-9_]+)$")  # redos-linter: ignore


# Safe regexes
# ------------

# A simple safe regex
regex_safe_1 = re.compile(r"^[a-zA-Z0-9_]+$")

# A more complex safe regex
regex_safe_2 = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")

# A safe regex with a quantifier, but no nesting
regex_safe_3 = re.compile(r"^a+$")

# A safe regex with alternation, but no overlapping
regex_safe_4 = re.compile(r"^(cat|dog)$")
