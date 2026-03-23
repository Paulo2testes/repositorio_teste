import json

with open('output_formatted.sarif', 'r') as f:
    sarif = json.load(f)

# Mapeamento de texto para Score numérico (padrão GitHub)
# 9.0+ = Critical | 7.0+ = High | 4.0+ = Medium | 0-3.9 = Low
sev_to_score = {
    'ERROR': '8.5',     # Mapeia ERROR para High
    'WARNING': '5.5',   # Mapeia WARNING para Medium
    'NOTE': '2.5',      # Mapeia NOTE para Low
    'NONE': '0.0'
}

for run in sarif.get('runs', []):
    rules = run.get('tool', {}).get('driver', {}).get('rules', [])
    
    for rule in rules:
        # 1. Lemos o que você apontou: o level padrão da regra
        default_level = rule.get('defaultConfiguration', {}).get('level').upper()
        
        # 2. Verificamos se o Semgrep injetou algo mais específico no precision
        # No seu arquivo, ele usa "very-high" etc, mas o 'level' é mais constante
        precision = rule.get('properties', {}).get('precision').upper()
        
        # 3. Lógica de decisão de Score
        # Se for um erro de SQL Injection (como no seu JSON), o level será ERROR -> 8.5
        score = sev_to_score.get(default_level)
        
        # 4. A Mágica: Injetamos o campo que o GitHub realmente usa para a aba Security
        if 'properties' not in rule:
            rule['properties'] = {}
        rule['properties']['security-severity'] = score


with open('output_formatted.sarif', 'w') as f:
    json.dump(sarif, f, indent=2)