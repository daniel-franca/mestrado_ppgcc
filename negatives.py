import datetime
import mysql.connector
from collections import defaultdict

# Configuração do banco de dados
mydb = mysql.connector.connect(
    charset="utf8",
    user='cvedb_user',
    password='change_password',
    database='cvedb5',
    host='127.0.0.1'
)
cursor = mydb.cursor(dictionary=True)

# Dicionários para armazenar resultados
version_stats = defaultdict(lambda: {'total': 0, 'negative': 0})
distro_stats = defaultdict(lambda: {'total': 0, 'negative': 0})


# Função para limpar e converter datas
def parse_date(date_str):
    if not date_str:
        return None

    # Tentar formatos conhecidos
    formats = [
        '%Y-%m-%d',  # Formato padrão
        '%Y-%m-%d %H:%M:%S',  # Com hora
        '%d/%m/%Y',  # Formato europeu
        '%m/%d/%Y'  # Formato americano
    ]

    for fmt in formats:
        try:
            return datetime.datetime.strptime(date_str, fmt).date()
        except (ValueError, TypeError):
            continue

    return None  # Se nenhum formato funcionar


# Consultas corrigidas
queries = {
    'debian': {
        'versions': ["bullseye", "bookworm", "sid", "trixie"],
        'sql': "SELECT CVE, Resolved, Published_NIST FROM debian WHERE Distro = %s"
    },
    'redhat': {
        'versions': ["6", "7", "8", "9"],
        'sql': "SELECT DISTINCT CVE, Resolved, Published_NIST FROM redhat WHERE Version LIKE %s"
    },
    'ubuntu': {
        'versions': ["xenial", "bionic", "focal", "jammy"],
        'sql': "SELECT DISTINCT CVE, Resolved, Published_NIST FROM ubuntu WHERE Distro = %s"
    },
    'ubuntupro': {
        'versions': ["xenial", "bionic", "focal", "jammy"],
        'sql': "SELECT DISTINCT CVE, Resolved, Published_NIST FROM ubuntupro WHERE Distro = %s"
    },
    'almalinux': {
        'versions': ["8", "9"],
        'sql': "SELECT DISTINCT CVE, Resolved, Published_NIST FROM almalinux WHERE Version LIKE %s"
    },
    'rockylinux': {
        'versions': ["8", "9"],
        'sql': "SELECT DISTINCT CVE, Resolved, Published_NIST FROM rockylinux WHERE Version LIKE %s"
    }
}

for distro, config in queries.items():
    for version in config['versions']:
        # Preparar parâmetro para a consulta
        param = version
        if distro in ['redhat', 'almalinux', 'rockylinux']:
            param = f"%{version}%"  # Usar padrão LIKE para versões

        cursor.execute(config['sql'], (param,))
        records = cursor.fetchall()

        for record in records:
            # Converter data resolvida
            resolved_date = parse_date(record['Resolved'])
            if not resolved_date:
                resolved_date = datetime.date(2024, 1, 1)  # Fallback

            # Converter data publicação
            nist_date = parse_date(record['Published_NIST'])
            if not nist_date:
                continue  # Ignorar registros sem data de publicação

            # Calcular diferença de dias
            days = (resolved_date - nist_date).days

            # Chaves para estatísticas
            version_key = f"{distro}-{version}"
            distro_key = distro

            # Atualizar estatísticas por versão
            version_stats[version_key]['total'] += 1
            if days < 0:
                version_stats[version_key]['negative'] += 1

            # Atualizar estatísticas por distribuição
            distro_stats[distro_key]['total'] += 1
            if days < 0:
                distro_stats[distro_key]['negative'] += 1

        print(f"Processados {len(records)} registros para {distro}-{version}")


# Função para formatar resultados
def format_results(title, data):
    print(f"\n{title}")
    print("=" * 80)
    print(f"{'Distribuição/Versão':<30} {'Negativos':<10} {'Total':<10} {'% Negativos':<10}")
    print("-" * 80)

    for key, stats in sorted(data.items()):
        if stats['total'] > 0:
            percentage = (stats['negative'] / stats['total']) * 100
            print(f"{key.upper():<30} {stats['negative']:<10} {stats['total']:<10} {percentage:>6.2f}%")
        else:
            print(f"{key.upper():<30} {'0':<10} {'0':<10} {'N/A':>10}")


# Exibir resultados por versão
format_results("ESTATÍSTICAS POR VERSÃO", version_stats)

# Exibir resultados por distribuição
format_results("ESTATÍSTICAS POR DISTRIBUIÇÃO", distro_stats)

# Calcular estatísticas gerais
total_records = sum(stats['total'] for stats in version_stats.values())
total_negatives = sum(stats['negative'] for stats in version_stats.values())
overall_percentage = (total_negatives / total_records) * 100 if total_records > 0 else 0

print("\n" + "=" * 80)
print(f"RESUMO GERAL: {total_negatives}/{total_records} ({overall_percentage:.2f}%) registros com datas negativas")
print("=" * 80)

# Fechar conexão
cursor.close()
mydb.close()
