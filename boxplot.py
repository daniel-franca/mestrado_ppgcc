import datetime
import mysql.connector
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

# Configurações de estilo
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['xtick.labelsize'] = 10
plt.rcParams['ytick.labelsize'] = 10
sns.set_palette("colorblind")


# Função para converter datas em diferentes formatos
def parse_date(date_str):
    if not date_str or not isinstance(date_str, str):
        return None

    try:
        # Tentar formato ISO com 'T'
        if 'T' in date_str:
            return datetime.datetime.fromisoformat(date_str).date()

        # Tentar formato com timestamp
        elif ' ' in date_str and ':' in date_str:
            return datetime.datetime.strptime(date_str, '%Y-%m-%d %H:%M:%S').date()

        # Formato simples de data
        else:
            return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()

    except ValueError:
        # Extrair apenas a parte da data usando regex
        match = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
        if match:
            return datetime.datetime.strptime(match.group(1), '%Y-%m-%d').date()
        return None
    except Exception as e:
        print(f"Erro ao converter data '{date_str}': {str(e)}")
        return None


# MySQL Connection
def connect_db():
    return mysql.connector.connect(
        charset="utf8",
        user='user',
        password='change_password',
        database='cvedb5',
        host='127.0.0.1',
        pool_name='mypool',
        pool_size=5
    )


# Coletar todos os dados de uma vez
def fetch_all_data(cursor):
    print("Otimizando: buscando todos os dados em lote...")

    # Buscar todos os dados necessários em consultas únicas
    queries = {
        'debian': "SELECT CVE, Resolved, Published_NIST, Status, Distro FROM debian",
        'redhat': "SELECT DISTINCT CVE, Resolved, Published_NIST, FixState, Version FROM redhat",
        'ubuntu': "SELECT DISTINCT CVE, Resolved, Published_NIST, Status, Distro FROM ubuntu",
        'ubuntupro': "SELECT DISTINCT CVE, Resolved, Published_NIST, Status, Distro FROM ubuntupro",
        'almalinux': "SELECT DISTINCT CVE, Resolved, Published_NIST, Version FROM almalinux",
        'rockylinux': "SELECT DISTINCT CVE, Resolved, Published_NIST, Version FROM rockylinux"
    }

    all_data = {}

    for distro, query in queries.items():
        print(f"Buscando dados para {distro}...")
        cursor.execute(query)
        results = cursor.fetchall()
        all_data[distro] = results
        print(f"  {len(results)} registros encontrados para {distro}")

    return all_data


# Buscar todas as datas mínimas de uma vez
def fetch_all_mindates(cursor):
    print("Buscando todas as datas mínimas...")
    start_time = time.time()
    cursor.execute("SELECT cve, MinDate FROM cvemindate")
    results = cursor.fetchall()
    mindate_dict = {cve: mindate for cve, mindate in results}
    print(f"  {len(mindate_dict)} datas encontradas em {time.time() - start_time:.2f} segundos")
    return mindate_dict


# Processar dados para uma distribuição específica
def process_distro_data(distro, version_data, mindate_dict, progress_bar=None):
    results = []
    version = version_data[0]
    records = version_data[1]

    # Debugging print for process_distro_data
    # print(f"Processing {len(records)} records for {distro} version {version}")

    for x in records:
        cve = str(x[0])
        resolved_str = x[1]
        pub_date_str = x[2]

        # Tratamento especial para distribuições sem status
        status = None
        if distro in ['debian', 'ubuntu', 'ubuntupro', 'redhat']:
            status = x[3] if len(x) > 3 else None
        
        try:
            # Processar data de resolução
            resolved = parse_date(resolved_str) if resolved_str else None

            # Processar ano de publicação
            year = None
            if pub_date_str:
                # Limpar string de data
                clean_pub_date = str(pub_date_str).replace("[('", "").replace("',)]", "")
                pub_date = parse_date(clean_pub_date)
                year = pub_date.year if pub_date else None

            # Verificar status não resolvido apenas para distribuições com status
            unresolved_statuses = ["Affected", "Fix deferred", "Out of support scope"]
            is_unresolved = False
            if status:
                is_unresolved = (status in unresolved_statuses) or (resolved_str == "CHECK MANUALLY")

            if not resolved or is_unresolved:
                # Se não resolvido ou tem um status de não resolvido, define a data de resolução para uma data futura fixa
                resolved = datetime.date(2024, 1, 1)

            # Obter data mínima do dicionário
            mindate = mindate_dict.get(cve)
            if not mindate:
                # print(f"  Skipping {cve}: MinDate not found in mindate_dict.") # Debugging
                continue # Pula se nenhuma mindate for encontrada

            # Calcular dias de resolução
            days = (resolved - mindate).days
            if days < 0:  # Corrigir datas inconsistentes (resolvido antes de mindate)
                # print(f"  Adjusting negative days for {cve}: {days} -> {abs(days)}") # Debugging
                days = abs(days)

            # Adicionar aos resultados
            results.append({
                'CVE': cve,
                'Year': year,
                'Distro': distro,
                'Version': version,
                'MinDate': mindate,
                'Resolved': resolved,
                'Days': days
            })

        except Exception as e:
            # print(f"Erro processando CVE {cve} for {distro} {version}: {str(e)}")
            pass

        if progress_bar:
            progress_bar.update(1)

    return results


# Gerar boxplots
def generate_boxplots(results_df, output_dir="results/boxplots"):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print("\nGerando visualizações...")

    # Filtrar outliers extremos (top 1%)
    if not results_df.empty:
        upper_limit = results_df['Days'].quantile(0.99)
        filtered_df = results_df[results_df['Days'] <= upper_limit]
        print(f"  Filtrando dados: mantendo 'Days' <= {upper_limit:.2f} (Top 99%)")
    else:
        filtered_df = results_df
        print("Aviso: DataFrame vazio, sem dados para gerar gráficos")
        return

    # 1. Boxplot comparativo entre distribuições
    print("  Gerando boxplot comparativo entre distribuições...")
    if not filtered_df.empty:
        plt.figure(figsize=(14, 8))
        sns.boxplot(
            x='Distro',
            y='Days',
            data=filtered_df,
            showfliers=False,
            showmeans=True,
            meanprops={'marker': 'o', 'markerfacecolor': 'white', 'markeredgecolor': 'black'}
        )

        plt.title('Tempo de Resolução de CVEs por Distribuição Linux', fontsize=16)
        plt.xlabel('Distribuição')
        plt.ylabel('Dias para Resolução')
        plt.xticks(rotation=15)
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, 'distro_comparison.png'), dpi=300)
        plt.close()
        print("    'distro_comparison.png' salvo.")
    else:
        print("Aviso: Sem dados para gráfico de distribuições")

    # 2. Boxplot comparativo por versão dentro de cada distribuição
    print("  Gerando boxplots comparativos por versão por distribuição...")
    for distro in filtered_df['Distro'].unique():
        distro_data = filtered_df[filtered_df['Distro'] == distro]

        if not distro_data.empty:
            plt.figure(figsize=(12, 7))
            sns.boxplot(
                x='Version',
                y='Days',
                data=distro_data,
                order=sorted(distro_data['Version'].unique()),
                showfliers=False,
                showmeans=True,
                meanprops={'marker': 'o', 'markerfacecolor': 'white', 'markeredgecolor': 'black'}
            )

            plt.title(f'Tempo de Resolução de CVEs - {distro.capitalize()}', fontsize=15)
            plt.xlabel('Versão')
            plt.ylabel('Dias para Resolução')
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, f'{distro}_version_comparison.png'), dpi=300)
            plt.close()
            print(f"    '{distro}_version_comparison.png' salvo.")
        else:
            print(f"Aviso: Sem dados para {distro} para gerar gráfico de versão.")

    # 3. Boxplot comparativo por ano
    print("  Gerando boxplot comparativo por ano...")
    if 'Year' in filtered_df.columns and not filtered_df.empty:
        # Filtrar anos com dados suficientes (e.g., mais de 10 registros por ano)
        year_counts = filtered_df['Year'].value_counts()
        valid_years = year_counts[year_counts > 10].index
        year_df = filtered_df[filtered_df['Year'].isin(valid_years)].sort_values('Year')

        if not year_df.empty:
            plt.figure(figsize=(16, 9))
            sns.boxplot(
                x='Year',
                y='Days',
                data=year_df,
                showfliers=False,
                showmeans=True,
                meanprops={'marker': 'o', 'markerfacecolor': 'white', 'markeredgecolor': 'black'}
            )

            plt.title('Tempo de Resolução de CVEs por Ano de Publicação', fontsize=16)
            plt.xlabel('Ano de Publicação do CVE')
            plt.ylabel('Dias para Resolução')
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(os.path.join(output_dir, 'year_comparison.png'), dpi=300)
            plt.close()
            print("    'year_comparison.png' salvo.")
        else:
            print("Aviso: Sem dados suficientes para gráfico por ano após filtragem.")
    else:
        print("Aviso: Sem dados de 'Year' ou DataFrame vazio para gráfico por ano.")

    print(f"Boxplots salvos em: {os.path.abspath(output_dir)}")


# Função principal
def main():
    start_time = time.time()

    # Conectar ao banco
    try:
        mydb = connect_db()
        cursor = mydb.cursor()
        print("Conexão com o banco de dados estabelecida com sucesso.")
    except Exception as e:
        print(f"Erro ao conectar ao banco de dados: {str(e)}")
        return

    # Buscar todos os dados em lote
    all_data = fetch_all_data(cursor)

    # Buscar todas as datas mínimas de uma vez
    mindate_dict = fetch_all_mindates(cursor)

    # Fechar conexão com o banco
    cursor.close()
    mydb.close()

    # Organizar dados por distribuição e versão
    distro_versions = {
        'debian': {
            "bullseye": [],
            "bookworm": [],
            "sid": [],
            "trixie": []
        },
        'redhat': {
            "6": [],
            "7": [],
            "8": [],
            "9": []
        },
        'ubuntu': {
            "xenial": [],
            "bionic": [],
            "focal": [],
            "jammy": []
        },
        'ubuntupro': {
            "xenial": [],
            "bionic": [],
            "focal": [],
            "jammy": []
        },
        'almalinux': {
            "8": [], # Chave para AlmaLinux 8
            "9": []  # Chave para AlmaLinux 9
        },
        'rockylinux': {
            "8": [], # Chave para Rocky Linux 8
            "9": []  # Chave para Rocky Linux 9
        }
    }

    # Agrupar dados por versão
    print("\nAgrupando dados por versão...")
    for distro, records in all_data.items():
        print(f"  Agrupando dados para {distro}...")
        for record in records:
            version = None

            # Determinar a versão com base na estrutura do registro
            if distro in ['debian', 'ubuntu', 'ubuntupro']:
                version = record[4]  # Campo 'Distro' para essas tabelas
            elif distro == 'redhat':
                version_str = record[4] if len(record) > 4 else ""
                # Mais robusto para RHEL, buscando o dígito após "Red Hat Enterprise Linux "
                version_match = re.search(r'Red Hat Enterprise Linux (\d+)', version_str, re.IGNORECASE)
                if version_match:
                    version = version_match.group(1)
                else: # Fallback para outros formatos de RHEL, se houver
                    version_match = re.search(r'(\d+)', version_str)
                    version = version_match.group() if version_match else None
            elif distro in ['almalinux', 'rockylinux']:
                # A versão é o último campo
                raw_version = record[3] if len(record) > 3 and record[3] is not None else None
                if raw_version is not None:
                    version_str_clean = str(raw_version).strip()
                    # Extrai o primeiro grupo de dígitos da string completa (ex: "Rocky Linux 9" -> "9")
                    version_match = re.search(r'(\d+)', version_str_clean)
                    if version_match:
                        version = version_match.group(1) # Pega o '8' ou '9'
                    else:
                        version = None # Não foi possível extrair a versão numérica
                        # print(f"    DEBUG: Não foi possível extrair a versão numérica de '{version_str_clean}' para {distro} CVE {record[0]}")
                # else:
                #    print(f"    DEBUG: raw_version é None para {distro} CVE {record[0]}") # Apenas para depuração


            if version and version in distro_versions.get(distro, {}):
                distro_versions[distro][version].append(record)
            # else: # Descomente para depurar registros pulados
            #     if version:
            #         print(f"    DEBUG: Pulando registro para {distro} com versão inesperada '{version}' (CVE: {record[0]})")
            #     else:
            #         print(f"    DEBUG: Pulando registro para {distro} onde a versão não pôde ser determinada ou é None (CVE: {record[0]})")

    # Debugging: Print counts for each distro/version after grouping
    print("\nContagem de registros por Distro e Versão após agrupamento:")
    for distro, versions_data in distro_versions.items():
        for version, records_list in versions_data.items():
            print(f"  {distro} - {version}: {len(records_list)} registros")
            if distro in ['almalinux', 'rockylinux'] and len(records_list) == 0:
                print(f"    AVISO: NENHUM DADO AGRUPADO para {distro} {version}. Verifique a consulta SQL e a extração da versão.")


    # Calcular total de registros para barra de progresso
    total_records = sum(len(records) for distro in distro_versions.values() for records in distro.values())
    print(f"\nTotal de registros para processar na próxima etapa: {total_records}")

    # Processar dados em paralelo
    all_results = []
    print("\nProcessando dados (usando paralelismo)...")

    try:
        with tqdm(total=total_records, desc="Progresso geral") as pbar:
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = []

                for distro, versions in distro_versions.items():
                    for version, records in versions.items():
                        if records: # Apenas envia se houver registros para esta versão
                            futures.append(
                                executor.submit(
                                    process_distro_data,
                                    distro,
                                    (version, records),
                                    mindate_dict,
                                    pbar
                                )
                            )

                for future in futures:
                    all_results.extend(future.result())
    except Exception as e:
        print(f"Erro durante o processamento paralelo: {str(e)}")

    # Converter para DataFrame
    results_df = pd.DataFrame(all_results)

    if results_df.empty:
        print("Aviso: Nenhum dado foi processado e o DataFrame de resultados está vazio. Verifique os logs de erro e a disponibilidade dos dados.")
        return

    # Gerar estatísticas descritivas
    print("\nEstatísticas descritivas (antes da filtragem de Days < 0):")
    # Verifica se a coluna 'Days' existe e é numérica antes de descrever
    if 'Days' in results_df.columns and pd.api.types.is_numeric_dtype(results_df['Days']):
        print(results_df.groupby(['Distro', 'Version'])['Days'].describe())
    else:
        print("A coluna 'Days' não está presente ou não é numérica no DataFrame.")


    # Filtrar dados inválidos (Days < 0 deve ser tratado durante o processamento, mas como salvaguarda)
    initial_rows = len(results_df)
    results_df = results_df[results_df['Days'] >= 0]
    if len(results_df) < initial_rows:
        print(f"Removidos {initial_rows - len(results_df)} registros com 'Days' negativo.")

    # Gerar boxplots
    generate_boxplots(results_df)

    # Salvar resultados em CSV
    csv_dir = "results"
    if not os.path.exists(csv_dir):
        os.makedirs(csv_dir)

    csv_path = os.path.join(csv_dir, "resolution_days.csv")
    results_df.to_csv(csv_path, index=False)
    print(f"\nDados salvos em: {os.path.abspath(csv_path)}")

    # Estatísticas de tempo
    elapsed_time = time.time() - start_time
    mins, secs = divmod(elapsed_time, 60)
    print(f"\nProcesso concluído em {int(mins)} minutos e {secs:.2f} segundos!")


if __name__ == "__main__":
    main()
