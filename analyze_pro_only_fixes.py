import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

# --- Configurações do Banco de Dados ---
db_user = 'cvedb_user'
db_password = 'password'
db_host = '127.0.0.1'
db_name = 'cvedb5'

def analyze_pro_only_difference(connection):

    try:
        print("Analisando a tabela 'results' para encontrar diferenças...")

        query_pro = "SELECT CVE, Version, Year FROM results WHERE Distro = 'ubuntupro'"
        df_pro = pd.read_sql_query(query_pro, connection)

        query_std = "SELECT CVE, Version, Year FROM results WHERE Distro = 'ubuntu'"
        df_std = pd.read_sql_query(query_std, connection)

        pro_set = set(map(tuple, df_pro.to_numpy()))
        std_set = set(map(tuple, df_std.to_numpy()))

        difference_set = pro_set - std_set
        
        if not difference_set:
            return pd.DataFrame()

        print(f"Diferença encontrada: {len(difference_set)} ocorrências (CVE+Version+Year) corrigidas apenas no Pro.")
        
        df_difference = pd.DataFrame(difference_set, columns=['CVE', 'Version', 'publication_year'])

        cve_version_pairs = list(df_difference[['CVE', 'Version']].itertuples(index=False, name=None))
        
        if not cve_version_pairs:
            return pd.DataFrame()

        print("Buscando a criticidade na tabela 'ubuntu' para os resultados...")
        
        values_str = ", ".join(map(str, cve_version_pairs))
        
        priority_query = f"""
            SELECT CVE, Distro, Priority FROM ubuntu
            WHERE (CVE, Distro) IN ({values_str})
        """
        df_priorities = pd.read_sql_query(priority_query, connection)
        
        df_priorities.rename(columns={'Distro': 'Version'}, inplace=True)
        df_final = pd.merge(df_difference, df_priorities, on=['CVE', 'Version'])
        
        return df_final

    except Exception as err:
        print(f"ERRO ao executar a análise: {err}")
        return None

def print_detailed_summary(df, scenario_name):
    """
    Recebe o DataFrame final e imprime o sumário agrupado por ano e por versão.
    """
    print("\n" + "#"*80)
    print(f"# {scenario_name}")
    print("#"*80)
    
    if df is not None and not df.empty:
        total_occurrences = len(df)
        print(f"\nTotal GERAL de ocorrências (CVE+Version+Year) corrigidas apenas no Pro: {total_occurrences}")

        grouped_by_year = df.groupby('publication_year')
        
        for year, year_group in sorted(grouped_by_year):
            print(f"\n\n{'='*60}")
            print(f"Ano: {year}")
            print(f"{'='*60}")
            
            grouped_by_version = year_group.groupby('Version')
            
            for version, version_group in sorted(grouped_by_version):
                total_for_version = len(version_group)
                
                print(f"\n--- Versão do Ubuntu: {version} ---")
                print(f"Total de ocorrências nesta versão: {total_for_version}\n")
                
                priority_counts = version_group['Priority'].value_counts().reset_index()
                priority_counts.columns = ['Criticidade (Priority)', 'Quantidade']
                
                print(priority_counts.to_string(index=False))
                print("-" * 40)
    elif df is not None:
        print("\nNenhuma vulnerabilidade encontrada que corresponda aos critérios.")
    else:
        print("\nNão foi possível gerar o sumário devido a um erro na consulta.")
    
    print("\n" + "#"*80)

def generate_pivoted_csv_output(df):
    """
    Agrupa, pivota os resultados para o formato "largo" e salva em CSV.
    """
    if df is None or df.empty:
        print("\nNenhum dado para gerar o arquivo CSV.")
        return

    print("\nPreparando dados para a saída pivotada do Excel...")
    try:
        # Passo 1: Agrupar e contar para obter a base para a pivotagem
        summary_df = df.groupby(['publication_year', 'Version', 'Priority']).size().reset_index(name='Total')

        # Passo 2: Pivotar a tabela para o formato "largo"
        pivoted_df = summary_df.pivot_table(
            index=['publication_year', 'Priority'], # Linhas
            columns='Version',                     # Colunas
            values='Total',                        # Valores nas células
            fill_value=0                           # Preenche células vazias com 0
        ).reset_index()

        # Renomeia as colunas para o formato final
        pivoted_df.rename(columns={
            'publication_year': 'Ano',
            'Priority': 'Criticidade'
        }, inplace=True)
        
        # Remove o nome do índice das colunas ('Version') para um cabeçalho mais limpo
        pivoted_df.columns.name = None
        
        output_filename = 'pro_only_fixes_pivoted_summary.csv'
        
        # Salva o DataFrame pivotado em um arquivo CSV
        pivoted_df.to_csv(output_filename, index=False, encoding='utf-8-sig')
        
        print(f"Arquivo '{output_filename}' gerado com sucesso! Você pode abri-lo no Excel.")

    except Exception as e:
        print(f"ERRO ao gerar o arquivo CSV pivotado: {e}")

def main():
    """
    Função principal que gerencia a conexão e orquestra a análise.
    """
    try:
        connection_string = f'mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}'
        engine = create_engine(connection_string)
        
        with engine.connect() as connection:
            print("Conexão via SQLAlchemy Engine estabelecida com sucesso.")
            
            df_summary = analyze_pro_only_difference(connection)
            
            # 1. Imprime o relatório detalhado no console (opcional)
            print_detailed_summary(df_summary, "Sumário Anual por Versão - Vulnerabilidades Corrigidas Apenas no Ubuntu Pro")
            
            # 2. Gera o arquivo CSV formatado para o Excel
            generate_pivoted_csv_output(df_summary)

    except SQLAlchemyError as err:
        print(f"ERRO CRÍTICO de conexão com o banco de dados: {err}")
    except Exception as e:
        print(f"Um erro inesperado ocorreu: {e}")
    finally:
        print("\nProcesso finalizado.")

if __name__ == "__main__":
    main()
