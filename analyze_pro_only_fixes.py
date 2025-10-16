import pandas as pd
from sqlalchemy import create_engine
from sqlalchemy.exc import SQLAlchemyError

# --- Configurações do Banco de Dados ---
# Verifique se a senha está correta.
db_user = 'cvedb_user'
db_password = 'password'
db_host = '127.0.0.1'
db_name = 'cvedb5'

# Busca CVEs para analise de criticidade

def analyze_cves_for_summary(connection, source_table_name):
    try:
        # Passo 1: Obter a lista de CVEs únicas que correspondem ao critério,
        # usando a tabela de origem especificada (results ou pacotescomum).
        print(f"\nIdentificando CVEs únicas para análise a partir da tabela '{source_table_name}'...")
        cves_query = f"""
            SELECT DISTINCT CVE FROM ubuntu
            WHERE Resolved = 'CHECK MANUALLY'
            AND CVE IN (SELECT DISTINCT CVE FROM {source_table_name});
        """
        df_cves = pd.read_sql_query(cves_query, connection)
        
        if df_cves.empty:
            return pd.DataFrame()

        cve_list = df_cves['CVE'].tolist()
        print(f"Encontradas {len(cve_list)} CVEs únicas para este cenário.")

        # Passo 2: Para essa lista de CVEs, buscar todas as suas prioridades na tabela ubuntupro.
        cve_tuple = tuple(cve_list)
        if not cve_tuple:
            return pd.DataFrame()

        priorities_query = f"""
            SELECT CVE, Priority FROM ubuntupro
            WHERE CVE IN {cve_tuple}
        """
        df_all_priorities = pd.read_sql_query(priorities_query, connection)
        
        # Passo 3: Determinar criticidade
        priority_order = pd.CategoricalDtype(
            ['critical', 'high', 'medium', 'low', 'negligible', 'unknown'], 
            ordered=True
        )
        df_all_priorities['Priority'] = df_all_priorities['Priority'].astype(priority_order)
        
        df_highest_priorities = df_all_priorities.loc[df_all_priorities.groupby('CVE')['Priority'].idxmax()]
        
        return df_highest_priorities

    except Exception as err:
        print(f"ERRO ao executar a análise para a tabela '{source_table_name}': {err}")
        return None

def print_summary(df, scenario_title):
    print("\n" + "="*80)
    print(scenario_title)
    print("="*80)
    
    if df is not None and not df.empty:
        total_count = len(df)
        print(f"\nTotal de CVEs ÚNICAS encontradas: {total_count}\n")
        
        priority_counts = df['Priority'].value_counts().reset_index()
        priority_counts.columns = ['Criticidade (Priority)', 'Quantidade']
        
        priority_counts['Percentual'] = (priority_counts['Quantidade'] / total_count) * 100
        priority_counts['Percentual'] = priority_counts['Percentual'].map('{:.2f}%'.format)
        
        print(priority_counts.to_string(index=False))

    elif df is not None:
        print("\nNenhuma vulnerabilidade encontrada que corresponda aos critérios neste cenário.")
    else:
        print("\nNão foi possível gerar o sumário devido a um erro na consulta.")
        
    print("\n" + "="*80)

def main():
    """
    Função principal que gerencia a conexão e orquestra as duas análises.
    """
    try:
        connection_string = f'mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}'
        engine = create_engine(connection_string)
        
        with engine.connect() as connection:
            print("Conexão via SQLAlchemy Engine estabelecida com sucesso.")
            
            # --- Análise 1: Cenário Geral (tabela 'results') ---
            df_summary_results = analyze_cves_for_summary(connection, 'results')
            print_summary(df_summary_results, "Sumário - Geral (análise da tabela 'results')")
            
            # --- Análise 2: Cenário de Pacotes Comuns (tabela 'pacotescomum') ---
            df_summary_common = analyze_cves_for_summary(connection, 'pacotescomum')
            print_summary(df_summary_common, "Sumário - Pacotes Comuns (análise da tabela 'pacotescomum')")

    except SQLAlchemyError as err:
        print(f"ERRO CRÍTICO de conexão com o banco de dados: {err}")
    except Exception as e:
        print(f"Um erro inesperado ocorreu: {e}")
    finally:
        print("\nProcesso finalizado.")

if __name__ == "__main__":
    main()
