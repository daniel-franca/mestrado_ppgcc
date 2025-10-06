# -*- coding: utf-8 -*-

# 1. Importação de bibliotecas
import pandas as pd
from sqlalchemy import create_engine
import mysql.connector
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import sys
from datetime import datetime

# 2. Configurações de estilo para os gráficos
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['figure.figsize'] = (16, 9)
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 16
plt.rcParams['xtick.labelsize'] = 11
plt.rcParams['ytick.labelsize'] = 11

# 3. --- Conexão com o Banco de Dados ---
db_user = 'cvedb_user'
db_password = 'password'
db_host = '127.0.0.1'
db_name = 'cvedb5'

try:
    engine = create_engine(f'mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}')
    print("Engine SQLAlchemy criada com sucesso.")
    mydb = mysql.connector.connect(
        user=db_user, password=db_password, host=db_host, database=db_name, charset="utf8"
    )
    cursor = mydb.cursor()
    print("Conexão MySQL estabelecida com sucesso.")
except Exception as err:
    print(f"Erro fatal ao conectar ao banco de dados: {err}")
    sys.exit(1)

# --- Funções para Gráficos Anuais ---

def fetch_precalculated_data(table_name: str, db_engine) -> pd.DataFrame:
    query = f"SELECT Distro, Year, Days FROM {table_name} WHERE Days >= 0;"
    print(f"Buscando dados anuais da tabela '{table_name}'...")
    try:
        df = pd.read_sql(query, db_engine)
    except Exception as e: return pd.DataFrame()
    if df.empty: return df
    name_map = {'debian': 'Debian', 'ubuntu': 'Ubuntu', 'ubuntupro': 'Ubuntu Pro', 'redhat': 'Red Hat', 'almalinux': 'AlmaLinux', 'rockylinux': 'Rocky Linux'}
    df['Distro'] = df['Distro'].apply(lambda x: name_map.get(x, x))
    df['Year'] = pd.Categorical(df['Year'], categories=sorted(df['Year'].unique()), ordered=True)
    return df

def generate_final_boxplot(data: pd.DataFrame, title: str, filename: str):
    if data.empty: return
    print(f"Gerando gráfico anual: {title}")
    plt.figure()
    sns.set_palette("Set2")
    ax = sns.boxplot(x='Year', y='Days', hue='Distro', data=data, showfliers=False)
    ax.legend(loc='upper right', frameon=True, fancybox=True, shadow=True, title='Distribuição')
    plt.title(title)
    ax.set_ylabel("Média de Tempo de Resolução (Dias)")
    ax.set_xlabel('')
    
    # Define uma escala fixa para o eixo Y de 0 a 2400 para comparação direta.
    ax.set_ylim(0, 2400)
    # Ajusta os marcadores da grade para a nova escala fixa.
    ax.set_yticks(np.arange(0, 2401, 200)) # Marcadores de 0 a 2400, a cada 200.
    
    ax.yaxis.grid(True, linestyle='--', which='major', color='grey', alpha=.7)
    
    medians = data.groupby(['Year', 'Distro'], observed=True)['Days'].median().to_dict()
    distro_labels = [text.get_text() for text in ax.get_legend().get_texts()]
    year_labels = [tick.get_text() for tick in ax.get_xticklabels()]
    num_distros = len(distro_labels)
    for i, year in enumerate(year_labels):
        for j, distro in enumerate(distro_labels):
            key = (int(year), distro)
            median_val = medians.get(key)
            if median_val is not None and median_val <= 2400: # So adiciona o texto se ele estiver dentro da escala visivel
                group_width = 0.8; box_width = group_width / num_distros
                offset = (j - (num_distros - 1) / 2.) * box_width
                x_pos = i + offset
                ax.text(x_pos, median_val, f'{int(median_val)}', ha='center', va='center', fontweight='bold', color='white', size=10, bbox=dict(facecolor='black', alpha=0.6, boxstyle='round,pad=0.2'))
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    print(f"Gráfico salvo com sucesso como '{filename}'")
    plt.show()

# --- Funções para Gráficos por Versão Agregada e Ano a Ano ---

def fetch_data_for_version_analysis(table_name: str, db_engine) -> pd.DataFrame:
    start_year = datetime.now().year - 5
    query = f"SELECT Distro, Version, Year, Days FROM {table_name} WHERE Days >= 0 AND Year >= {start_year};"
    print(f"Buscando dados por versão da tabela '{table_name}'...")
    try:
        df = pd.read_sql(query, db_engine)
    except Exception as e:
        print(f"ERRO: Não foi possível ler a tabela '{table_name}' ou a coluna 'Version' não existe. Detalhe: {e}")
        return pd.DataFrame()
    if df.empty: return df
    name_map = {'debian': 'Debian', 'ubuntu': 'Ubuntu', 'ubuntupro': 'Ubuntu Pro', 'redhat': 'Red Hat', 'almalinux': 'AlmaLinux', 'rockylinux': 'Rocky Linux'}
    df['Distro_Fmt'] = df['Distro'].apply(lambda x: name_map.get(x, x))
    df['Distro-Version'] = df['Distro_Fmt'] + '-' + df['Version'].astype(str)
    return df

def generate_version_boxplot(data: pd.DataFrame, title: str, filename: str):
    if data.empty: return
    data = data.sort_values(by=['Distro_Fmt', 'Version'])
    print(f"Gerando gráfico por versão agregada: {title}")
    plt.figure()
    sns.set_palette("tab10")
    ax = sns.boxplot(x='Distro-Version', y='Days', data=data, showfliers=False)
    plt.title(title)
    ax.set_ylabel("Média de Tempo de Resolução (Dias)")
    ax.set_xlabel("Versão da Distribuição")
    plt.xticks(rotation=45, ha='right')
    y_min, y_max = ax.get_ylim()
    ax.set_yticks(np.arange(0, y_max + 200, 200))
    ax.yaxis.grid(True, linestyle='--', which='major', color='grey', alpha=.7)
    medians = data.groupby('Distro-Version', observed=True)['Days'].median()
    for tick, label in enumerate(ax.get_xticklabels()):
        version_name = label.get_text()
        if version_name in medians:
            median_val = medians[version_name]
            ax.text(tick, median_val, f'{int(median_val)}', ha='center', va='center', fontweight='bold', color='white', size=10, bbox=dict(facecolor='black', alpha=0.6, boxstyle='round,pad=0.2'))
    plt.tight_layout()
    plt.savefig(filename, dpi=300)
    print(f"Gráfico salvo com sucesso como '{filename}'")
    plt.show()

def generate_version_yearly_subplots(data: pd.DataFrame, title: str, filename: str):
    if data.empty: return
    print(f"Gerando gráfico por versão (ano a ano): {title}")
    data['Year'] = pd.Categorical(data['Year'], categories=sorted(data['Year'].unique()), ordered=True)
    g = sns.FacetGrid(data, col="Distro_Fmt", col_wrap=3, height=6, aspect=1.2, sharey=True, sharex=False)
    g.map_dataframe(sns.boxplot, x="Version", y="Days", hue="Year", showfliers=False, palette="viridis")
    g.set(ylim=(0, 2600))
    g.set_titles("Distribuição: {col_name}", size=14)
    g.set_axis_labels("Versão", "Média de Tempo de Resolução (Dias)")
    for ax in g.axes.flat:
        ax.yaxis.grid(True, linestyle='--', which='major', color='grey', alpha=.7)
        if ax.get_xticklabels():
             plt.setp(ax.get_xticklabels(), rotation=45, ha='right')
    g.add_legend(title="Ano")
    plt.suptitle(title, y=1.02, size=18)
    g.tight_layout()
    plt.savefig(filename, dpi=300)
    print(f"Gráfico salvo com sucesso como '{filename}'")
    plt.show()

# --- Função Principal ---

def check_table_exists(table_name: str) -> bool:
    cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
    return cursor.fetchone() is not None

def main():
    geral_table_name = 'results'
    comum_table_name = 'pacotescomum'
    
    print("\n" + "#"*25 + " INICIANDO GRÁFICOS ANUAIS " + "#"*26)
    if check_table_exists(geral_table_name):
        geral_data_anual = fetch_precalculated_data(geral_table_name, engine)
        generate_final_boxplot(geral_data_anual, "Tempo de Resolução por Ano (Geral)", "1_boxplot_anual_geral.png")
    if check_table_exists(comum_table_name):
        comum_data_anual = fetch_precalculated_data(comum_table_name, engine)
        generate_final_boxplot(comum_data_anual, "Tempo de Resolução por Ano (Pacotes Comuns)", "2_boxplot_anual_pacotes_comuns.png")

    print("\n" + "#"*20 + " INICIANDO GRÁFICOS POR VERSÃO DA DISTRIBUIÇÃO " + "#"*20)
    if check_table_exists(geral_table_name):
        geral_data_v = fetch_data_for_version_analysis(geral_table_name, engine)
        generate_version_boxplot(geral_data_v, "Tempo de Resolução por Versão - Agregado (Geral)", "3_boxplot_versao_agregado_geral.png")
        generate_version_yearly_subplots(geral_data_v, "Análise Anual por Versão da Distribuição (Geral)", "4_boxplot_versao_ano_a_ano_geral.png")
    
    if check_table_exists(comum_table_name):
        comum_data_v = fetch_data_for_version_analysis(comum_table_name, engine)
        generate_version_boxplot(comum_data_v, "Tempo de Resolução por Versão - Agregado (Pacotes Comuns)", "5_boxplot_versao_agregado_pacotes_comuns.png")
        generate_version_yearly_subplots(comum_data_v, "Análise Anual por Versão da Distribuição (Pacotes Comuns)", "6_boxplot_versao_ano_a_ano_pacotes_comuns.png")

    cursor.close()
    mydb.close()
    print("\nAnálise completa.")

if __name__ == "__main__":
    main()

