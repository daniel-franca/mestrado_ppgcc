# Importing necessary libraries.
import datetime
import pandas as pd
import mysql.connector
from sqlalchemy import create_engine
import matplotlib.pyplot as plt
import seaborn as sns
import os
from collections import defaultdict
import numpy as np

# Configurações de estilo para gráficos
plt.style.use('default')
plt.rcParams['font.family'] = 'DejaVu Sans'
plt.rcParams['axes.labelsize'] = 12
plt.rcParams['axes.titlesize'] = 14
plt.rcParams['xtick.labelsize'] = 10
plt.rcParams['ytick.labelsize'] = 10
sns.set_palette("colorblind")

# --- Conexão com o Banco de Dados ---
db_user = 'cvedb_user'
db_password = 'password'
db_host = '127.0.0.1'
db_name = 'cvedb5'

# Conexão original para operações do script
try:
    mydb = mysql.connector.connect(
        charset="utf8",
        user=db_user,
        password=db_password,
        database=db_name,
        host=db_host
    )
    cursor = mydb.cursor()
    print("Conexão MySQL estabelecida com sucesso.")
except mysql.connector.Error as err:
    print(f"Erro ao conectar ao MySQL: {err}")
    exit()

# Engine SQLAlchemy para compatibilidade com Pandas
try:
    engine = create_engine(f'mysql+mysqlconnector://{db_user}:{db_password}@{db_host}/{db_name}')
    print("Engine SQLAlchemy criada com sucesso.")
except ImportError:
    print("Driver mysql-connector-python não encontrado. Instale com: pip install mysql-connector-python")
    engine = None

# ===================================================================
# ===== ESTRUTURA DE DADOS COMPLETA =================================
# ===================================================================
def create_stats_structure():
    """Modificado para incluir o detalhamento de status não corrigidos."""
    return defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {
        'negative': 0,
        'error': 0,
        'valid': 0,
        'zero_days': 0,
        'not_fixed_total': 0, # Contador total para consistência
        'not_fixed_detail': defaultdict(int), # Dicionário para status detalhados
        'severities_vendor': defaultdict(lambda: defaultdict(int)),
        'severities_nist': defaultdict(lambda: defaultdict(int)),
        'comparison': defaultdict(lambda: defaultdict(int))
    })))

annual_stats = create_stats_structure()
common_pkg_annual_stats = create_stats_structure()

# ===================================================================
# ===== FUNÇÕES DE INFRAESTRUTURA E HELPERS =========================
# ===================================================================

def recreate_table(table_name):
    """
    Apaga a tabela se ela existir e a recria com a coluna Status, garantindo uma execução limpa.
    """
    try:
        print(f"Recriando tabela '{table_name}'...")
        cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
        cursor.execute(f"""
            CREATE TABLE {table_name} (
                id INT AUTO_INCREMENT PRIMARY KEY,
                CVE VARCHAR(255),
                Year INT,
                Distro VARCHAR(255),
                Version VARCHAR(255),
                NormPackage VARCHAR(255),
                MinDate DATE,
                Resolved DATE,
                Days INT,
                Status VARCHAR(255),
                UNIQUE KEY unique_cve_distro_version_pkg (CVE, Distro, Version, NormPackage),
                INDEX (CVE), INDEX (Distro), INDEX (Year), INDEX(Status)
            )
        """)
        mydb.commit()
        print(f"Tabela '{table_name}' recriada com sucesso.")
    except mysql.connector.Error as err:
        print(f"Erro ao recriar a tabela '{table_name}': {err}")

def get_year_from_date(date_obj):
    try:
        return date_obj.year
    except:
        return datetime.datetime.now().year

def parse_date(date_str):
    if date_str is None or pd.isna(date_str) or date_str == '' or date_str == '[]': return None
    date_str = str(date_str).split(' ')[0]
    try:
        return datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
    except (ValueError, TypeError):
        return None

def get_text_color_for_bg(bg_color):
    """
    Determina se a cor do texto deve ser preta ou branca com base na luminosidade da cor de fundo.
    """
    luminance = (0.299 * bg_color[0] + 0.587 * bg_color[1] + 0.114 * bg_color[2])
    return 'white' if luminance < 0.5 else 'black'

# ===================================================================
# ===== LÓGICA DE PROCESSAMENTO (PARA TABELAS results/pacotescomum) =
# ===================================================================
def process_records(records, distro, version_map, stats_dict, nist_dates, mindate_map):
    if not records: return []
    records_to_insert = []
    
    for x in records:
        cve, resolved_date, status_str, norm_package, vendor_severity, nist_severity, version_long = x
        cve = str(cve)

        published_nist = nist_dates.get(cve)
        if not published_nist: continue

        year = get_year_from_date(published_nist)
        if not (2019 <= year <= 2023): continue

        version = version_map.get(str(version_long).strip(), str(version_long).strip())
        vendor_severity = str(vendor_severity).strip().lower() if vendor_severity else 'n/a'
        nist_severity = str(nist_severity).strip().lower() if nist_severity else 'n/a'
        
        resolved = parse_date(resolved_date)
        mindate = mindate_map.get(cve)

        days = None
        if resolved and mindate:
            days = (resolved - mindate).days

        status_key = 'not_fixed'
        
        unresolved_statuses = [
            "pending", "needed", "deferred", "will not fix", "Affected", 
            "out of support scope", "Fix deferred", "fix deferred", 
            "Out of support scope", "end-of-life", "not yet assigned"
        ]
        
        is_unresolved = resolved is None or (distro not in ["almalinux", "rockylinux"] and str(status_str).strip() in unresolved_statuses)
        
        if not is_unresolved and days is not None:
            if days < 0:
                status_key = 'negative'
                stats_dict[distro][version][year]['negative'] += 1
            elif days == 0:
                status_key = 'zero_days'
                stats_dict[distro][version][year]['zero_days'] += 1
            else:
                status_key = 'valid'
                stats_dict[distro][version][year]['valid'] += 1
        else:
            status_key = 'not_fixed'
            stats_dict[distro][version][year]['not_fixed_total'] += 1
            detailed_status = str(status_str).strip() if str(status_str).strip() else 'unresolved_no_status'
            
            if detailed_status in ['resolved', 'released'] and resolved is None:
                detailed_status = f"{detailed_status} (sem data)"
            
            stats_dict[distro][version][year]['not_fixed_detail'][detailed_status] += 1

        stats_dict[distro][version][year]['severities_vendor'][status_key][vendor_severity] += 1
        stats_dict[distro][version][year]['severities_nist'][status_key][nist_severity] += 1
        stats_dict[distro][version][year]['comparison'][vendor_severity][nist_severity] += 1
        
        records_to_insert.append((cve, year, distro, version, norm_package, mindate, resolved, days, status_key))
            
    return records_to_insert

# ===================================================================
# ===== FUNÇÕES DE ANÁLISE E GERAÇÃO DE RELATÓRIOS ==================
# ===================================================================

def print_total_severity_summary_from_source(distros, distro_configs, common_cves=None, title=""):
    print(f"\n\n{'='*50}\n# {title.upper()} \n{'='*50}")
    cve_filter_clause = ""
    if common_cves:
        if not common_cves:
            print("Nenhuma CVE de pacote comum para analisar.")
            return
        cve_list_str = ",".join([f"'{cve}'" for cve in common_cves])
        cve_filter_clause = f"WHERE distro.CVE IN ({cve_list_str})"

    for distro_name in distros:
        config = distro_configs.get(distro_name)
        if not config: continue
        
        print(f"\n--- ANÁLISE DE SEVERIDADE: {distro_name.upper()} ---")
        try:
            query = f"SELECT distro.CVE, nist.Severity AS nist_severity, distro.{config['prio']} AS distro_severity FROM `{distro_name}` AS distro JOIN nist ON distro.CVE = nist.CVE {cve_filter_clause}"
            df = pd.read_sql(query, engine)
            if df.empty:
                print("Nenhum dado encontrado para esta distribuição com os filtros aplicados.")
                continue
            df['distro_severity'] = df['distro_severity'].str.lower().str.strip().replace('', 'n/a')
            df['nist_severity'] = df['nist_severity'].str.lower().str.strip().replace('', 'n/a')
            df.dropna(subset=['nist_severity', 'distro_severity'], inplace=True)
            if df.empty:
                print("Nenhum dado válido após a limpeza.")
                continue
            nist_counts = df.drop_duplicates(subset=['CVE'])['nist_severity'].value_counts()
            distro_unique_pairs = df[['CVE', 'distro_severity']].drop_duplicates()
            distro_counts = distro_unique_pairs['distro_severity'].value_counts()
            all_severities = sorted(list(set(nist_counts.index) | set(distro_counts.index)))
            summary_df = pd.DataFrame(index=all_severities)
            summary_df.index.name = 'Severidade'
            summary_df['DISTRIBUIÇÃO'] = distro_counts
            summary_df['NIST (NVD)'] = nist_counts
            summary_df.fillna(0, inplace=True)
            summary_df = summary_df.astype(int)
            print(summary_df)
        except Exception as e:
            print(f"Ocorreu um erro ao processar {distro_name}: {e}")

def print_aggregated_severity_summary_for_status(stats_dict, status_key, title):
    print(f"\n\n{'='*50}\n# {title.upper()} \n{'='*50}")
    for distro in sorted(stats_dict.keys()):
        print(f"\n--- {distro.upper()} ---")
        distro_counts = defaultdict(int)
        nist_counts = defaultdict(int)
        for versions in stats_dict[distro].values():
            for years_data in versions.values():
                for sev, count in years_data['severities_vendor'][status_key].items():
                    distro_counts[sev] += count
                for sev, count in years_data['severities_nist'][status_key].items():
                    nist_counts[sev] += count
        if not distro_counts and not nist_counts:
            print("Nenhum dado encontrado para esta análise.")
            continue
        all_severities = sorted(list(set(distro_counts.keys()) | set(nist_counts.keys())))
        summary_df = pd.DataFrame(index=all_severities)
        summary_df.index.name = 'Severidade'
        summary_df['DISTRIBUIÇÃO'] = pd.Series(distro_counts)
        summary_df['NIST (NVD)'] = pd.Series(nist_counts)
        summary_df.fillna(0, inplace=True)
        summary_df = summary_df.astype(int)
        summary_df.loc['Total'] = summary_df.sum()
        print(summary_df)

def generate_severity_bar_charts(stats_dict, scenario_name, output_folder='high_quality_plots_comparison'):
    print(f"\n\n{'='*50}\n# GERANDO GRÁFICOS DE BARRAS DE SEVERIDADE ({scenario_name.upper()}) \n{'='*50}")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    status_map = {
        'valid': {'title': f'Severidade de CVEs Corrigidas (>0 dias) - {scenario_name}', 'filename': f'severidade_corrigidas_{scenario_name.lower()}.png'},
        'zero_days': {'title': f'Severidade de CVEs Corrigidas (Dia Zero) - {scenario_name}', 'filename': f'severidade_dia_zero_{scenario_name.lower()}.png'},
        'not_fixed_total': {'title': f'Severidade de CVEs Não Corrigidas - {scenario_name}', 'filename': f'severidade_nao_corrigidas_{scenario_name.lower()}.png'},
        'negative': {'title': f'Severidade de CVEs com Datas Negativas - {scenario_name}', 'filename': f'severidade_datas_negativas_{scenario_name.lower()}.png'}
    }
    all_distros = sorted(stats_dict.keys())
    for status_key, info in status_map.items():
        plot_data = []
        sev_key = 'not_fixed' if status_key == 'not_fixed_total' else status_key
        for distro in all_distros:
            distro_counts = defaultdict(int)
            for versions in stats_dict[distro].values():
                for years_data in versions.values():
                    for sev, count in years_data['severities_vendor'][sev_key].items():
                        distro_counts[sev] += count
            for sev, count in distro_counts.items():
                plot_data.append({'Distribuição': distro, 'Severidade': sev, 'Contagem': count})
        if not plot_data:
            print(f"\nNenhum dado para gerar gráfico para '{info['title']}'.")
            continue
        df_plot = pd.DataFrame(plot_data)
        pivot_df = df_plot.pivot_table(index='Distribuição', columns='Severidade', values='Contagem', fill_value=0, aggfunc='sum')
        sev_order = [s for s in ['critical', 'high', 'medium', 'low', 'unimportant', 'neglible', 'not yet assigned', 'end-of-life', 'n/a'] if s in pivot_df.columns]
        pivot_df = pivot_df[sev_order]
        ax = pivot_df.plot(kind='barh', stacked=True, figsize=(16, 9), colormap='viridis_r', width=0.8)
        ax.set_title(info['title'], fontsize=18, pad=30)
        ax.set_xlabel('Número de Registros de Vulnerabilidade')
        ax.set_ylabel('Distribuição')
        ax.invert_yaxis()
        ax.legend(title='Severidade', loc='upper center', bbox_to_anchor=(0.5, 1.08), ncol=len(pivot_df.columns), frameon=False)
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        total_width = pivot_df.sum(axis=1)
        for i, container in enumerate(ax.containers):
            colors = [get_text_color_for_bg(c.get_facecolor()) for c in container]
            texts = ax.bar_label(container, label_type='center', color='white', weight='bold', fontsize=9)
            for j, (patch, text_obj) in enumerate(zip(container.patches, texts)):
                width = patch.get_width()
                if total_width.iloc[j] > 0 and width / total_width.iloc[j] < 0.02:
                    text_obj.set_text('')
                else:
                    text_obj.set_text(f'{int(width)}')
                    text_obj.set_color(colors[j])
        plt.savefig(f"{output_folder}/{info['filename']}", dpi=300)
        plt.close()
        print(f"\nGráfico de barras salvo: {output_folder}/{info['filename']}")

def analyze_and_print_redhat_comparison(output_folder='high_quality_plots_comparison'):
    print(f"\n\n{'='*25}\n ANÁLISE COMPARATIVA DE CORREÇÕES VS. RED HAT (POR VERSÃO) \n{'='*25}")
    if not engine:
        print("A engine SQLAlchemy não está disponível. A saltar a análise.")
        return
    try:
        all_version_stats = []
        alma_combined_delays = []
        rocky_combined_delays = []
        versions_to_compare = ['8', '9']
        for version in versions_to_compare:
            print(f"\n\n--- A INICIAR COMPARAÇÃO PARA A VERSÃO {version} ---")
            rh_version_name = f"Red Hat Enterprise Linux {version}"
            alma_version_name = f"AlmaLinux {version}"
            rocky_version_name = f"Rocky Linux {version}"
            rh_df = pd.read_sql(f"SELECT CVE, MIN(Resolved) as ResolvedDate FROM redhat WHERE Resolved IS NOT NULL AND Version = '{rh_version_name}' GROUP BY CVE", engine)
            rh_dates = {row['CVE']: pd.to_datetime(row['ResolvedDate']).date() for _, row in rh_df.iterrows()}
            alma_df = pd.read_sql(f"SELECT CVE, MIN(Resolved) as ResolvedDate FROM almalinux WHERE Resolved IS NOT NULL AND Version = '{alma_version_name}' GROUP BY CVE", engine)
            alma_dates = {row['CVE']: pd.to_datetime(row['ResolvedDate']).date() for _, row in alma_df.iterrows()}
            rocky_df = pd.read_sql(f"SELECT CVE, MIN(Resolved) as ResolvedDate FROM rockylinux WHERE Resolved IS NOT NULL AND Version = '{rocky_version_name}' GROUP BY CVE", engine)
            rocky_dates = {row['CVE']: pd.to_datetime(row['ResolvedDate']).date() for _, row in rocky_df.iterrows()}
            print(f"\n--- Comparação: {alma_version_name} vs. {rh_version_name} ---")
            alma_stats, alma_delays = analyze_distro_vs_redhat_by_cve(f'AlmaLinux {version}', alma_dates, rh_dates)
            all_version_stats.append({'distro': f'AlmaLinux {version}', 'stats': alma_stats})
            alma_combined_delays.extend(alma_delays)
            print(f"\n--- Comparação: {rocky_version_name} vs. {rh_version_name} ---")
            rocky_stats, rocky_delays = analyze_distro_vs_redhat_by_cve(f'Rocky Linux {version}', rocky_dates, rh_dates)
            all_version_stats.append({'distro': f'Rocky Linux {version}', 'stats': rocky_stats})
            rocky_combined_delays.extend(rocky_delays)
        if not os.path.exists(output_folder): os.makedirs(output_folder)
        print(f"\n--- A gerar gráficos comparativos na pasta '{output_folder}' ---")
        generate_comparison_plots(all_version_stats, alma_combined_delays, rocky_combined_delays, output_folder)
    except Exception as e:
        print(f"Ocorreu um erro durante a análise comparativa por versão: {e}")

def analyze_distro_vs_redhat_by_cve(distro_name, distro_dates, rh_dates):
    stats = {'same_day': 0, 'before_rh': 0, 'after_rh': 0, 'only_in_distro': 0, 'only_in_rh': 0}
    all_delays = []
    distro_cves = set(distro_dates.keys())
    rh_cves = set(rh_dates.keys())
    for cve, distro_date in distro_dates.items():
        if cve in rh_dates:
            rh_date = rh_dates[cve]
            delay = (distro_date - rh_date).days
            all_delays.append(delay)
            if delay == 0: stats['same_day'] += 1
            elif delay < 0: stats['before_rh'] += 1
            else: stats['after_rh'] += 1
        else:
            stats['only_in_distro'] += 1
    stats['only_in_rh'] = len(rh_cves - distro_cves)
    total_compared_distro = len(distro_cves)
    if total_compared_distro > 0:
        p_same = (stats['same_day'] / total_compared_distro) * 100
        p_before = (stats['before_rh'] / total_compared_distro) * 100
        p_after = (stats['after_rh'] / total_compared_distro) * 100
        p_only_distro = (stats['only_in_distro'] / total_compared_distro) * 100
        print(f"Total de CVEs únicas corrigidas em {distro_name}: {total_compared_distro}")
        print(f"  - Igual ao Red Hat:       {stats['same_day']:>5} ({p_same:.2f}%)")
        print(f"  - Antes do Red Hat:       {stats['before_rh']:>5} ({p_before:.2f}%)")
        print(f"  - Depois do Red Hat:      {stats['after_rh']:>5} ({p_after:.2f}%)")
        print(f"  - Red Hat Não Corrigiu:   {stats['only_in_distro']:>5} ({p_only_distro:.2f}%)")
        print(f"\n  - Apenas o Red Hat corrigiu (e {distro_name} não): {stats['only_in_rh']}")
    return stats, all_delays

def generate_comparison_plots(all_version_stats, alma_delays, rocky_delays, output_folder):
    bar_labels_map = {'same_day': 'Igual ao Red Hat', 'before_rh': 'Antes do Red Hat', 
                      'after_rh': 'Depois do Red Hat', 'only_in_distro': 'Red Hat Não Corrigiu', 
                      'only_in_rh': 'Apenas o Red Hat Corrigiu'}
    plot_data_list = []
    for item in all_version_stats:
        distro_name = item['distro']
        for stat_key, stat_value in item['stats'].items():
            plot_data_list.append({'Categoria': bar_labels_map[stat_key], 'Quantidade': stat_value, 'Distribuição': distro_name})
    plot_data = pd.DataFrame(plot_data_list)
    plt.figure(figsize=(14, 8))
    ax = sns.barplot(x='Categoria', y='Quantidade', hue='Distribuição', data=plot_data, palette='viridis')
    ax.set_title('Comparação de Correções vs. Red Hat (por Versão)', fontsize=16, pad=30)
    ax.set_ylabel('Quantidade de CVEs')
    ax.set_xlabel('')
    ax.legend(title='Distribuição', loc='upper center', bbox_to_anchor=(0.5, 1.08), ncol=len(plot_data['Distribuição'].unique()), frameon=False)
    plt.xticks(rotation=15, ha='right')
    for container in ax.containers:
        ax.bar_label(container, fmt='%d', padding=3, fontsize=9)
    plt.tight_layout(rect=[0, 0, 1, 0.95])
    plt.savefig(f'{output_folder}/grouped_barchart_summary_by_version.png', dpi=300)
    plt.close()
    print("  - Gráfico de barras por versão salvo.")
    for distro_name, delays, color in [('AlmaLinux', alma_delays, 'teal'), ('Rocky Linux', rocky_delays, 'indigo')]:
        if delays:
            fig, ax = plt.subplots(figsize=(12, 7))
            delays_series = pd.Series(delays)
            bins = np.histogram_bin_edges(delays_series, bins=50) 
            sns.histplot(delays_series[delays_series < 0], bins=bins, color='green', ax=ax, label='Antes do Red Hat')
            sns.histplot(delays_series[delays_series >= 0], bins=bins, color=color, ax=ax, label=f'Depois do Red Hat ({distro_name})')
            mean_delay = delays_series.mean()
            ax.axvline(0, color='black', linestyle='-', linewidth=2, zorder=4) 
            ax.axvline(mean_delay, color='red', linestyle='-', linewidth=2, zorder=5)
            legend_text = (f"Eixo X: Diferença de dias ({distro_name} - Red Hat)\n"
                           f"Verde: Corrigido ANTES do Red Hat\n"
                           f"{color.capitalize()}: Corrigido NO DIA ou DEPOIS\n"
                           f"Eixo Y: Frequência (Nº de CVEs)")
            ax.text(0.97, 0.97, legend_text, transform=ax.transAxes, fontsize=10,
                    verticalalignment='top', horizontalalignment='right', 
                    bbox=dict(boxstyle='round,pad=0.5', fc='wheat', alpha=0.8))
            ax.text(0.97, 0.82, f'Diferença Média: {mean_delay:.2f} dias', color='red',
                    transform=ax.transAxes, fontsize=12, verticalalignment='top', 
                    horizontalalignment='right', weight='bold')
            ax.set_xlabel('Diferença de Dias na Correção (Negativo = Mais Rápido que Red Hat)')
            ax.set_ylabel('Frequência (Nº de CVEs)')
            ax.set_title(f'Histograma da Diferença de Dias: {distro_name} vs. Red Hat')
            ax.yaxis.tick_right()
            ax.yaxis.set_label_position("right")
            plt.tight_layout()
            plt.savefig(f'{output_folder}/histogram_alldelays_{distro_name.lower().replace(" ", "_")}.png', dpi=300)
            plt.close()
            print(f"  - Histograma ajustado de diferença de dias para '{distro_name}' salvo.")
            print(f"\n--- Análise Textual do Histograma: {distro_name} ---")
            print(f"  Total de CVEs Comparadas: {len(delays_series)}")
            print(delays_series.describe().round(2).to_string())


def print_status_summary(stats_dict, title):
    print(f"\n\n{'='*25}\n {title.upper()} \n{'='*25}")
    summary_data = defaultdict(lambda: defaultdict(int))
    for distro, versions in stats_dict.items():
        for years in versions.values():
            for data in years.values():
                summary_data[distro]['valid'] += data['valid']
                summary_data[distro]['not_fixed_total'] += data['not_fixed_total']
                summary_data[distro]['negative'] += data['negative']
                summary_data[distro]['zero_days'] += data['zero_days']
    print(f"\n| {'Distribuição':<12} | {'Corrigidas (>0 dias)':<20} | {'Corrigidas (Dia Zero)':<22} | {'Não Corrigidas':<15} | {'Datas Negativas':<16} | {'Total Processado':<17} |")
    print(f"|{'-'*14}|{'-'*22}|{'-'*24}|{'-'*17}|{'-'*18}|{'-'*19}|")
    for distro, data in sorted(summary_data.items()):
        total_processed = sum(data.values())
        if total_processed == 0: continue
        p_corrected = (data['valid'] / total_processed) * 100 if total_processed > 0 else 0
        p_zero_day = (data['zero_days'] / total_processed) * 100 if total_processed > 0 else 0
        p_not_fixed = (data['not_fixed_total'] / total_processed) * 100 if total_processed > 0 else 0
        p_negative = (data['negative'] / total_processed) * 100 if total_processed > 0 else 0
        print(f"| {distro:<12} | {data['valid']:<7} ({p_corrected:4.1f}%) | {data['zero_days']:<7} ({p_zero_day:4.1f}%)      | {data['not_fixed_total']:<7} ({p_not_fixed:4.1f}%) | {data['negative']:<7} ({p_negative:4.1f}%)   | {total_processed:<17} |")

def find_and_process_common_packages(nist_dates, mindate_map, distro_configs_main, version_prefixes):
    print("\n\n" + "="*50 + "\nINICIANDO ANÁLISE DE PACOTES COMUNS ENTRE RPM E DEB\n" + "="*50)
    rpm_distros = ['almalinux', 'rockylinux', 'redhat']
    deb_distros = ['debian', 'ubuntu', 'ubuntupro']
    
    try:
        print("\nPasso 1: Encontrando CVEs comuns...")
        rpm_cve_query = " UNION ".join([f"SELECT DISTINCT CVE FROM `{d}`" for d in rpm_distros])
        deb_cve_query = " UNION ".join([f"SELECT DISTINCT CVE FROM `{d}`" for d in deb_distros])
        common_cve_query = f"SELECT rpm.CVE FROM ({rpm_cve_query}) as rpm INNER JOIN ({deb_cve_query}) as deb ON rpm.CVE = deb.CVE"
        cursor.execute(common_cve_query)
        common_cves = [item[0] for item in cursor.fetchall()]

        if not common_cves:
            print("Nenhuma CVE em comum encontrada.")
            return []
        print(f"Encontradas {len(common_cves)} CVEs em comum.")

        print("\nPasso 2: Coletando pacotes (NormPackage) associados...")
        cve_placeholders = ','.join(['%s'] * len(common_cves))
        package_query = " UNION ".join([f"SELECT DISTINCT NormPackage FROM `{d}` WHERE CVE IN ({cve_placeholders})" for d in rpm_distros + deb_distros])
        cursor.execute(package_query, common_cves * len(rpm_distros + deb_distros))
        common_packages = [item[0] for item in cursor.fetchall() if item[0]]

        if not common_packages:
            print("Nenhum pacote em comum encontrado.")
            return common_cves
        print(f"Encontrados {len(common_packages)} pacotes únicos para análise.")

        print("\nPasso 3: Processando registos para os pacotes comuns...")
        pkg_placeholders = ','.join(['%s'] * len(common_packages))
        
        all_records_to_insert = []

        for distro, config in distro_configs_main.items():
            version_filters = config['versions']
            version_map = {v: v.replace(version_prefixes.get(distro, ''), '') for v in version_filters}
            
            placeholders = ','.join(['%s'] * len(version_filters))

            status_selection = f"'{'not-affected'}'"
            if config['status_col']:
                status_selection = config['status_col']
            
            sql_common = (f"SELECT CVE, Resolved, {status_selection} as status, NormPackage, {config['prio']}, {config['nist_sev_col']}, {config['col']} "
                          f"FROM `{distro}` WHERE {config['col']} IN ({placeholders}) AND NormPackage IN ({pkg_placeholders})")
            
            params = version_filters + common_packages
            try:
                cursor.execute(sql_common, params)
                records = cursor.fetchall()
                print(f"  -> Encontrados {len(records)} registos de pacotes comuns para {distro}.")
            except mysql.connector.Error as err:
                print(f"!!! ERRO ao executar consulta de pacotes comuns para {distro}: {err}")
                records = []

            if records:
                records_to_insert_distro = process_records(records, distro, version_map, common_pkg_annual_stats, nist_dates, mindate_map)
                if records_to_insert_distro:
                    all_records_to_insert.extend(records_to_insert_distro)

        if all_records_to_insert:
            print(f"Inserindo {len(all_records_to_insert)} registos na tabela 'pacotescomum'...")
            sql_insert = ("INSERT INTO pacotescomum (CVE, Year, Distro, Version, NormPackage, MinDate, Resolved, Days, Status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                          "ON DUPLICATE KEY UPDATE Days=VALUES(Days), Resolved=VALUES(Resolved), Status=VALUES(Status)")
            cursor.executemany(sql_insert, all_records_to_insert)
            mydb.commit()
            print("Inserção em lote concluída.")

        return common_cves

    except mysql.connector.Error as err:
        print(f"ERRO DE BANCO DE DADOS durante a análise de pacotes comuns: {err}")
        return []

def print_summary_cve_counts(common_cves_list, distro_configs_main):
    print("\n\n" + "#"*50 + "\n# SUMÁRIO GERAL DE CONTAGEM DE CVEs\n" + "#"*50)
    print("\n--- Total de CVEs únicos por Distribuição (Geral) ---")
    for distro_name in distro_configs_main.keys():
        try:
            cursor.execute(f"SELECT COUNT(DISTINCT CVE) FROM `{distro_name}`")
            print(f"  {distro_name.upper():<10}: {cursor.fetchone()[0]} CVEs")
        except mysql.connector.Error as err:
            print(f"  Erro ao contar CVEs para {distro_name}: {err}")
    print("\n--- Total de CVEs em comum por Distribuição (Geral) ---")
    if not common_cves_list:
        print("  Nenhuma CVE em comum foi encontrada para a análise.")
        return
    cve_placeholders = ','.join(['%s'] * len(common_cves_list))
    for distro_name in distro_configs_main.keys():
        try:
            sql = f"SELECT COUNT(DISTINCT CVE) FROM `{distro_name}` WHERE CVE IN ({cve_placeholders})"
            cursor.execute(sql, common_cves_list)
            print(f"  {distro_name.upper():<10}: {cursor.fetchone()[0]} CVEs")
        except mysql.connector.Error as err:
            print(f"  Erro ao contar CVEs em comum para {distro_name}: {err}")

def print_yearly_cve_counts(common_cves_list, distro_configs_main):
    print("\n\n" + "#"*50 + "\n# SUMÁRIO ANUAL DE CONTAGEM DE CVEs (A PARTIR DE 2019)\n" + "#"*50)
    print("\n--- Total de CVEs únicos por Distribuição (Ano a Ano, baseado na data do NIST) ---")
    for distro_name in distro_configs_main.keys():
        print(f"\n  Distribuição: {distro_name.upper()}")
        try:
            sql = f"""
                SELECT YEAR(nist.Published), COUNT(DISTINCT distro.CVE)
                FROM `{distro_name}` as distro
                JOIN nist ON distro.CVE = nist.CVE
                WHERE YEAR(nist.Published) BETWEEN 2019 AND 2023
                GROUP BY YEAR(nist.Published)
                ORDER BY YEAR(nist.Published) DESC
            """
            cursor.execute(sql)
            results = cursor.fetchall()
            if not results: print("    Nenhum dado encontrado para os anos entre 2019-2023.")
            else:
                for year, count in results: print(f"    Ano {year}: {count} CVEs")
        except mysql.connector.Error as err:
            print(f"    Erro ao contar CVEs para {distro_name}: {err}")

    print("\n\n--- Total de CVEs em comum por Distribuição (Ano a Ano, baseado na data do NIST) ---")
    if not common_cves_list:
        print("  Nenhuma CVE em comum foi encontrada para a análise.")
        return
        
    cve_placeholders = ','.join(['%s'] * len(common_cves_list))
    for distro_name in distro_configs_main.keys():
        print(f"\n  Distribuição: {distro_name.upper()}")
        try:
            sql = f"""
                SELECT YEAR(nist.Published), COUNT(DISTINCT distro.CVE)
                FROM `{distro_name}` as distro
                JOIN nist ON distro.CVE = nist.CVE
                WHERE YEAR(nist.Published) BETWEEN 2019 AND 2023
                AND distro.CVE IN ({cve_placeholders})
                GROUP BY YEAR(nist.Published)
                ORDER BY YEAR(nist.Published) DESC
            """
            cursor.execute(sql, common_cves_list)
            results = cursor.fetchall()
            if not results: print("    Nenhum dado encontrado para os anos entre 2019-2023.")
            else:
                for year, count in results: print(f"    Ano {year}: {count} CVEs")
        except mysql.connector.Error as err:
            print(f"    Erro ao contar CVEs em comum para {distro_name}: {err}")

def print_severity_comparison(stats_dict, title):
    print(f"\n\n{'='*25}\n {title.upper()} \n{'='*25}")
    for distro, versions in stats_dict.items():
        print(f"\n\n--- Distribuição: {distro.upper()} ---")
        for version, years_data in versions.items():
            print(f"\n  --- Versão: {version} ---")
            comparison_total = defaultdict(lambda: defaultdict(int))
            for year_data in years_data.values():
                for vendor_sev, nist_sevs in year_data['comparison'].items():
                    for nist_sev, count in nist_sevs.items():
                        comparison_total[vendor_sev][nist_sev] += count
            total_cves = sum(sum(nist_sevs.values()) for nist_sevs in comparison_total.values())
            if total_cves == 0:
                print("    Nenhum dado de criticidade para comparar.")
                continue
            matches, mismatches = 0, 0
            mismatch_details = defaultdict(int)
            for vendor_sev, nist_sevs in comparison_total.items():
                for nist_sev, count in nist_sevs.items():
                    if vendor_sev == nist_sev: matches += count
                    else:
                        mismatches += count
                        mismatch_details[f"{distro.upper():<10}: {vendor_sev.upper():<10} | NVD: {nist_sev.upper()}"] += count
            print(f"    Total de CVEs Analisadas: {total_cves}")
            print(f"    Coincidências na Classificação: {matches} ({matches/total_cves*100:.2f}%)")
            print(f"    Divergências na Classificação:  {mismatches} ({mismatches/total_cves*100:.2f}%)")
            if mismatches > 0:
                print("\n      --- Detalhes das Divergências (Contagem | Classificação) ---")
                for detail, count in sorted(mismatch_details.items(), key=lambda item: item[1], reverse=True):
                    print(f"        {count:<5} | {detail}")
            vendor_labels = sorted(list(comparison_total.keys()))
            all_nist_labels = set(l for nist_sevs in comparison_total.values() for l in nist_sevs.keys())
            nist_labels = sorted(list(all_nist_labels))
            matrix = pd.DataFrame(0, index=nist_labels, columns=vendor_labels)
            for vendor_sev, nist_sevs in comparison_total.items():
                for nist_sev, count in nist_sevs.items():
                    matrix.loc[nist_sev, vendor_sev] = count
            matrix.index.name = "NVD"
            matrix.columns.name = f"DISTRO: {distro.upper()}"
            print(f"\n    --- Matriz de Comparação de Criticidade (Linhas: NVD, Colunas: Distro) ---")
            with pd.option_context('display.width', 1000, 'display.max_columns', 10):
                print(matrix)

def print_severity_analysis(stats_dict, title, severity_type='vendor'):
    print(f"\n\n{'='*25}\n {title.upper()} \n{'='*25}")
    categories_map = {'valid': 'CVEs Corrigidas (>0 dias)', 'zero_days': 'CVEs Corrigidas (Dia Zero)', 'not_fixed': 'CVEs Não Corrigidas', 'negative': 'CVEs com Datas Negativas'}
    severity_key = 'severities_vendor' if severity_type == 'vendor' else 'severities_nist'
    for distro, versions in sorted(stats_dict.items()):
        print(f"\n\n--- Distribuição: {distro.upper()} ---")
        for version, years_data in sorted(versions.items()):
            print(f"\n  --- Versão: {version} ---")
            geral_severities = {cat: defaultdict(int) for cat in categories_map}
            for data in years_data.values():
                for cat in categories_map:
                    if cat in data[severity_key]:
                        for sev, count in data[severity_key][cat].items():
                            geral_severities[cat][sev] += count
            analysis_title = "Distribuição" if severity_type == 'vendor' else "NVD"
            print(f"\n    --- Análise de Criticidade da {analysis_title} por Status da CVE (Geral - Todos os Anos) ---")
            for cat_key, cat_label in categories_map.items():
                total_in_cat = sum(geral_severities[cat_key].values())
                if total_in_cat > 0:
                    print(f"      {cat_label} (Total: {total_in_cat}):")
                    for sev, count in sorted(geral_severities[cat_key].items()):
                        print(f"        - {sev.upper() or 'N/A'}: {count} ({(count/total_in_cat*100):.2f}%)")

def print_resolution_time_stats(table_name):
    if not engine: return
    print(f"\n\n{'='*25}\n MÉDIAS DE TEMPO DE RESOLUÇÃO (TABELA: '{table_name}') \n{'='*25}")
    try:
        df = pd.read_sql(f"SELECT Distro, Year, Days FROM {table_name}", engine)
        if df.empty:
            print("Nenhum dado de resolução encontrado para calcular as médias.")
            return
        print("\n--- Média Geral por Distribuição ---")
        avg_geral = df.groupby('Distro')['Days'].mean().round(2)
        for distro_name, avg_day in avg_geral.items():
            print(f"  {distro_name}: {avg_day} dias")
        print("\n--- Média Anual por Distribuição ---")
        for distro_name, group in df.groupby('Distro'):
            print(f"\n{distro_name}:")
            avg_times = group.groupby('Year')['Days'].mean().round(2)
            for year, avg_day in avg_times.items():
                print(f"  {int(year)}: {avg_day} dias")
    except Exception as e:
        print(f"Erro ao calcular médias para '{table_name}': {e}")
        
def generate_plots(table_name, output_folder, days_filter_query=""):
    if not engine: return
    print(f"\n\n{'='*25}\n GRÁFICOS E ESTATÍSTICAS (TABELA: '{table_name}') \n{'='*25}")
    if not os.path.exists(output_folder): os.makedirs(output_folder)
    try:
        query = f"SELECT * FROM {table_name}"
        if days_filter_query:
            query += f" WHERE {days_filter_query}"
            print(f"A aplicar filtro aos dados: {days_filter_query}")

        df = pd.read_sql(query, engine)
        
        if df.empty:
            print(f"Nenhum dado em '{table_name}' para gerar gráficos ou estatísticas com o filtro aplicado.")
            return

        print("\n--- Sumário Estatístico (média, mediana, min, max, etc.) ---")
        pd.set_option('display.width', 1000)
        stats_summary = df.groupby('Distro')['Days'].describe().round(2)
        print(stats_summary)
        print("\nLegenda: count=total, mean=média, std=desvio padrão, min=mínimo, 25%/50%/75%=quartis (50% é a mediana), max=máximo")

        plt.figure(figsize=(14, 8))
        ax = sns.boxplot(x='Distro', y='Days', data=df, showfliers=False, hue='Distro', palette='viridis', legend=False)
        plot_title = f'Tempo de Resolução por Distribuição (Tabela: {table_name})'
        if days_filter_query:
            plot_title += f' - Filtro: {days_filter_query}'
        plt.title(plot_title, fontsize=16)
        plt.xlabel('Distribuição'); plt.ylabel('Dias para Resolução')
        plt.xticks(rotation=45, ha='right'); plt.tight_layout()
        
        filename = f'{output_folder}/boxplot_distribuicoes'
        if days_filter_query:
             filename += '_dias_gt_0'
        filename += '.png'
        
        plt.savefig(filename, dpi=300)
        plt.close()
        print(f"\nGráficos salvos em '{output_folder}'")

    except Exception as e:
        print(f"Erro ao gerar gráficos e estatísticas para '{table_name}': {e}")

# ==============================================================================
# ===== FUNÇÕES PARA ANÁLISES GRÁFICAS E INVESTIGAÇÃO ========================
# ==============================================================================

def generate_summary_status_by_version_plots(stats_dict, output_dir='high_quality_plots_detalhados'):
    print("\n\n" + "#"*80)
    print("# GRÁFICOS DE SUMÁRIO DE STATUS POR VERSÃO #")
    print("# (Esta análise espelha a tabela 'Sumário de Status' por versão)")
    print("#"*80)

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    summary_by_version = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    
    for distro, versions in stats_dict.items():
        for version, years in versions.items():
            for data in years.values():
                summary_by_version[distro][version]['Corrigidas (>0 dias)'] += data['valid']
                summary_by_version[distro][version]['Corrigidas (Dia Zero)'] += data['zero_days']
                summary_by_version[distro][version]['Não Corrigidas'] += data['not_fixed_total']
                summary_by_version[distro][version]['Datas Negativas'] += data['negative']
    
    for dist, versions_data in summary_by_version.items():
        if not versions_data:
            continue
        
        df = pd.DataFrame.from_dict(versions_data, orient='index').fillna(0).astype(int)
        if df.empty:
            continue

        df.index = df.index.astype(str)
        df = df.sort_index()

        status_order = ['Corrigidas (>0 dias)', 'Corrigidas (Dia Zero)', 'Não Corrigidas', 'Datas Negativas']
        colors = ['#2ca02c', '#1f77b4', '#ff7f0e', '#d62728']
        df = df[status_order]

        ax = df.plot(kind='barh', stacked=True, figsize=(14, 8), width=0.8, color=colors)
        
        ax.set_title(f'Sumário de Status de CVEs por Versão - {dist}', fontsize=16, pad=30)
        ax.set_xlabel('Contagem de CVEs', fontsize=12)
        ax.set_ylabel('Versão', fontsize=12)
        ax.invert_yaxis()
        ax.legend(title='Status', loc='upper center', bbox_to_anchor=(0.5, 1.08), ncol=len(df.columns), frameon=False)
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        
        total_width = df.sum(axis=1)
        for i, container in enumerate(ax.containers):
            colors = [get_text_color_for_bg(c.get_facecolor()) for c in container]
            
            texts = ax.bar_label(container, label_type='center', color='white', weight='bold', fontsize=9)
            for j, (patch, text_obj) in enumerate(zip(container.patches, texts)):
                width = patch.get_width()
                if total_width.iloc[j] > 0 and width / total_width.iloc[j] < 0.025:
                    text_obj.set_text('')
                else:
                    text_obj.set_text(f'{int(width)}')
                    text_obj.set_color(colors[j])

        filename = f"{output_dir}/sumario_status_{dist.replace(' ', '_')}.png"
        plt.savefig(filename, dpi=300)
        plt.close()
        print(f"Gráfico de sumário por versão salvo em: {filename}")

def generate_detailed_status_breakdown_plots(stats_dict, output_dir='high_quality_plots_detalhados'):
    print("\n\n" + "#"*80)
    print("# GRÁFICOS DE DETALHAMENTO DE STATUS POR VERSÃO #")
    print("# (Esta análise aprofunda nas categorias 'Não Corrigidas' e 'Datas Negativas')")
    print("#"*80)

    not_fixed_by_version = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    negative_by_version = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

    for distro, versions in stats_dict.items():
        for version, years in versions.items():
            for data in years.values():
                if 'not_fixed_detail' in data:
                    for status, count in data['not_fixed_detail'].items():
                        not_fixed_by_version[distro][version][status] += count
                if 'negative' in data and data['negative'] > 0:
                    negative_by_version[distro][version]['Datas Negativas'] += data['negative']

    print("\n--- Gerando gráficos para detalhamento de 'Vulnerabilidades Não Corrigidas' ---")
    if not_fixed_by_version:
        generate_plot_from_dict(not_fixed_by_version, "Detalhamento de Status Nao Corrigidos", output_dir)
    else:
        print("Nenhum dado encontrado.")

    print("\n--- Gerando gráficos para 'Vulnerabilidades com Datas Negativas' ---")
    if negative_by_version:
        generate_plot_from_dict(negative_by_version, "Vulnerabilidades Data Negativas", output_dir)
    else:
        print("Nenhum dado encontrado.")

def generate_plot_from_dict(data_to_plot, category_title, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    for dist, versions_data in data_to_plot.items():
        if not versions_data: continue
            
        df = pd.DataFrame.from_dict(versions_data, orient='index').fillna(0).astype(int)
        if df.empty: continue

        df.index = df.index.astype(str)
        df = df.sort_index()

        ax = df.plot(kind='barh', stacked=True, figsize=(14, 8), width=0.8, colormap='viridis')
        
        ax.set_title(f'Análise por Versão - {category_title} - {dist}', fontsize=16, pad=30)
        ax.set_xlabel('Contagem de CVEs', fontsize=12)
        ax.set_ylabel('Versão', fontsize=12)
        ax.invert_yaxis()
        ax.legend(title='Status', loc='upper center', bbox_to_anchor=(0.5, 1.08), ncol=len(df.columns), frameon=False)
        plt.tight_layout(rect=[0, 0, 1, 0.95])
        
        total_width = df.sum(axis=1)
        for i, container in enumerate(ax.containers):
            colors = [get_text_color_for_bg(c.get_facecolor()) for c in container]
            
            texts = ax.bar_label(container, label_type='center', color='white', weight='bold', fontsize=9)
            for j, (patch, text_obj) in enumerate(zip(container.patches, texts)):
                width = patch.get_width()
                if total_width.iloc[j] > 0 and width / total_width.iloc[j] < 0.025:
                     text_obj.set_text('')
                else:
                    text_obj.set_text(f'{int(width)}')
                    text_obj.set_color(colors[j])

        filename = f"{output_dir}/{category_title.replace(' ', '_')}_{dist.replace(' ', '_')}.png"
        plt.savefig(filename, dpi=300)
        plt.close()
        print(f"Gráfico detalhado salvo em: {filename}")
        
def investigate_unresolved_by_all_db_versions():
    """
    Realiza uma contagem de status 'não corrigidos' para todas as versões de distro
    encontradas diretamente no banco de dados, para fins de investigação.
    """
    print("\n\n" + "#"*80)
    print("# INVESTIGAÇÃO DE 'NÃO CORRIGIDOS' POR TODAS AS VERSÕES PRESENTES NO BANCO DE DADOS #")
    print("#"*80)
    pd.set_option('display.max_rows', 100)
    pd.set_option('display.width', 200)

    tables_to_check = ['debian', 'ubuntu', 'ubuntupro']

    for table in tables_to_check:
        print(f"\n--- Análise da Tabela: {table} ---")
        try:
            distinct_distros_df = pd.read_sql(f"SELECT DISTINCT Distro FROM {table}", engine)
            if distinct_distros_df.empty:
                print(f"Nenhuma versão/distro encontrada na tabela {table}.")
                continue
            
            all_distros = distinct_distros_df['Distro'].tolist()
            print(f"Versões encontradas na tabela: {', '.join(all_distros)}")

            for distro_version in all_distros:
                print(f"\n  -> Detalhamento de 'Não Corrigidos' para a versão '{distro_version}':")
                query = f"""
                    SELECT Status, COUNT(*) as Contagem 
                    FROM {table} 
                    WHERE Distro = %s
                      AND (Resolved IS NULL OR Resolved = '' OR Resolved = '[]') 
                    GROUP BY Status 
                    ORDER BY Contagem DESC
                """
                unresolved_df = pd.read_sql(query, engine, params=(distro_version,))

                if not unresolved_df.empty:
                    print(unresolved_df.to_string())
                else:
                    print("     Nenhum registro 'não corrigido' (com base na falta de data) foi encontrado para esta versão.")

        except Exception as e:
            print(f"Ocorreu um erro ao analisar a tabela {table}: {e}")

def _calculate_and_plot_mttr_from_df(df, scenario_name, output_folder):
    """Função auxiliar para plotar MTTR a partir de um DataFrame."""
    mean_times = df.groupby('Distro')['Days'].mean()
    print(f"\n--- Tempo Médio de Correção (MTTR) por Distribuição ({scenario_name}) ---")
    for distro, mean_days in mean_times.items():
        print(f"  - {distro}: {mean_days:.2f} dias")
        
    stats_summary = df.groupby('Distro')['Days'].describe()
    
    plt.figure(figsize=(14, 8))
    ax = sns.boxplot(x='Distro', y='Days', data=df, showfliers=False, hue='Distro', palette='viridis', legend=False)
    xtick_labels = [tick.get_text() for tick in ax.get_xticklabels()]
    
    for i, distro_name in enumerate(xtick_labels):
        if distro_name in mean_times:
            mean_value = mean_times[distro_name]
            median_value = stats_summary.loc[distro_name]['50%']
            
            ax.plot(i, mean_value, 'D', color='red', markersize=8, label='Média (MTTR)' if i == 0 else "")
            
            y_offset = (ax.get_ylim()[1] - ax.get_ylim()[0]) * 0.02
            ax.text(i, mean_value + y_offset, f'{mean_value:.1f}', ha='center', va='bottom', size='small', color='black', weight='semibold')
            ax.text(i + 0.05, median_value, f'{median_value:.1f}', ha='left', va='center', size='x-small', color='navy', weight='bold')

    handles, labels = ax.get_legend_handles_labels()
    if handles:
        ax.legend(handles=handles, labels=labels)

    ax.set_title(f'Distribuição e Métricas do Tempo de Correção ({scenario_name})', fontsize=16)
    ax.set_xlabel('Distribuição', fontsize=12)
    ax.set_ylabel('Dias para Correção (Mediana indicada em azul)', fontsize=12)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    filename = f"{output_folder}/boxplot_mttr_{scenario_name.lower().replace(' ', '_')}.png"
    plt.savefig(filename, dpi=300)
    plt.close()
    print(f"\nGráfico Boxplot com MTTR ({scenario_name}) salvo em: {filename}")

def calculate_and_plot_mttr(table_name='results', scenario_name='Geral', output_folder='high_quality_plots_final'):
    """
    Calcula o Tempo Médio de Correção (MTTR) e gera um gráfico boxplot.
    """
    title = f"# ANÁLISE DE TEMPO MÉDIO DE CORREÇÃO (MTTR) - {scenario_name} #"
    print("\n\n" + "#"*len(title))
    print(title)
    print("#"*len(title))

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    try:
        query = f"SELECT Distro, Days FROM {table_name} WHERE Days >= 0"
        df = pd.read_sql(query, engine)
        if df.empty:
            print(f"Nenhum dado de resolução encontrado para o cenário '{scenario_name}'.")
            return
        _calculate_and_plot_mttr_from_df(df, scenario_name, output_folder)
    except Exception as e:
        print(f"Ocorreu um erro durante a análise de MTTR para '{scenario_name}': {e}")

def generate_yearly_trend_chart(stats_dict, title, filename, output_folder='high_quality_plots_final'):
    """
    Gera um gráfico de linhas mostrando a tendência de CVEs por ano para cada distribuição.
    """
    print(f"\n\n{'#'*80}\n# GERANDO GRÁFICO DE TENDÊNCIA ANUAL: {title} #\n{'#'*80}")
    
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    yearly_counts = defaultdict(lambda: defaultdict(int))
    for distro, versions in stats_dict.items():
        for years in versions.values():
            for year, data in years.items():
                total_cves_in_year = data['valid'] + data['zero_days'] + data['negative'] + data['not_fixed_total']
                if total_cves_in_year > 0:
                    yearly_counts[distro][year] += total_cves_in_year
    
    if not yearly_counts:
        print("Nenhum dado encontrado para gerar o gráfico de tendência.")
        return

    df = pd.DataFrame(yearly_counts).fillna(0).astype(int)
    df = df.sort_index()

    plt.figure(figsize=(14, 8))
    ax = df.plot(kind='line', marker='o', figsize=(14, 8))
    
    plt.title(title, fontsize=16)
    plt.xlabel("Ano", fontsize=12)
    plt.ylabel("Contagem de Registros de CVEs", fontsize=12)
    plt.grid(True, which='both', linestyle='--', linewidth=0.5)
    plt.xticks(df.index)
    plt.legend(title='Distribuição')
    
    for col in df.columns:
        for year, count in df[col].items():
            if count > 0:
                ax.text(year, count, f' {count}', va='bottom', ha='center')

    plt.tight_layout()
    filepath = f"{output_folder}/{filename}"
    plt.savefig(filepath, dpi=300)
    plt.close()
    print(f"Gráfico de tendência anual salvo em: {filepath}")

def analyze_ubuntu_vs_pro(output_folder='high_quality_plots_final'):
    """
    Compara o TEMPO DE CORREÇÃO (MTTR) entre Ubuntu e Ubuntu Pro.
    """
    print(f"\n\n{'#'*80}\n# ANÁLISE COMPARATIVA DE MTTR: UBUNTU VS UBUNTU PRO #\n{'#'*80}")
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    try:
        query = "SELECT Distro, Days FROM results WHERE Distro IN ('ubuntu', 'ubuntupro') AND Days >= 0"
        df = pd.read_sql(query, engine)
        if df.empty:
            print("Não foram encontrados dados de correção para Ubuntu ou Ubuntu Pro na tabela 'results'.")
            return
        _calculate_and_plot_mttr_from_df(df, 'Ubuntu_vs_UbuntuPro', output_folder)
    except Exception as e:
        print(f"Ocorreu um erro durante a análise Ubuntu vs Pro: {e}")
    
def analyze_mttr_for_common_cves(output_folder='high_quality_plots_final'):
    """
    Identifica CVEs comuns entre os ecossistemas RPM e DEB e calcula o MTTR para elas.
    """
    title = "# ANÁLISE DE MTTR PARA CVEs COMUNS ENTRE ECOSSISTEMAS #"
    print("\n\n" + "#"*len(title))
    print(title)
    print("#"*len(title))

    rpm_distros = ['Red Hat', 'AlmaLinux', 'Rocky Linux']
    deb_distros = ['Debian', 'ubuntu', 'ubuntupro']
    
    try:
        df_results = pd.read_sql("SELECT CVE, Distro FROM results", engine)
        if df_results.empty:
            print("Tabela 'results' está vazia. Não é possível fazer a análise.")
            return

        rpm_cves = set(df_results[df_results['Distro'].isin(rpm_distros)]['CVE'])
        deb_cves = set(df_results[df_results['Distro'].isin(deb_distros)]['CVE'])
        
        common_cves = rpm_cves.intersection(deb_cves)
        
        print(f"\n--- Análise de Interseção de CVEs ---")
        print(f"  - CVEs (únicas) em distribuições RPM: {len(rpm_cves)}")
        print(f"  - CVEs (únicas) em distribuições DEB: {len(deb_cves)}")
        print(f"  - CVEs em comum: {len(common_cves)}")

        if not common_cves:
            print("Nenhuma CVE em comum encontrada entre os ecossistemas RPM e DEB.")
            return

        cve_list_str = "','".join(common_cves)
        query = f"SELECT Distro, Days FROM results WHERE Days >= 0 AND CVE IN ('{cve_list_str}')"
        df_common_cves = pd.read_sql(query, engine)

        if df_common_cves.empty:
            print("Nenhum dado de tempo de correção encontrado para as CVEs comuns.")
            return
            
        _calculate_and_plot_mttr_from_df(df_common_cves, 'CVEs_Comuns', output_folder)

    except Exception as e:
        print(f"Ocorreu um erro durante a análise de MTTR para CVEs comuns: {e}")

# ===================================================================
# ===== FLUXO DE EXECUÇÃO PRINCIPAL =================================
# ===================================================================

if __name__ == '__main__':
    distro_configs_main = {
        "debian":    {"col": "Distro", "prio": "Priority", "status_col": "Status", "nist_sev_col": "Severity_Nist"},
        "ubuntu":    {"col": "Distro", "prio": "Priority", "status_col": "Status", "nist_sev_col": "Severity_Nist"},
        "ubuntupro": {"col": "Distro", "prio": "Priority", "status_col": "Status", "nist_sev_col": "Severity_Nist"},
        "redhat":    {"col": "Version", "prio": "Severity", "status_col": "FixState", "nist_sev_col": "Severity_Nist"},
        "almalinux": {"col": "Version", "prio": "Severity", "status_col": None, "nist_sev_col": "Severity_NIST"},
        "rockylinux":{"col": "Version", "prio": "Severity", "status_col": None, "nist_sev_col": "Severity_NIST"}
    }
    
    print("\n" + "#"*50 + "\n# BUSCANDO DINAMICAMENTE TODAS AS VERSÕES DAS DISTROS\n" + "#"*50)
    for distro, config in distro_configs_main.items():
        try:
            versions_df = pd.read_sql(f"SELECT DISTINCT {config['col']} FROM `{distro}`", engine)
            config['versions'] = versions_df[config['col']].tolist()
            print(f"  -> Versões encontradas para {distro}: {len(config['versions'])}")
        except Exception as e:
            print(f"!!! ERRO ao buscar versões para {distro}: {e}. Usando lista vazia.")
            config['versions'] = []
    
    version_prefixes = {"redhat": "Red Hat Enterprise Linux ", "almalinux": "AlmaLinux ", "rockylinux": "Rocky Linux "}
    distros_to_analyze = list(distro_configs_main.keys())

    recreate_table('results')
    recreate_table('pacotescomum')

    print("\n\n" + "#"*50 + "\n# A PRÉ-BUSCAR DATAS DE REFERÊNCIA (NIST E MINDATE)\n" + "#"*50)
    try:
        cursor.execute("SELECT CVE, Published FROM nist WHERE Published IS NOT NULL")
        nist_dates_map = {cve: parse_date(date_str) for cve, date_str in cursor.fetchall()}
        print(f"Encontradas {len(nist_dates_map)} datas de publicação NIST.")

        cursor.execute("SELECT cve, MinDate FROM cvemindate WHERE MinDate IS NOT NULL")
        mindate_map = {cve: date_obj for cve, date_obj in cursor.fetchall()}
        print(f"Encontradas {len(mindate_map)} datas mínimas (MinDate).")
    except mysql.connector.Error as err:
        print(f"!!! ERRO CRÍTICO ao buscar datas de referência: {err}")
        exit()

    print("\n\n" + "#"*50 + "\n# INICIANDO ANÁLISE PADRÃO (TODAS AS CVEs)\n" + "#"*50)

    all_records_to_insert = []
    for distro, config in distro_configs_main.items():
        version_filters = config['versions']
        version_map = {v: v.replace(version_prefixes.get(distro, ''), '') for v in version_filters}
        
        if not version_filters:
            print(f"Nenhuma versão para processar em {distro}. Pulando.")
            continue
            
        placeholders = ','.join(['%s'] * len(version_filters))
        
        status_selection = f"'{'not-affected'}'" 
        if config['status_col']:
            status_selection = config['status_col']
        
        sql = (f"SELECT CVE, Resolved, {status_selection} as status, NormPackage, {config['prio']}, {config['nist_sev_col']}, {config['col']} "
               f"FROM `{distro}` WHERE {config['col']} IN ({placeholders})")
        
        print(f"\nProcessando {distro} (todas as {len(version_filters)} versões encontradas)")
        try:
            cursor.execute(sql, version_filters)
            records = cursor.fetchall()
            print(f"Encontrados {len(records)} registos para {distro}.")
        except mysql.connector.Error as err:
            print(f"!!! ERRO ao executar consulta para {distro}: {err}\nConsulta: {cursor.statement}")
            records = []

        if records:
            records_to_insert_distro = process_records(records, distro, version_map, annual_stats, nist_dates_map, mindate_map)
            if records_to_insert_distro:
                all_records_to_insert.extend(records_to_insert_distro)

    if all_records_to_insert:
        print(f"\nInserindo {len(all_records_to_insert)} registos na tabela 'results'...")
        sql_insert = ("INSERT INTO results (CVE, Year, Distro, Version, NormPackage, MinDate, Resolved, Days, Status) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) "
                      "ON DUPLICATE KEY UPDATE Days=VALUES(Days), Resolved=VALUES(Resolved), Status=VALUES(Status)")
        cursor.executemany(sql_insert, all_records_to_insert)
        mydb.commit()
        print("Inserção em lote concluída.")

    common_cves_list = find_and_process_common_packages(nist_dates_map, mindate_map, distro_configs_main, version_prefixes)
    
    print("\n\n" + "#"*50 + "\n# SUMÁRIOS GERAIS E ANUAIS DE CONTAGEM DE CVEs\n" + "#"*50)
    print_summary_cve_counts(common_cves_list, distro_configs_main)
    print_yearly_cve_counts(common_cves_list, distro_configs_main)
    
    print_total_severity_summary_from_source(distros_to_analyze, distro_configs_main, title="Sumário de Contagem de Criticidade (Cenário Geral - Todas as CVEs)")
    print_aggregated_severity_summary_for_status(annual_stats, 'not_fixed', "Sumário de Criticidade de CVEs Não Corrigidas (Cenário Geral)")
    print_aggregated_severity_summary_for_status(annual_stats, 'negative', "Sumário de Criticidade de CVEs com Datas Negativas (Cenário Geral)")

    print("\n\n" + "#"*50 + "\n# GERAÇÃO DE RELATÓRIOS FINAIS DETALHADOS\n" + "#"*50)
    print_status_summary(annual_stats, "Sumário de Status - Análise Padrão (Todas as CVEs)")
    print_resolution_time_stats('results')
    print_severity_analysis(annual_stats, "Análise de Criticidade (Distribuição) por Status - Padrão", 'vendor')
    print_severity_analysis(annual_stats, "Análise de Criticidade (NVD) por Status - Padrão", 'nist')
    generate_plots('results', 'high_quality_plots_results', days_filter_query="Days >= 0")
    print_severity_comparison(annual_stats, "Comparação de Criticidade - Análise Padrão")
    
    if common_pkg_annual_stats:
        print("\n\n" + "-"*50 + "\n RELATÓRIOS PARA PACOTES COMUNS\n" + "-"*50)
        
        print_total_severity_summary_from_source(distros_to_analyze, distro_configs_main, common_cves=common_cves_list, title="Sumário de Contagem de Criticidade (Pacotes Comuns - Todas as CVEs)")
        print_aggregated_severity_summary_for_status(common_pkg_annual_stats, 'not_fixed', "Sumário de Criticidade de CVEs Não Corrigidas (Pacotes Comuns)")
        print_aggregated_severity_summary_for_status(common_pkg_annual_stats, 'negative', "Sumário de Criticidade de CVEs com Datas Negativas (Pacotes Comuns)")
        
        print_status_summary(common_pkg_annual_stats, "Sumário de Status - Pacotes Comuns (Todas as CVEs)")
        print_resolution_time_stats('pacotescomum')
        print_severity_analysis(common_pkg_annual_stats, "Análise de Criticidade (Distribuição) por Status - Pacotes Comuns", 'vendor')
        print_severity_analysis(common_pkg_annual_stats, "Análise de Criticidade (NVD) por Status - Pacotes Comuns", 'nist')
        generate_plots('pacotescomum', 'high_quality_plots_pacotescomum', days_filter_query="Days >= 0")
        print_severity_comparison(common_pkg_annual_stats, "Comparação de Criticidade - Pacotes Comuns")
    else:
        print("\n\n" + "#"*50 + "\n# Nenhum dado de pacote comum foi processado. Relatórios para 'pacotescomum' não serão gerados.\n" + "#"*50)
    
    analyze_and_print_redhat_comparison()
    
    generate_severity_bar_charts(annual_stats, "Geral")
    if common_pkg_annual_stats:
        generate_severity_bar_charts(common_pkg_annual_stats, "Pacotes_Comuns")

    generate_summary_status_by_version_plots(annual_stats)
    generate_detailed_status_breakdown_plots(annual_stats)

    investigate_unresolved_by_all_db_versions()
    
    calculate_and_plot_mttr()
    if common_pkg_annual_stats:
        calculate_and_plot_mttr(table_name='pacotescomum', scenario_name='Pacotes_Comuns')

    if common_pkg_annual_stats:
        generate_yearly_trend_chart(common_pkg_annual_stats, 
                                    "Evolução Anual de CVEs em Pacotes Comuns (2019-2023)", 
                                    "yearly_trend_common_pkgs.png")
    
    analyze_ubuntu_vs_pro()
    
    analyze_mttr_for_common_cves()

    print("\nExecução finalizada com sucesso.")
    cursor.close()
    mydb.close()
