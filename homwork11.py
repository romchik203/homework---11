#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Скрипт для анализа логов WinEventLog и DNS из файла botsv1.json.
Выявляет подозрительные события и строит топ-10 наиболее частых из них.
Требуемые библиотеки: pandas, matplotlib, seaborn.
"""

import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# --------------------------------------
# 1. Загрузка и подготовка данных
# --------------------------------------
def load_data(filename):
    """Загружает данные из JSON-файла и возвращает список записей (result)."""
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    # Извлекаем поле result из каждого элемента
    results = [item['result'] for item in data]
    return results

def create_dataframe(results):
    """Создаёт pandas DataFrame из списка записей."""
    df = pd.DataFrame(results)
    return df

# --------------------------------------
# 2. Разделение на WinEventLog и DNS
# --------------------------------------
def split_logs(df):
    """
    Разделяет DataFrame на два: для WinEventLog и для DNS.
    WinEventLog: записи, у которых EventCode не равен 'DNS'.
    DNS: записи с EventCode == 'DNS'.
    """
    win_df = df[df['EventCode'] != 'DNS'].copy()
    dns_df = df[df['EventCode'] == 'DNS'].copy()
    return win_df, dns_df

# --------------------------------------
# 3. Выявление подозрительных событий
# --------------------------------------
def mark_suspicious_win(win_df):
    """
    Отмечает подозрительные события в WinEventLog на основе EventID.
    Список подозрительных EventID задаётся в переменной suspicious_ids.
    Возвращает копию DataFrame с добавленным столбцом 'suspicious'.
    """
    # Типовые подозрительные EventID (можно расширить)
    suspicious_ids = {4625, 4672, 4703, 4648, 4688}
    win_df = win_df.copy()
    # Преобразуем EventCode в числовой тип (ошибочные станут NaN)
    win_df['EventCode_num'] = pd.to_numeric(win_df['EventCode'], errors='coerce')
    win_df['suspicious'] = win_df['EventCode_num'].isin(suspicious_ids)
    return win_df

def mark_suspicious_dns(dns_df):
    """
    Отмечает подозрительные DNS-запросы.
    Критерии:
      - поле eventtype содержит строку 'suspicious'
      - имя домена (QueryName) содержит подстроки 'malicious' или 'c2.'
    Возвращает копию DataFrame с добавленным столбцом 'suspicious'.
    """
    dns_df = dns_df.copy()
    def is_suspicious(row):
        # Проверка по eventtype (если есть)
        if 'eventtype' in row and isinstance(row['eventtype'], list):
            if 'suspicious' in row['eventtype']:
                return True
        # Проверка по имени домена (если есть поле QueryName)
        qname = row.get('QueryName')
        if isinstance(qname, str):
            qname_low = qname.lower()
            if 'malicious' in qname_low or 'c2.' in qname_low:
                return True
        return False
    dns_df['suspicious'] = dns_df.apply(is_suspicious, axis=1)
    return dns_df

# --------------------------------------
# 4. Формирование меток для визуализации
# --------------------------------------
def prepare_labels(win_susp, dns_susp):
    """
    Для подозрительных событий создаёт столбец 'event_label':
      - для WinEventLog: строка вида "WinEvent <EventCode>: <signature>"
      - для DNS: имя домена (QueryName)
    Возвращает объединённый DataFrame всех подозрительных событий.
    """
    win_susp = win_susp.copy()
    # Используем поле 'signature' как описание, если есть, иначе общее название
    win_susp['event_label'] = win_susp.apply(
        lambda row: f"WinEvent {row['EventCode_num']:.0f}: {row.get('signature', 'unknown')}",
        axis=1
    )
    
    dns_susp = dns_susp.copy()
    dns_susp['event_label'] = dns_susp['QueryName'].fillna('unknown_dns')
    
    # Объединяем
    all_susp = pd.concat([win_susp, dns_susp], ignore_index=True)
    return all_susp

# --------------------------------------
# 5. Подсчёт топ-10 и визуализация
# --------------------------------------
def plot_top10(all_susp, output_filename='top10_suspicious_events.png'):
    """Строит горизонтальную столбчатую диаграмму топ-10 подозрительных событий."""
    # Подсчёт частоты
    top = all_susp['event_label'].value_counts().head(10).reset_index()
    top.columns = ['event', 'count']
    
    # Построение графика
    plt.figure(figsize=(10, 6))
    sns.barplot(data=top, y='event', x='count', palette='Reds_r')
    plt.title('Топ‑10 наиболее частых подозрительных событий')
    plt.xlabel('Количество')
    plt.ylabel('Тип события')
    plt.tight_layout()
    plt.savefig(output_filename, dpi=100)
    plt.show()
    print(f"График сохранён как {output_filename}")
    
    # Вывод таблицы в консоль
    print("\nТоп-10 подозрительных событий:")
    print(top.to_string(index=False))
    return top

# --------------------------------------
# 6. Основная функция
# --------------------------------------
def main():
    # Имя файла с данными (можно изменить или передавать аргументом)
    filename = 'botsv1.json'
    
    # Загрузка
    print(f"Загрузка данных из {filename}...")
    results = load_data(filename)
    df = create_dataframe(results)
    print(f"Всего записей: {len(df)}")
    
    # Разделение
    win_df, dns_df = split_logs(df)
    print(f"WinEventLog записей: {len(win_df)}")
    print(f"DNS записей: {len(dns_df)}")
    
    # Разметка подозрительных
    win_df = mark_suspicious_win(win_df)
    dns_df = mark_suspicious_dns(dns_df)
    
    win_susp = win_df[win_df['suspicious']]
    dns_susp = dns_df[dns_df['suspicious']]
    print(f"Подозрительных WinEventLog: {len(win_susp)}")
    print(f"Подозрительных DNS: {len(dns_susp)}")
    
    if len(win_susp) == 0 and len(dns_susp) == 0:
        print("Нет подозрительных событий для визуализации.")
        return
    
    # Подготовка меток
    all_susp = prepare_labels(win_susp, dns_susp)
    
    # Визуализация
    top10 = plot_top10(all_susp)
    
    # Дополнительно можно вывести информацию о подозрительных событиях
    print("\nПримеры подозрительных событий WinEventLog:")
    if len(win_susp) > 0:
        print(win_susp[['EventCode', 'signature', 'ComputerName']].head())
    print("\nПримеры подозрительных DNS-запросов:")
    if len(dns_susp) > 0:
        print(dns_susp[['QueryName', 'ClientIP', 'eventtype']].head())

if __name__ == '__main__':
    main()