import pandas as pd
import re
from flask import Flask, render_template
import os
import sys

app = Flask(__name__)

csv_dir = sys.argv[1] if len(sys.argv) > 1 else r"C:\Users\CSV"
csv_files = [file for file in os.listdir(csv_dir) if file.endswith(".csv")]

def remove_column_from_csv_files(csv_dir):
    files = os.listdir(csv_dir)
    for filename in files:
        if filename.endswith(".csv"):
            file_path = os.path.join(csv_dir, filename)
            df = pd.read_csv(file_path, escapechar='\\')
            if 'ContainerLog' in df.columns:
                columns_to_remove = ['Version','Qualifiers','Level','Task','Keywords','Opcode','ContainerLog', 'Bookmark', 'KeywordsDisplayNames', 'Properties', 'RelatedActivityId', 'ActivityId','MatchedQueryIds']
                df.drop(columns=columns_to_remove, inplace=True)
                df.to_csv(file_path, index=False)

remove_column_from_csv_files(csv_dir)

def process_dataframe(df):
    df.replace(to_replace=r'\n', value="<br>", regex=True, inplace=True)
    df.replace(to_replace=r'\r', value="", regex=True, inplace=True)
    df.replace(to_replace=r'\t', value="    ", regex=True, inplace=True)
    
def find_unique_exe_files(df, column_name):
    unique_exe_files = set()
    file_regex = r'\b\w+\.exe\b'  # Регулярное выражение для поиска файлов с расширением .exe

    if column_name in df.columns:
        messages = df[column_name].astype(str)
        for message in messages:
            exe_files = re.findall(file_regex, message)
            unique_exe_files.update(exe_files)

    return unique_exe_files

def find_unique_machine_names(file_path, column_name):
    unique_machine_names = set()
    try:
        df = pd.read_csv(file_path)
        if column_name in df.columns:
            unique_machine_names = set(df[column_name].unique())
    except Exception as e:
        print(f"Error reading file: {e}")
    return unique_machine_names

def find_unique_ip_addresses(df):
    unique_ips = set()
    ip_regex = r'\b(?:25[0-5]|2[4-9][0-9]|[1-9][0-9]|[4-9])(?:\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}\b'

    for column in df.columns:
        if df[column].dtype == 'object':
            matches = df[column].astype(str).apply(lambda x: re.findall(ip_regex, x))
            unique_ips.update([ip for sublist in matches for ip in sublist])

    return unique_ips

def find_unique_users_from_messages(df, column_name):
    unique_users = set()
    user_regex = r'Пользователь = ([^<]+)'  # Изменяем регулярное выражение для поиска символов до "<"

    if column_name in df.columns:
        messages = df[column_name].astype(str)
        for message in messages:
            users = re.findall(user_regex, message)
            unique_users.update(users)

    return unique_users

def find_http_https_requests_and_ips(df, column_name):
    unique_urls = set()
    unique_ips = set()
    url_regex = r'https?://\S+'
    ip_regex = r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(:[0-9]+)?'

    if column_name in df.columns:
        messages = df[column_name].astype(str)
        for message in messages:
            urls = re.findall(url_regex, message)
            for url in urls:
                unique_urls.add(url)
                ip_match = re.search(ip_regex, url)
                if ip_match:
                    unique_ips.add(ip_match.group())

    return unique_urls, unique_ips

def write_ips_to_csv(ips, filename="network_map.csv"):
    df = pd.DataFrame(ips, columns=["IP"])
    df.to_csv(os.path.join(csv_dir, filename), index=False)

@app.route("/")
def index():
    data_frames = []
    unique_http_requests = set()
    all_unique_ips = set()
    unique_machine_names = set()
    unique_users = set()  # Создаем пустое множество для уникальных пользователей
    unique_exe_files = set()  # Создаем пустое множество для уникальных файлов .exe

    for file in csv_files:
        file_path = os.path.join(csv_dir, file)
        try:
            df = pd.read_csv(file_path)
            process_dataframe(df)
            # Поиск HTTP/HTTPS запросов и IP адресов
            urls, ips = find_http_https_requests_and_ips(df, 'Message')
            unique_http_requests.update(urls)
            all_unique_ips.update(ips)
            # Поиск уникальных имен машин
            machine_names = find_unique_machine_names(file_path, 'MachineName')
            unique_machine_names.update(machine_names)
            # Поиск уникальных пользователей
            users = find_unique_users_from_messages(df, 'Message')
            unique_users.update(users)  # Обновляем множество уникальных пользователей
            # Поиск уникальных файлов .exe
            exe_files = find_unique_exe_files(df, 'Message')
            unique_exe_files.update(exe_files)  # Обновляем множество уникальных файлов .exe
            html_table = df.to_html(classes="table table-striped", index=False, escape=False)
            data_frames.append((file, html_table))
        except Exception as e:
            print(f"Ошибка при чтении файла {file_path}: {e}")
    
    return render_template("index.html", data_frames=data_frames, unique_http_requests=unique_http_requests, unique_machine_names=unique_machine_names, unique_users=unique_users, unique_exe_files=unique_exe_files)

if __name__ == "__main__":
    app.run(port=8080)