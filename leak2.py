import os
import re
import time
from datetime import datetime
from multiprocessing import Pool
from pathlib import Path
import psutil

def get_all_drives():
    """Lista todos os HDs/partições disponíveis no sistema."""
    drives = [partition.mountpoint for partition in psutil.disk_partitions()]
    return drives

def search_in_file(args):
    """Busca um termo em um arquivo e retorna as linhas correspondentes."""
    file_path, pattern = args
    results = []
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_number, line in enumerate(f, 1):
                if pattern.search(line):  # Usa o padrão compilado diretamente
                    results.append(f"{file_path}:{line_number}: {line.strip()}")
    except Exception as e:
        return [f"Erro ao ler {file_path}: {str(e)}"]
    return results

def process_drive(drive_path, search_term, output_dir):
    """Processa todos os arquivos .txt em um HD e salva os resultados."""
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    drive_name = Path(drive_path).name.replace(" ", "_") or "root"
    output_file = os.path.join(output_dir, f"{drive_name}_{search_term}.txt")
    
    print(f"[{timestamp}] Iniciando busca no HD {drive_name}")
    
    # Compila o padrão de busca com a flag IGNORECASE
    pattern = re.compile(re.escape(search_term), re.IGNORECASE)
    
    # Lista todos os arquivos .txt
    txt_files = []
    for root, _, files in os.walk(drive_path):
        for file in files:
            if file.lower().endswith('.txt'):
                txt_files.append(os.path.join(root, file))
    
    # Usa multiprocessing para processar arquivos em paralelo
    with Pool() as pool:
        results = pool.map(search_in_file, [(f, pattern) for f in txt_files])
    
    # Escreve os resultados no arquivo de saída
    with open(output_file, 'w', encoding='utf-8') as f:
        for result in results:
            for line in result:
                f.write(line + '\n')
    
    end_time = time.time()
    end_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elapsed_time = end_time - start_time
    print(f"[{end_timestamp}] Finalizada busca no HD {drive_name}. Tempo: {elapsed_time:.2f} segundos")
    print(f"Resultados salvos em: {output_file}")

def main():
    # Cria diretório para resultados, se não existir
    output_dir = "search_results"
    os.makedirs(output_dir, exist_ok=True)
    
    # Lista todos os HDs/partições
    drives = get_all_drives()
    if not drives:
        print("Nenhum HD ou partição encontrado.")
        return
    
    # Mostra os HDs disponíveis
    print("HDs/partições disponíveis:")
    for i, drive in enumerate(drives, 1):
        print(f"{i}. {drive} ({Path(drive).name or 'root'})")
    
    # Solicita seleção dos HDs
    while True:
        try:
            choice_input = input("Digite os números dos HDs que deseja pesquisar (ex.: 1,3,4): ")
            choices = [int(x) for x in choice_input.replace(" ", "").split(",")]
            if not choices:
                print("Você deve selecionar pelo menos um HD.")
                continue
            if all(1 <= choice <= len(drives) for choice in choices):
                selected_drives = [drives[choice - 1] for choice in choices]
                break
            else:
                print("Um ou mais números são inválidos. Tente novamente.")
        except ValueError:
            print("Digite números válidos separados por vírgulas (ex.: 1,3,4).")
    
    # Solicita o termo de pesquisa
    search_term = input("Digite o termo de pesquisa: ").strip()
    if not search_term:
        print("Termo de pesquisa não pode ser vazio.")
        return
    
    # Processa cada HD selecionado
    for drive in selected_drives:
        process_drive(drive, search_term, output_dir)

if __name__ == "__main__":
    main()
