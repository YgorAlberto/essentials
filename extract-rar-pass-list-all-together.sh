#!/bin/bash

# Diretório onde estão os .rar e o wordlist
DIR="."
# Arquivo de senhas
WORDLIST="pass-slurm.txt"
# Diretório único de extração
DEST="extracao_total"

# Cria o diretório de destino
mkdir -p "$DEST"

# Verifica o arquivo de senhas
if [[ ! -f "$WORDLIST" ]]; then
    echo "[ERRO] Arquivo de senhas '$WORDLIST' não encontrado."
    exit 1
fi

# Itera por cada arquivo .rar
for rarfile in "$DIR"/*.rar; do
    echo "📦 Processando: $rarfile"
    base=$(basename "$rarfile" .rar)
    success=0

    # Tenta cada senha
    while IFS= read -r password; do
        echo "  🔐 Tentando senha: $password"
        
        # Testa a senha
        if unrar t -p"$password" "$rarfile" > /dev/null 2>&1; then
            echo "  ✅ Senha correta: $password"

            # Extrai para um diretório temporário
            tmpdir=$(mktemp -d)
            unrar x -o+ -p"$password" "$rarfile" "$tmpdir/" > /dev/null

            # Move os arquivos para o diretório final, renomeando para evitar conflitos
            find "$tmpdir" -type f | while read -r filepath; do
                filename=$(basename "$filepath")
                newname="${base}_${filename}"

                # Garante que não sobrescreva arquivos existentes
                while [[ -e "$DEST/$newname" ]]; do
                    newname="${base}_$RANDOM_${filename}"
                done

                mv "$filepath" "$DEST/$newname"
                echo "    ➕ Extraído: $newname"
            done

            # Limpa diretório temporário
            rm -rf "$tmpdir"
            success=1
            break
        fi
    done < "$WORDLIST"

    if [[ $success -eq 0 ]]; then
        echo "  ❌ Nenhuma senha funcionou para: $rarfile"
    fi
done

echo "✅ Finalizado. Arquivos extraídos estão em: $DEST"
