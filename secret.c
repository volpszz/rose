#include <stdio.h>
#include <stdlib.h>
#include <string.h>
 
#define ARQUIVO_SAIDA "senha.enc"
#define TAM_MAX 256
 
/* Le uma linha do teclado sem deixar o \n no final */
static void ler_linha(char *buf, size_t tam) {
    if (fgets(buf, (int)tam, stdin) != NULL) {
        size_t len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[len - 1] = '\0';
        }
    }
}
 
/* XOR simples: aplica a chave (em ciclo) sobre os bytes do texto */
static void xor_cifra(unsigned char *dados, size_t tam_dados,
                       const unsigned char *chave, size_t tam_chave) {
    for (size_t i = 0; i < tam_dados; i++) {
        dados[i] ^= chave[i % tam_chave];
    }
}
 
/* Checksum simples (soma dos bytes) usado so para validar o codigo
 * na hora de descriptografar, nao tem valor criptografico real */
static unsigned char calcular_checksum(const unsigned char *dados, size_t tam) {
    unsigned char soma = 0;
    for (size_t i = 0; i < tam; i++) {
        soma = (unsigned char)(soma + dados[i]);
    }
    return soma;
}
 
static void modo_encrypt(void) {
    char senha[TAM_MAX];
    char codigo[TAM_MAX];
 
    printf("Digite a senha que deseja criptografar: ");
    ler_linha(senha, sizeof(senha));
 
    printf("Crie um codigo secreto (sera necessario para descriptografar): ");
    ler_linha(codigo, sizeof(codigo));
 
    size_t tam_senha = strlen(senha);
    size_t tam_codigo = strlen(codigo);
 
    if (tam_senha == 0 || tam_codigo == 0) {
        printf("Senha e codigo nao podem ser vazios.\n");
        return;
    }
 
    unsigned char checksum = calcular_checksum((unsigned char *)senha, tam_senha);
 
    unsigned char buffer[TAM_MAX];
    memcpy(buffer, senha, tam_senha);
    xor_cifra(buffer, tam_senha, (unsigned char *)codigo, tam_codigo);
 
    FILE *f = fopen(ARQUIVO_SAIDA, "wb");
    if (!f) {
        perror("Erro ao criar arquivo");
        return;
    }
 
    /* grava: tamanho da senha (1 byte), checksum (1 byte), depois os bytes cifrados */
    unsigned char tam_byte = (unsigned char)tam_senha;
    fwrite(&tam_byte, 1, 1, f);
    fwrite(&checksum, 1, 1, f);
    fwrite(buffer, 1, tam_senha, f);
    fclose(f);
 
    printf("\nSenha criptografada com sucesso em '%s'.\n", ARQUIVO_SAIDA);
    printf("Guarde bem o codigo secreto: sem ele NAO da pra recuperar a senha.\n");
}
 
static void modo_decrypt(void) {
    FILE *f = fopen(ARQUIVO_SAIDA, "rb");
    if (!f) {
        printf("Arquivo '%s' nao encontrado. Rode primeiro o modo encrypt.\n", ARQUIVO_SAIDA);
        return;
    }
 
    unsigned char tam_byte = 0, checksum_original = 0;
    fread(&tam_byte, 1, 1, f);
    fread(&checksum_original, 1, 1, f);
 
    unsigned char buffer[TAM_MAX];
    size_t lidos = fread(buffer, 1, tam_byte, f);
    fclose(f);
 
    if (lidos != tam_byte) {
        printf("Arquivo corrompido ou invalido.\n");
        return;
    }
 
    char codigo[TAM_MAX];
    printf("Digite o codigo secreto: ");
    ler_linha(codigo, sizeof(codigo));
    size_t tam_codigo = strlen(codigo);
 
    if (tam_codigo == 0) {
        printf("Codigo nao pode ser vazio.\n");
        return;
    }
 
    xor_cifra(buffer, tam_byte, (unsigned char *)codigo, tam_codigo);
    buffer[tam_byte] = '\0';
 
    unsigned char checksum_calculado = calcular_checksum(buffer, tam_byte);
 
    if (checksum_calculado != checksum_original) {
        printf("\nCodigo secreto incorreto. Nao foi possivel recuperar a senha.\n");
        return;
    }
 
    printf("\nSenha recuperada: %s\n", buffer);
}
 
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s [encrypt|decrypt]\n", argv[0]);
        return 1;
    }
 
    if (strcmp(argv[1], "encrypt") == 0) {
        modo_encrypt();
    } else if (strcmp(argv[1], "decrypt") == 0) {
        modo_decrypt();
    } else {
        printf("Opcao invalida. Use 'encrypt' ou 'decrypt'.\n");
        return 1;
    }
 
    return 0;
}
