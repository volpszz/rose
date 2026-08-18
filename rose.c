#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __ unsigned char
#define ___ size_t
#define X(a,b,c,d) (a)[(b)]^=(c)[(b)%(d)]
typedef char T[256];
int(*O)(const char*,...)=printf;
static void W(char*s,___ n){if(fgets(s,(int)n,stdin)){___ z=strlen(s);if(z&&s[z-1]==10)s[--z]=0;}}
static void N(__*p,___ n,const __*k,___ m){___ i=0;L1:if(i<n){X(p,i,k,m);i++;goto L1;}}
static __ S(const __*p,___ n){__ s=0;___ i=0;while(i<n){s=(__)(s+p[i]),i++;}return s;}
static void E(const char*f){
T a,b;
O("Digite a senha que deseja criptografar: ");W(a,sizeof a);
O("Crie um codigo secreto (sera necessario para descriptografar): ");W(b,sizeof b);
___ na=strlen(a),nb=strlen(b);
if(!na||!nb){O("Senha e codigo nao podem ser vazios.\n");return;}
__ cs=S((__*)a,na);
__ buf[256];memcpy(buf,a,na);N(buf,na,(__*)b,nb);
FILE*fp=fopen(f,"wb");
if(!fp){perror("Erro ao criar arquivo");return;}
__ tb=(__)na;
fwrite(&tb,1,1,fp),fwrite(&cs,1,1,fp),fwrite(buf,1,na,fp),fclose(fp);
O("\nSenha criptografada com sucesso em '%s'.\n",f);
O("Guarde bem o codigo secreto: sem ele NAO da pra recuperar a senha.\n");
}
static void D(const char*f){
FILE*fp=fopen(f,"rb");
if(!fp){O("Arquivo '%s' nao encontrado. Rode primeiro o modo encrypt.\n",f);return;}
__ tb=0,co=0;fread(&tb,1,1,fp),fread(&co,1,1,fp);
__ buf[256];___ rd=fread(buf,1,tb,fp);fclose(fp);
if(rd!=tb){O("Arquivo corrompido ou invalido.\n");return;}
T b;O("Digite o codigo secreto: ");W(b,sizeof b);
___ nb=strlen(b);
if(!nb){O("Codigo nao pode ser vazio.\n");return;}
N(buf,tb,(__*)b,nb),buf[tb]=0;
__ cc=S(buf,tb);
cc!=co?(void)O("\nCodigo secreto incorreto. Nao foi possivel recuperar a senha.\n"):(void)O("\nSenha recuperada: %s\n",buf);
}
int main(int c,char**v){
if(c<2){O("Uso: %s [encrypt|decrypt] [arquivo.enc]\n",v[0]);O("Se o nome do arquivo nao for informado, usa 'senha.enc' por padrao.\n");exit(1);}
const char*f=c>=3?v[2]:"senha.enc";
!strcmp(v[1],"encrypt")?(E(f),0):!strcmp(v[1],"decrypt")?(D(f),0):(O("Opcao invalida. Use 'encrypt' ou 'decrypt'.\n"),exit(1));
return 0;
}
