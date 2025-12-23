🛡️ Relatório Técnico de Pentest: OWASP Broken Web Apps

Data: 23/12/2025 Analista: marcos leal Alvo: OWASP BWA (IP: 10.x.x.x / 10.x.x.x) Classificação de Risco: 🔴 CRÍTICO
1. Sumário Executivo

Durante a análise de segurança realizada no ambiente controlado OWASP BWA, foi possível comprometer totalmente o servidor, obtendo privilégios de superusuário (root). A exploração foi facilitada por configurações padrão inseguras, softwares desatualizados e uso de senhas fracas. O impacto de negócio é severo, permitindo que um atacante tenha controle total sobre os dados, aplicações e sistema operacional.
2. Metodologia e Evidências
Fase 1: Reconhecimento e Varredura (Scanning)

Iniciou-se com uma varredura de portas para identificar a superfície de ataque. Ferramenta: Nmap Comando: nmap -sV -sC -p 22,80... -oN owasp_detalhado.txt

Descobertas: O alvo apresenta múltiplos vetores de entrada críticos expostos:

    Porta 22 (SSH): OpenSSH 5.3p1 (Versão obsoleta).

    Porta 80/443 (HTTP/HTTPS): Apache 2.2.14 e PHP 5.3.2 (Vulneráveis a múltiplos CVEs).

    Portas 139/445 (SMB): Samba rodando com assinatura de mensagens desabilitada.

    Porta 8080: Apache Tomcat 1.1.

    Porta 5001: Java Object Serialization (Alto risco de RCE).

    Evidência: O scan confirmou versões de serviços com mais de 10 anos de defasagem e configurações padrão do Ubuntu antigo.

Fase 2: Enumeração de Vulnerabilidades
2.1 Enumeração Web

Utilizando o Nikto, foram identificados arquivos sensíveis e configurações inseguras no servidor web Apache. Descobertas Críticas:

    Ausência de headers de segurança (X-Frame-Options).

    Diretórios de administração expostos: /wordpress/wp-login/, /phpmyadmin/.

    Versões de software (PHP/Apache) em End-of-Life (EOL).

    Evidência: O Nikto mapeou a estrutura de diretórios e confirmou a antiguidade da stack web.

2.2 Enumeração de Usuários (SMB)

Através do protocolo SMB, foi possível enumerar usuários válidos do sistema operacional, mesmo sem acesso inicial. Ferramenta: Enum4linux Descobertas:

    Domínio/Workgroup: WORKGROUP.

    Usuários identificados via RID Cycling: root (RID 1001) e user (RID 1000).

    Evidência: A ferramenta confirmou a existência dos usuários alvo, permitindo ataques de força bruta direcionados.

Fase 3: Exploração (Exploitation)

Com os usuários identificados (root, user), foi realizado um teste de credenciais padrão (Default Credentials), técnica comum contra infraestruturas mal configuradas.

Vetor de Ataque: SSH (Porta 22) Credenciais Testadas: root:owaspbwa Resultado: Acesso administrativo concedido com sucesso.

Nota Técnica: Devido à antiguidade do servidor SSH (OpenSSH 5.3), foi necessário forçar o cliente SSH moderno a aceitar algoritmos de chave legados (ssh-rsa). Comando de bypass: ssh -oHostKeyAlgorithms=+ssh-rsa ... root@alvo

    Evidência: Acesso root confirmado pelo prompt do sistema e banner de boas-vindas.

Fase 4: Pós-Exploração e Quebra de Senhas

Com acesso root, o arquivo de hashes de senha (/etc/shadow) foi exfiltrado para análise da política de senhas da organização.

Análise do Hash:

    Algoritmo: SHA-512 ($6$).

    Robustez: O algoritmo é criptograficamente forte, mas a segurança depende da complexidade da senha.

Quebra de Senha (Cracking): Utilizando o John the Ripper em um ambiente controlado, foi demonstrado que a senha utilizada (owaspbwa) era extremamente fraca.

    Ataque realizado: Dictionary Attack / Single Crack Mode.

    Tempo de quebra: < 1 segundo.

    Evidência: O arquivo shadow foi lido e as senhas foram quebradas com sucesso pelo John.

3. Recomendações de Segurança (Remediação)

Para mitigar os riscos identificados, recomenda-se:

    Gestão de Identidade: Alterar imediatamente todas as senhas padrão de fábrica e implementar política de senhas fortes (mínimo 12 caracteres, complexidade alta).

    Hardening de SSH:

        Desabilitar login direto como root.

        Implementar autenticação baseada exclusivamente em chaves públicas (SSH Keys).

        Atualizar o serviço OpenSSH para versão suportada.

    Atualização de Software (Patch Management): O sistema operacional e serviços (Apache, PHP, Tomcat) estão obsoletos. É mandatória a migração para versões com suporte de segurança ativo.

    Firewall: Restringir o acesso às portas de gerenciamento (22, 8080, 5001) apenas para IPs de administração autorizados via VPN.
