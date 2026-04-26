# Sistema de Autenticação G9 Private (Node.js)

Este é um sistema completo de autenticação para o seu painel C++, incluindo um site administrativo para gerenciamento de usuários, agora desenvolvido em **JavaScript (Node.js)**.

## Funcionalidades
- **Login por API**: Integração direta com o seu painel C++.
- **Vínculo de HWID**: O primeiro login vincula o HWID automaticamente.
- **Gerenciamento de Dias**: Adicione ou remova tempo de assinatura pelo site.
- **Sistema de Ban**: Banimento de usuários com motivo.
- **Reset de HWID**: Permita que usuários troquem de PC através do painel admin.
- **Discord ID**: Armazene o ID do Discord para referência.

## Como Instalar

1. Instale o [Node.js](https://nodejs.org/).
2. Abra o terminal na pasta `G9 Authentication`.
3. Instale as dependências:
   ```bash
   npm install
   ```
4. Inicie o servidor:
   ```bash
   npm start
   ```
5. Acesse o painel admin em: `http://localhost:5000/admin/login`
   - **Usuário Padrão**: `admin`
   - **Senha Padrão**: `admin123`

## Integração C++ (Exemplo de JSON)

O seu painel deve enviar um POST para `http://localhost:5000/api/login` com o seguinte corpo:
```json
{
    "username": "usuario_aqui",
    "hwid": "hwid_do_pc_aqui",
    "product": "VALORANT" 
}
```
*(Se o campo `product` não for enviado, o sistema usará `G9_PRIVATE` por padrão)*.

O servidor responderá com:
- `status: "success"` se o login for permitido.
- `status: "error"` com uma mensagem caso contrário.
