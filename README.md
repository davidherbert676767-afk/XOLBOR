# XOLBOR Backend Online

Backend inicial para transformar o protótipo em um serviço online.

## O que já existe
- Cadastro/login por e-mail + senha com bcrypt.
- Sessões JWT.
- ID único por conta; jogos guardam `owner_id`.
- Catálogo online de jogos e criação de jogos.
- Chat por jogo.
- Saldo de moedas no servidor e gasto validado no servidor.
- Ban/unban e cargos OWNER/ADMIN/MODERATOR/PLAYER.
- O OWNER não pode ser banido nem rebaixado pelas rotas normais.
- SQLite para começar sem precisar de outro banco.

## Rodar localmente
1. Instale Node.js 20+.
2. Entre em `backend/`.
3. Rode `npm install`.
4. Defina `JWT_SECRET` forte. Em produção, use HTTPS e uma variável secreta real.
5. Rode `npm start`.
6. Teste `GET /health`.

O app Android está configurado para desenvolvimento com `http://10.0.2.2:8080` (emulador Android). Para celular físico ou produção, troque `BuildConfig.XOLBOR_API_URL` por uma URL HTTPS pública.

## Importante
Este backend é a base técnica; ele não fica público automaticamente. Para multiplayer real, é preciso hospedá-lo em um servidor e, depois, conectar o cliente Android à URL HTTPS. O código não contém suas credenciais, cartão ou conta bancária.
