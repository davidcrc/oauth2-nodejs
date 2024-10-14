# OAuth2 Token Server

Este es un servidor de tokens OAuth2 que implementa el flujo de client_credentials. El servidor se encarga de generar tokens JWT y validar las solicitudes de los clientes.

## Requisitos

- Node.js v12.22.1 o superior
- npm v6.14.14 o superior

## Instalación

1. Clona el repositorio:

```bash
git clone https://github.com/davidcrc/oauth2-nodejs.git
```

2. Instala las dependencias:

```
cd oauth2-nodejs
npm install
```

3. Configura las variables de entorno:

```
cp .env.example .env
```

Edita el archivo .env y configura las siguientes variables de entorno:

CLIENT_ID: ID del cliente.
CLIENT_SECRET: Secreto del cliente.
JWT_SECRET: Secreto para firmar los tokens JWT.
TOKEN_EXPIRATION: Tiempo de expiración de los tokens en segundos.
PORT: Puerto en el que se ejecutará el servidor.

# Endpoints

- POST /oauth2/default/v1/token: Genera un nuevo token JWT.
- GET /stream/collections: Obtiene una lista de colecciones. Requiere autenticación.

# Autenticación

Para autenticar las solicitudes, se debe incluir un token JWT en el encabezado Authorization de la solicitud. El token se puede obtener realizando una solicitud POST a /oauth2/default/v1/token.
