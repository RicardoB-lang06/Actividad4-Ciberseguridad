# API simulada – Actividad 4

API de laboratorio (ClinicApp) con JWT, OAuth 2.0 (client credentials), validación de entradas y rate limiting de 100 solicitudes/minuto.

1. `npm install`
2. `npm start`  → http://localhost:3000
3. Importa `Actividad4_API_Seguridad.postman_collection.json` en Postman.
4. Collection Runner: carpetas 01, 02 y 03.
5. Espera 60 s y ejecuta sola la carpeta 04 con 110 iteraciones (0 ms de retraso).

Credenciales de laboratorio (cámbialas con variables de entorno `CLIENT_SECRET` y `USER_PASSWORD`):
- OAuth: `postman-lab` / `lab-secret-cambiar`
- Usuario: `recepcion` / `Recepcion#2026`
